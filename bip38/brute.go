package bip38

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var totalTried uint64 = 0
var stopSearch int32 = 0

func tryPasswords(start, finish uint64, key *Key, passwords <-chan string, c chan string) {
	startTime := time.Now()
	if key == nil {
		log.Fatal("Invalid key: nil pointer")
	}
	var b strings.Builder
	b.Grow(128) // Preallocate buffer to reduce allocations

	for i := start; i < finish; i++ {
		// Check stop flag once per iteration
		if atomic.LoadInt32(&stopSearch) != 0 {
			c <- fmt.Sprintf("%d", i-start)
			return
		}

		password, ok := <-passwords
		if !ok {
			// Channel closed: no more passwords
			c <- ""
			return
		}

		privKey, addr := DecryptWithPassphrase(key, password)
		atomic.AddUint64(&totalTried, 1)

		if privKey != "" {
			// Construct result string without extra allocations
			b.Reset()
			b.WriteString(privKey)
			b.WriteString("    pass = '")
			b.WriteString(password)
			b.WriteString("'   ( Address: ")
			b.WriteString(addr)
			b.WriteString(" )")
			c <- b.String()
			return
		}

		// Print progress every 1000 attempts to reduce overhead
		if atomic.LoadUint64(&totalTried)%1000 == 0 {
			elapsed := time.Since(startTime).Truncate(time.Second)
			fmt.Printf("%9d passphrases tried (latest guess: %s ) elapsed: %v\r",
				atomic.LoadUint64(&totalTried), password, elapsed)
		}
	}

	// If stopped externally
	if atomic.LoadInt32(&stopSearch) != 0 {
		c <- fmt.Sprintf("%d", finish-start)
		return
	}

	// No key found
	c <- ""
}
func searchRange(start, finish uint64, key *Key, charset string, pwlen int, pat []rune, c chan string) {
	startTime := time.Now()

	if key == nil || charset == "" || len(pat) == 0 || start > finish {
		log.Fatal("Invalid input: nil key, empty charset, empty pattern, or invalid range")
	}
	cset := []rune(charset)
	csetLen := uint64(len(cset))
	if csetLen == 0 {
		log.Fatal("Empty charset")
	}
	var b strings.Builder
	b.Grow(128) // Estimate: 52 (WIF) + 20 (passphrase) + 34 (address) + 22 (formatting)
	guess := make([]rune, len(pat))
	for i := start; i < finish && atomic.LoadInt32(&stopSearch) == 0; i++ {
		acum := i
		for j := 0; j < len(pat); j++ {
			if pat[j] == '?' {
				guess[j] = cset[acum%csetLen]
				acum /= csetLen
			} else {
				guess[j] = pat[j]
			}
		}
		b.Reset()
		b.WriteString(string(guess))
		guessString := b.String()
		privKey, addr := DecryptWithPassphrase(key, guessString)
		if privKey != "" {
			b.Reset()
			b.WriteString(privKey)
			b.WriteString("    pass = '")
			b.WriteString(guessString)
			b.WriteString("'   ( Address: ")
			b.WriteString(addr)
			b.WriteString(" )")
			c <- b.String()
			return
		}
		atomic.AddUint64(&totalTried, 1)
		// Optional: Uncomment for throttled progress output
		if atomic.LoadUint64(&totalTried)%1000 == 0 {
			elapsed := time.Since(startTime).Truncate(time.Second)

			fmt.Printf("%6d passphrases tried (latest guess: %s )  elapsed: %v \r", atomic.LoadUint64(&totalTried), guessString, elapsed)
		}
	}
	if atomic.LoadInt32(&stopSearch) != 0 {
		c <- fmt.Sprintf("%d", finish-start)
		return
	}
	c <- ""
}

func displayPerformance(routines int, spaceSize, resume uint64, startTime time.Time, fileMode bool, fileSize int64, avgLineLen int64) {
	for atomic.LoadInt32(&stopSearch) == 0 {
		time.Sleep(5 * time.Second) // Update every 5 seconds
		tried := atomic.LoadUint64(&totalTried)
		elapsed := time.Since(startTime).Seconds()
		if elapsed < 1 {
			continue // Avoid division by zero
		}
		rate := float64(tried) / elapsed
		ratePerGoroutine := rate / float64(routines)
		var b strings.Builder
		b.Grow(256)
		b.WriteString(fmt.Sprintf("\nPerformance: %d passphrases tried, %.2f passphrases/sec, %.2f passphrases/sec/goroutine\n",
			tried, rate, ratePerGoroutine))
		if !fileMode {
			remaining := spaceSize - tried
			if remaining > 0 {
				eta := time.Duration(float64(remaining)/rate) * time.Second
				b.WriteString(fmt.Sprintf("Remaining: %d passphrases, ETA: %v\n", remaining, eta.Truncate(time.Second)))
			}
		} else if fileSize > 0 && avgLineLen > 0 {
			estimatedLines := uint64(fileSize / avgLineLen)
			remaining := estimatedLines - tried
			if remaining > 0 {
				eta := time.Duration(float64(remaining)/rate) * time.Second
				b.WriteString(fmt.Sprintf("Estimated remaining: %d passphrases (based on file size), ETA: %v\n",
					remaining, eta.Truncate(time.Second)))
			}
		}
		fmt.Print(b.String())
	}
}
func BruteChunk(routines int, encryptedKey, charset, passwordFile string, pwlen int, pat string, chunk, chunks int, resume uint64, coinInfo [2]byte, coinName string) string {
	if chunk < 0 || chunks <= 0 || chunk >= chunks {
		log.Fatal("Invalid chunk specification")
	}
	if encryptedKey == "" {
		log.Fatal("Empty encryptedKey")
	}
	if routines < 1 {
		log.Fatal("Routines must be >= 1")
	}
	if pwlen < 1 && passwordFile == "" {
		log.Fatal("Password length must be >= 1 or password file must be provided")
	}
	if coinName == "" {
		log.Fatal("Empty coinName")
	}
	key := NewKey(encryptedKey)
	key.networkVersion = coinInfo[0]
	key.privateKeyPrefix = coinInfo[1]
	var b strings.Builder
	b.Grow(256) // Estimate for config output
	if charset == "" && passwordFile == "" {
		charset = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~."
	}
	if charset != "" {
		b.WriteString("Using character set: ")
		b.WriteString(charset)
		b.WriteByte('\n')
	}
	b.WriteString("Encrypted key: ")
	b.WriteString(encryptedKey)
	b.WriteString("\nKeyType: ")
	b.WriteString(key.TypeString())
	b.WriteString("\nNetwork: ")
	b.WriteString(coinName)
	b.WriteByte('\n')
	var spaceSize uint64
	var patAsRunes []rune
	if passwordFile == "" {
		if pat == "" {
			patAsRunes = make([]rune, pwlen)
			for i := range patAsRunes {
				patAsRunes[i] = '?'
			}
			b.WriteString("Password length: ")
			b.WriteString(strconv.Itoa(pwlen))
			b.WriteByte('\n')
		} else {
			patAsRunes = []rune(pat)
			if len(patAsRunes) == 0 {
				log.Fatal("Empty pattern")
			}
			b.WriteString("Pattern: ")
			b.WriteString(pat)
			b.WriteString("\nUnknown chars: ")
			b.WriteString(strconv.Itoa(pwlen))
			b.WriteString("\nPassword length: ")
			b.WriteString(strconv.Itoa(len(patAsRunes)))
			b.WriteByte('\n')
		}
		csetLen := uint64(len([]rune(charset)))
		if csetLen == 0 {
			log.Fatal("Empty charset")
		}
		spaceSize = 1
		for i := 0; i < pwlen; i++ {
			spaceSize *= csetLen
		}
		b.WriteString("Total passphrase space size: ")
		b.WriteString(strconv.FormatUint(spaceSize, 10))
		b.WriteByte('\n')
	} else {
		// For file, we don't know spaceSize upfront; estimate or skip
		spaceSize = math.MaxUint64 // Placeholder for chunking
		b.WriteString("Password file: ")
		b.WriteString(passwordFile)
		b.WriteByte('\n')
	}
	fmt.Print(b.String())
	startFrom := uint64(0)
	chunkSize := spaceSize / uint64(chunks)
	blockSize := chunkSize / uint64(routines)
	if chunks > 1 {
		startFrom = chunkSize * uint64(chunk)
		csz := chunkSize
		if chunk == chunks-1 {
			csz = spaceSize - startFrom
		}
		b.Reset()
		b.WriteString("Chunk passphrase space size: ")
		b.WriteString(strconv.FormatUint(csz, 10))
		b.WriteString("  Starting from point: ")
		b.WriteString(strconv.FormatUint(startFrom, 10))
		b.WriteByte('\n')
		fmt.Print(b.String())
	}
	totalTried = resume * uint64(routines)
	c := make(chan string, routines)
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)
	defer signal.Stop(sigc)
	if passwordFile != "" {
		file, err := os.Open(passwordFile)
		if err != nil {
			log.Fatalf("Failed to open password file: %v", err)
		}
		defer file.Close()
		pwdChan := make(chan string, routines*100) // Buffer to reduce contention
		go func() {
			defer close(pwdChan)
			scanner := bufio.NewScanner(file)
			scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 64KB initial, 1MB max
			for i := uint64(0); scanner.Scan() && atomic.LoadInt32(&stopSearch) == 0; i++ {
				if i < startFrom+resume {
					continue // Skip to resume point
				}
				pwdChan <- scanner.Text()
			}
			if err := scanner.Err(); err != nil {
				log.Printf("Error reading password file: %v", err)
			}
		}()
		for i := 0; i < routines; i++ {
			finish := uint64(i)*blockSize + blockSize + startFrom
			if i == routines-1 {
				finish = chunkSize + startFrom
				if chunk == chunks-1 {
					finish = spaceSize
				}
			}
			start := uint64(i)*blockSize + startFrom + resume
			go tryPasswords(start, finish, key, pwdChan, c)
		}
	} else {
		for i := 0; i < routines; i++ {
			finish := uint64(i)*blockSize + blockSize + startFrom
			if i == routines-1 {
				finish = chunkSize + startFrom
				if chunk == chunks-1 {
					finish = spaceSize
				}
			}
			start := uint64(i)*blockSize + startFrom + resume
			go searchRange(start, finish, key, charset, pwlen, patAsRunes, c)
		}
	}
	var minResumeKey uint64
	for i := routines; i > 0; i-- {
		select {
		case s := <-c:
			if s == "" {
				continue
			}
			if atomic.LoadInt32(&stopSearch) != 0 {
				if u, err := strconv.ParseUint(s, 10, 64); err == nil && (u+resume < minResumeKey || minResumeKey == 0) {
					minResumeKey = u + resume
				} else if err != nil {
					return s
				}
				continue
			}
			return s
		case sig := <-sigc:
			atomic.StoreInt32(&stopSearch, 1)
			fmt.Printf("\nReceived signal: %s\n", sig)
		}
	}
	if minResumeKey > 0 {
		b.Reset()
		b.WriteString("to resume, use offset ")
		b.WriteString(strconv.FormatUint(minResumeKey, 10))
		return b.String()
	}
	return ""
}
