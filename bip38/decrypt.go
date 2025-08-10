package bip38

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"log"
	"math/big"

	"github.com/cculianu/gocoin/btc"
	"golang.org/x/crypto/scrypt"
)

type KeyType int

const ( /* used for Key.type */
	_                    = iota
	NonECMultKey KeyType = iota
	ECMultKey    KeyType = iota
)

type Key struct {
	enc            string  // bip38 base58 encoded key (as the user would see it in a paper wallet)
	dec            []byte  // key decoded to bytes
	flag           byte    // the flag byte
	compressed     bool    // boolean flag determining if compressed
	typ            KeyType // one of NonECMultKey or ECMultKey above
	salt           []byte  // the slice salt -- a slice of .dec slice
	entropy        []byte  // only non-nil for typ==ECMultKey -- a slice into .dec
	hasLotSequence bool    // usually false, may be true only for typ==ECMultKey

	// coin / network specific info affecting key decription and address decoding:
	networkVersion   byte // usually 0x0 for BTC, but may be 0x1f for ONION, etc
	privateKeyPrefix byte // usually 0x80 for BTC, may be 0x9f for ONION, etc
}

var bigN *big.Int ///< used by Decrypt code below for ECMultKey type keys

func init() {
	// secp256k1 curve order (32 bytes)
	bigN = new(big.Int).SetBytes([]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
		0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
		0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
	})
	if bigN == nil || bigN.Sign() == 0 {
		log.Fatal("Failed to initialize secp256k1 curve order (bigN)")
	}
}

func NewKey(encKey string) *Key {
	dec := btc.Decodeb58(encKey)
	if dec == nil || len(dec) < 39 {
		log.Fatal("Cannot decode base58 string or wrong length: " + encKey)
	}
	// original code trimmed to 39 bytes — keep that behavior but safely
	dec = dec[:39]

	o := &Key{
		enc:              encKey,
		dec:              dec,
		networkVersion:   0x00,
		privateKeyPrefix: 0x80,
	}

	b0, b1 := dec[0], dec[1]
	if b0 == 0x01 && b1 == 0x42 {
		o.typ = NonECMultKey
	} else if b0 == 0x01 && b1 == 0x43 {
		o.typ = ECMultKey
	} else {
		log.Fatal("Malformed byte slice -- invalid key")
	}

	o.flag = dec[2]

	if o.typ == NonECMultKey {
		o.compressed = (o.flag == 0xe0)
		o.salt = dec[3:7]
		if !o.compressed && o.flag != 0xc0 {
			log.Fatal("Invalid BIP38 compression flag")
		}
	} else { // ECMultKey
		o.compressed = (o.flag & 0x20) != 0
		o.hasLotSequence = (o.flag & 0x04) != 0
		if (o.flag & 0x24) != o.flag {
			log.Fatal("Invalid BIP38 ECMultKey flag")
		}
		if o.hasLotSequence {
			o.salt = dec[7:11]
			o.entropy = dec[7:15]
		} else {
			o.salt = dec[7:15]
			o.entropy = o.salt
		}
	}

	return o
}

func (o *Key) TypeString() string {
	switch o.typ {
	case NonECMultKey:
		return "NonECMultKey"
	case ECMultKey:
		return "ECMultKey"
	}
	return "UnknownKey"
}

func sha256Twice(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:] // returns 32-byte slice backed by array
}

func Pk2Wif(pk []byte, compressed bool, privateKeyPrefix byte) string {
	buf := make([]byte, 0, 37) // 1 (prefix) + 32 (pk) + 1 (compressed) + 4 (checksum)
	buf = append(buf, privateKeyPrefix)
	buf = append(buf, pk...)
	if compressed {
		buf = append(buf, 0x01)
	}
	sha2 := sha256Twice(buf)
	buf = append(buf, sha2[:4]...)
	return btc.Encodeb58(buf)
}

func DecryptWithPassphraseNoEC(key *Key, passphrase string) (wifPrivKey, addr string) {
	scryptBuf, _ := scrypt.Key([]byte(passphrase), key.salt, 16384, 8, 8, 64)
	derivedHalf1 := scryptBuf[0:32]
	derivedHalf2 := scryptBuf[32:64]
	encryptedHalf1 := key.dec[7:23]
	encryptedHalf2 := key.dec[23:39]
	h, err := aes.NewCipher(derivedHalf2)
	if h == nil {
		log.Fatal(err)
	}
	k1 := make([]byte, 16)
	k2 := make([]byte, 16)
	h.Decrypt(k1, encryptedHalf1)
	h, err = aes.NewCipher(derivedHalf2)
	if h == nil {
		log.Fatal(err)
	}
	h.Decrypt(k2, encryptedHalf2)
	keyBytes := make([]byte, 32)
	for i := 0; i < 16; i++ {
		keyBytes[i] = k1[i] ^ derivedHalf1[i]
		keyBytes[i+16] = k2[i] ^ derivedHalf1[i+16]
	}
	d := new(big.Int).SetBytes(keyBytes)
	pubKey, err := btc.PublicFromPrivate(d.Bytes(), key.compressed)
	if pubKey == nil {
		log.Fatal(err)
	}
	addr = btc.NewAddrFromPubkey(pubKey, key.networkVersion).String()

	addrHashed := sha256Twice([]byte(addr))[0:4]

	if addrHashed[0] != key.salt[0] || addrHashed[1] != key.salt[1] || addrHashed[2] != key.salt[2] || addrHashed[3] != key.salt[3] {
		wifPrivKey, addr = "", ""
		return
	}

	wifPrivKey = Pk2Wif(d.Bytes(), key.compressed, key.privateKeyPrefix)
	return
}

func DecryptWithPassphrase(key *Key, passphrase string) (wifPrivKey, addr string) {
	if key.typ == NonECMultKey {
		return DecryptWithPassphraseNoEC(key, passphrase)
	}
	passBytes := []byte(passphrase)

	prefactorA, err := scrypt.Key(passBytes, key.salt, 16384, 8, 8, 32)
	if err != nil {
		log.Fatal(err)
	}

	var passFactor []byte
	if key.hasLotSequence {
		passFactor = sha256Twice(append(prefactorA, key.entropy...))
	} else {
		passFactor = prefactorA
	}

	passpoint, err := btc.PublicFromPrivate(passFactor, true)
	if err != nil || passpoint == nil {
		log.Fatal(err)
	}

	salt := key.dec[3:7]
	derived, err := scrypt.Key(passpoint, append(salt, key.entropy...), 1024, 1, 1, 64)
	if err != nil {
		log.Fatal(err)
	}

	h, err := aes.NewCipher(derived[32:])
	if err != nil {
		log.Fatal(err)
	}

	var unencryptedpart2 [16]byte
	h.Decrypt(unencryptedpart2[:], key.dec[23:39])
	for i := range unencryptedpart2 {
		unencryptedpart2[i] ^= derived[i+16]
	}

	encryptedpart1 := bytes.Join([][]byte{key.dec[15:23], unencryptedpart2[:8]}, nil)

	var unencryptedpart1 [16]byte
	h.Decrypt(unencryptedpart1[:], encryptedpart1)
	for i := range unencryptedpart1 {
		unencryptedpart1[i] ^= derived[i]
	}
	seeddb := append(unencryptedpart1[:16], unencryptedpart2[8:]...)

	factorb := sha256Twice(seeddb)

	privKey := new(big.Int).SetBytes(passFactor)
	privKey.Mul(privKey, new(big.Int).SetBytes(factorb))
	privKey.Mod(privKey, bigN)

	pubKey, err := btc.PublicFromPrivate(privKey.Bytes(), key.compressed)
	if err != nil || pubKey == nil {
		log.Fatal(err)
	}

	addr = btc.NewAddrFromPubkey(pubKey, key.networkVersion).String()

	if !bytes.Equal(sha256Twice([]byte(addr))[:4], salt) {
		return "", ""
	}

	wifPrivKey = Pk2Wif(privKey.Bytes(), key.compressed, key.privateKeyPrefix)
	return
}
