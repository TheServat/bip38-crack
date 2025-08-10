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
	var success bool
	bigN, success = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	if !success {
		log.Fatal("Failed to create Int for N")
	}
}

func NewKey(encKey string) *Key {
	o := &Key{
		enc:              encKey,
		dec:              btc.Decodeb58(encKey),
		networkVersion:   0x0,
		privateKeyPrefix: 0x80,
	}
	if len(o.dec) < 39 {
		log.Fatal("Cannot decode base58 string or wrong length: " + encKey)
	}
	o.dec = o.dec[:39] // Trim to 39 bytes
	switch {
	case o.dec[0] == 0x01 && o.dec[1] == 0x42:
		o.typ = NonECMultKey
	case o.dec[0] == 0x01 && o.dec[1] == 0x43:
		o.typ = ECMultKey
	default:
		log.Fatal("Malformed byte slice -- invalid key")
	}

	o.flag = o.dec[2]
	o.compressed = false
	if o.typ == NonECMultKey {
		o.compressed = o.flag == 0xe0
		o.salt = o.dec[3:7]
		if !o.compressed && o.flag != 0xc0 {
			log.Fatal("Invalid BIP38 compression flag")
		}
	} else if o.typ == ECMultKey {
		o.compressed = (o.flag & 0x20) != 0
		o.hasLotSequence = (o.flag & 0x04) != 0
		if (o.flag & 0x24) != o.flag {
			log.Fatal("Invalid BIP38 ECMultKey flag")
		}
		if o.hasLotSequence {
			o.salt = o.dec[7:11]
			o.entropy = o.dec[7:15]
		} else {
			o.salt = o.dec[7:15]
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
	h := sha256.New()
	h.Write(b)
	hashed := h.Sum(nil)[:32] // Ensure 32-byte output
	h.Reset()
	h.Write(hashed)
	return h.Sum(nil)[:32]
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
	scryptBuf, err := scrypt.Key([]byte(passphrase), key.salt, 16384, 8, 8, 64)
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

	prefactorA, err := scrypt.Key([]byte(passphrase), key.salt, 16384, 8, 8, 32)
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

	encryptedpart1 := key.dec[15:23]
	encryptedpart2 := key.dec[23:39]

	derived, err := scrypt.Key(passpoint, append(key.dec[3:7], key.entropy...), 1024, 1, 1, 64)
	if err != nil {
		log.Fatal(err)
	}

	h, err := aes.NewCipher(derived[32:])
	if err != nil {
		log.Fatal(err)
	}

	unencryptedpart2 := make([]byte, 16)
	h.Decrypt(unencryptedpart2, encryptedpart2)
	for i := range unencryptedpart2 {
		unencryptedpart2[i] ^= derived[i+16]
	}

	encryptedpart1 = bytes.Join([][]byte{encryptedpart1, unencryptedpart2[:8]}, nil)

	unencryptedpart1 := make([]byte, 16)
	h.Decrypt(unencryptedpart1, encryptedpart1)
	for i := range unencryptedpart1 {
		unencryptedpart1[i] ^= derived[i]
	}

	seeddb := append(unencryptedpart1[:16], unencryptedpart2[8:]...)

	factorb := sha256Twice(seeddb)

	passFactorBig := new(big.Int).SetBytes(passFactor)
	factorbBig := new(big.Int).SetBytes(factorb)

	privKey := new(big.Int)
	privKey.Mul(passFactorBig, factorbBig)
	privKey.Mod(privKey, bigN)

	pubKey, err := btc.PublicFromPrivate(privKey.Bytes(), key.compressed)
	if err != nil || pubKey == nil {
		log.Fatal(err)
	}

	addr = btc.NewAddrFromPubkey(pubKey, key.networkVersion).String()

	addrHashed := sha256Twice([]byte(addr))[:4]

	if !bytes.Equal(addrHashed, key.dec[3:7]) {
		return "", ""
	}

	wifPrivKey = Pk2Wif(privKey.Bytes(), key.compressed, key.privateKeyPrefix)
	return
}
