package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"encoding/hex"

	"github.com/riete/convert/str"
)

type Encoder func([]byte) string

var HexEncoder Encoder = hex.EncodeToString
var Base64Encoder Encoder = base64.StdEncoding.EncodeToString

type Decoder func(string) ([]byte, error)

var HexDecoder Decoder = hex.DecodeString
var Base64Decoder Decoder = base64.StdEncoding.DecodeString

// NewAESCipher creates an AES cipher. It panics if key length is not 16, 24, or 32 bytes.
func NewAESCipher(key string) cipher.Block {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		panic("crypto: AES key length must be 16, 24, or 32 bytes")
	}
	block, _ := aes.NewCipher(str.ToBytes(key))
	return block
}

// NewDESCipher creates a DES cipher. It panics if key length is not 8 bytes.
func NewDESCipher(key string) cipher.Block {
	if len(key) != 8 {
		panic("crypto: DES key length must be 8 bytes")
	}
	block, _ := des.NewCipher(str.ToBytes(key))
	return block
}
