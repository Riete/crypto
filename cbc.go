package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"encoding/hex"

	"github.com/riete/convert/str"
)

type IVFunc func() []byte

var FixedIV = func(iv string) IVFunc {
	return func() []byte {
		return str.ToBytes(iv)
	}
}

type Encoder func([]byte) string

var HexEncoder Encoder = hex.EncodeToString
var Base64Encoder Encoder = base64.StdEncoding.EncodeToString

type Decoder func(string) ([]byte, error)

var HexDecoder Decoder = hex.DecodeString
var Base64Decoder Decoder = base64.StdEncoding.DecodeString

type CBCEncrypter struct {
	iv     IVFunc
	cipher cipher.Block
}

func (c *CBCEncrypter) Encrypt(plaintext string) []byte {
	paddedText := PKCS5Padding(str.ToBytes(plaintext), c.cipher.BlockSize())
	encrypter := cipher.NewCBCEncrypter(c.cipher, c.iv())
	ciphertext := make([]byte, len(paddedText))
	encrypter.CryptBlocks(ciphertext, paddedText)
	return ciphertext
}

func (c *CBCEncrypter) EncryptToString(plaintext string, encoder Encoder) string {
	if encoder == nil {
		encoder = str.FromBytes
	}
	return encoder(c.Encrypt(plaintext))
}

type CBCDecrypter struct {
	iv     IVFunc
	cipher cipher.Block
}

func (c *CBCDecrypter) Decrypt(ciphertext []byte) string {
	decrypter := cipher.NewCBCDecrypter(c.cipher, c.iv())
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)
	return str.FromBytes(PKCS5UnPadding(plaintext))
}

func (c *CBCDecrypter) DecryptFromString(ciphertext string, decoder Decoder) (string, error) {
	if decoder == nil {
		return c.Decrypt(str.ToBytes(ciphertext)), nil
	}
	decoded, err := decoder(ciphertext)
	if err != nil {
		return "", err
	}
	return c.Decrypt(decoded), nil
}

type CBCEncryptDecrypter struct {
	*CBCEncrypter
	*CBCDecrypter
}

// NewAESCipher key length must be 16 or 24 or 32
func NewAESCipher(key string) (cipher.Block, error) {
	return aes.NewCipher(str.ToBytes(key))
}

// NewDESCipher key length must be 8
func NewDESCipher(key string) (cipher.Block, error) {
	return des.NewCipher(str.ToBytes(key))
}

func NewCBCEncrypter(cipher cipher.Block, iv IVFunc) *CBCEncrypter {
	return &CBCEncrypter{cipher: cipher, iv: iv}
}

func NewCBCDecrypter(cipher cipher.Block, iv IVFunc) *CBCDecrypter {
	return &CBCDecrypter{cipher: cipher, iv: iv}
}

func NewCBCEncryptDecrypter(encrypter *CBCEncrypter, decrypter *CBCDecrypter) *CBCEncryptDecrypter {
	return &CBCEncryptDecrypter{encrypter, decrypter}
}
