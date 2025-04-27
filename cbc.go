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

func (c *CBCEncrypter) EncryptToString(plaintext string) string {
	return str.FromBytes(c.Encrypt(plaintext))
}

func (c *CBCEncrypter) EncryptToHexString(plaintext string) string {
	return hex.EncodeToString(c.Encrypt(plaintext))
}

func (c *CBCEncrypter) EncryptToBase64String(plaintext string) string {
	return base64.StdEncoding.EncodeToString(c.Encrypt(plaintext))
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

func (c *CBCDecrypter) DecryptFromString(ciphertext string) string {
	return c.Decrypt(str.ToBytes(ciphertext))
}

func (c *CBCDecrypter) DecryptFromHexString(ciphertext string) string {
	decoded, _ := hex.DecodeString(ciphertext)
	return c.Decrypt(decoded)
}

func (c *CBCDecrypter) DecryptFromBase64String(ciphertext string) string {
	decoded, _ := base64.StdEncoding.DecodeString(ciphertext)
	return c.Decrypt(decoded)
}

type CBCEncryptDecrypter struct {
	*CBCEncrypter
	*CBCDecrypter
}

// NewAESCipher key length must be 16 or 24 or 32
func NewAESCipher(key string) cipher.Block {
	c, _ := aes.NewCipher(str.ToBytes(key))
	return c
}

// NewDESCipher key length must be 8
func NewDESCipher(key string) cipher.Block {
	c, _ := des.NewCipher(str.ToBytes(key))
	return c
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
