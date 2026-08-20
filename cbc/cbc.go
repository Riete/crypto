package cbc

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"slices"

	"github.com/riete/convert/str"
	"github.com/riete/crypto"
)

// ExtractIVAndCiphertext returns the prefixed IV and the ciphertext after removing it.
func ExtractIVAndCiphertext(ciphertext []byte, size int) ([]byte, []byte, error) {
	if size <= 0 || len(ciphertext) < size {
		return nil, nil, errors.New("cbc: ciphertext is missing IV")
	}
	return ciphertext[:size], ciphertext[size:], nil
}

// PrependIVToCiphertext adds the IV before the ciphertext.
func PrependIVToCiphertext(iv, ciphertext []byte) []byte {
	return slices.Concat(iv, ciphertext)
}

// IVFunc returns an IV for a CBC encryption operation.
type IVFunc func() []byte

// Crypter encrypts and decrypts data using CBC mode.
type Crypter struct {
	iv     IVFunc
	cipher cipher.Block
	codec  *crypto.CipherCodec
}

func (c *Crypter) pkcs7Padding(plaintext []byte) []byte {
	blockSize := c.cipher.BlockSize()
	padding := blockSize - len(plaintext)%blockSize
	paddedText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, paddedText...)
}

func (c *Crypter) pkcs7Unpadding(data []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("cbc.pkcs7: invalid padding length")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize || padding > len(data) {
		return nil, errors.New("cbc.pkcs7: invalid padding")
	}
	for _, value := range data[len(data)-padding:] {
		if int(value) != padding {
			return nil, errors.New("cbc.pkcs7: invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}

// Encrypt encrypts plaintext and prepends the IV to the ciphertext.
func (c *Crypter) Encrypt(plaintext string) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	iv := c.iv()
	if len(iv) != blockSize {
		return nil, errors.New("cbc.Encrypt: IV length must equal block size")
	}
	paddedText := c.pkcs7Padding(str.ToBytes(plaintext))
	encrypter := cipher.NewCBCEncrypter(c.cipher, iv)
	ciphertext := make([]byte, len(paddedText))
	encrypter.CryptBlocks(ciphertext, paddedText)
	return PrependIVToCiphertext(iv, ciphertext), nil
}

// EncryptToString encrypts plaintext and encodes the ciphertext.
func (c *Crypter) EncryptToString(plaintext string) (string, error) {
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return c.codec.Encode(ciphertext), nil
}

// Decrypt extracts the IV and decrypts the ciphertext.
func (c *Crypter) Decrypt(ciphertext []byte) (string, error) {
	blockSize := c.cipher.BlockSize()
	iv, ciphertext, err := ExtractIVAndCiphertext(ciphertext, blockSize)
	if err != nil {
		return "", err
	}
	if len(ciphertext) == 0 || len(ciphertext)%blockSize != 0 {
		return "", errors.New("cbc.Decrypt: invalid CBC ciphertext length")
	}
	decrypter := cipher.NewCBCDecrypter(c.cipher, iv)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)
	unpaddedText, err := c.pkcs7Unpadding(plaintext)
	if err != nil {
		return "", err
	}
	return str.FromBytes(unpaddedText), nil
}

// DecryptFromString decodes and decrypts the ciphertext.
func (c *Crypter) DecryptFromString(ciphertext string) (string, error) {
	decoded, err := c.codec.Decode(ciphertext)
	if err != nil {
		return "", err
	}
	return c.Decrypt(decoded)
}

// NewCrypter creates a CBC crypter with random IVs and Base64 cipher codec by default.
// Options can override the IV source and cipher codec.
func NewCrypter(cipher cipher.Block, options ...CrypterOption) crypto.Crypter {
	cbc := &Crypter{cipher: cipher}
	options = append(
		[]CrypterOption{WithBase64CipherCodec(), WithRandomIV(cipher.BlockSize())},
		options...,
	)
	for _, opt := range options {
		opt(cbc)
	}
	return cbc
}
