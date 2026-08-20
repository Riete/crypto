package cbc

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"slices"

	"github.com/riete/convert/str"
	"github.com/riete/crypto"
)

func ExtractIVAndCiphertext(ciphertext []byte, size int) ([]byte, []byte, error) {
	if size <= 0 || len(ciphertext) < size {
		return nil, nil, errors.New("crypto.CBC: ciphertext is missing IV")
	}
	return ciphertext[:size], ciphertext[size:], nil
}

func PrependIVToCiphertext(iv, ciphertext []byte) []byte {
	return slices.Concat(iv, ciphertext)
}

type IVFunc func() []byte
type CBCCrypter struct {
	iv     IVFunc
	cipher cipher.Block
	codec  *crypto.CipherCodec
}

func (c *CBCCrypter) pkcs7Padding(plaintext []byte) []byte {
	blockSize := c.cipher.BlockSize()
	padding := blockSize - len(plaintext)%blockSize
	paddedText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, paddedText...)
}

func (c *CBCCrypter) pkcs7Unpadding(data []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("pkcs7: invalid padding length")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize || padding > len(data) {
		return nil, errors.New("pkcs7: invalid padding")
	}
	for _, value := range data[len(data)-padding:] {
		if int(value) != padding {
			return nil, errors.New("pkcs7: invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}

func (c *CBCCrypter) Encrypt(plaintext string) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	iv := c.iv()
	if len(iv) != blockSize {
		return nil, errors.New("crypto.CBCCrypter: IV length must equal block size")
	}
	paddedText := c.pkcs7Padding(str.ToBytes(plaintext))
	encrypter := cipher.NewCBCEncrypter(c.cipher, iv)
	ciphertext := make([]byte, len(paddedText))
	encrypter.CryptBlocks(ciphertext, paddedText)
	return PrependIVToCiphertext(iv, ciphertext), nil
}

func (c *CBCCrypter) EncryptToString(plaintext string) (string, error) {
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return c.codec.Encode(ciphertext), nil
}

func (c *CBCCrypter) Decrypt(ciphertext []byte) (string, error) {
	blockSize := c.cipher.BlockSize()
	iv, ciphertext, err := ExtractIVAndCiphertext(ciphertext, blockSize)
	if err != nil {
		return "", err
	}
	if len(ciphertext) == 0 || len(ciphertext)%blockSize != 0 {
		return "", errors.New("crypto.CBCDecrypter: invalid CBC ciphertext length")
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

func (c *CBCCrypter) DecryptFromString(ciphertext string) (string, error) {
	decoded, err := c.codec.Decode(ciphertext)
	if err != nil {
		return "", err
	}
	return c.Decrypt(decoded)
}

func NewCBCCrypter(cipher cipher.Block, options ...CBCCrypterOption) crypto.Crypter {
	cbc := &CBCCrypter{cipher: cipher}
	options = append(
		[]CBCCrypterOption{WithBase64CipherCodec(), WithRandomIV(cipher.BlockSize())},
		options...,
	)
	for _, opt := range options {
		opt(cbc)
	}
	return cbc
}
