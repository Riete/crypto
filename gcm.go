package crypto

import (
	"bytes"
	"crypto/cipher"

	"github.com/riete/convert/str"
)

type GCMCrypter struct {
	aead           cipher.AEAD
	additionalData []byte
}

func (c *GCMCrypter) Encrypt(plaintext string) ([]byte, error) {
	return c.aead.Seal(nil, nil, str.ToBytes(plaintext), c.additionalData), nil
}

func (c *GCMCrypter) EncryptToString(plaintext string, encoder Encoder) (string, error) {
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	if encoder == nil {
		encoder = str.FromBytes
	}
	return encoder(ciphertext), nil
}

func (c *GCMCrypter) Decrypt(ciphertext []byte) (string, error) {
	plaintext, err := c.aead.Open(nil, nil, ciphertext, c.additionalData)
	if err != nil {
		return "", err
	}
	return str.FromBytes(plaintext), nil
}

func (c *GCMCrypter) DecryptFromString(ciphertext string, decoder Decoder) (string, error) {
	if decoder == nil {
		return c.Decrypt(str.ToBytes(ciphertext))
	}
	decoded, err := decoder(ciphertext)
	if err != nil {
		return "", err
	}
	return c.Decrypt(decoded)
}

func newGCM(block cipher.Block, additionalData []byte) (*GCMCrypter, error) {
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return &GCMCrypter{
		aead:           aead,
		additionalData: bytes.Clone(additionalData),
	}, nil
}

func NewGCMEncrypter(block cipher.Block, additionalData []byte) (Encrypter, error) {
	return newGCM(block, additionalData)
}

func NewGCMDecrypter(block cipher.Block, additionalData []byte) (Decrypter, error) {
	return newGCM(block, additionalData)
}

func NewGCMEncryptDecrypter(block cipher.Block, additionalData []byte) (EncryptDecrypter, error) {
	return newGCM(block, additionalData)
}
