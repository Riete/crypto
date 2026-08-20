package gcm

import (
	"crypto/cipher"

	"github.com/riete/convert/str"
	"github.com/riete/crypto"
)

type GCMCrypter struct {
	aead           cipher.AEAD
	codec          *crypto.CipherCodec
	additionalData []byte
}

func (c *GCMCrypter) Encrypt(plaintext string) ([]byte, error) {
	return c.aead.Seal(nil, nil, str.ToBytes(plaintext), c.additionalData), nil
}

func (c *GCMCrypter) EncryptToString(plaintext string) (string, error) {
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return c.codec.Encode(ciphertext), nil
}

func (c *GCMCrypter) Decrypt(ciphertext []byte) (string, error) {
	plaintext, err := c.aead.Open(nil, nil, ciphertext, c.additionalData)
	if err != nil {
		return "", err
	}
	return str.FromBytes(plaintext), nil
}

func (c *GCMCrypter) DecryptFromString(ciphertext string) (string, error) {
	decoded, err := c.codec.Decode(ciphertext)
	if err != nil {
		return "", err
	}
	return c.Decrypt(decoded)
}

func NewGCMCrypter(block cipher.Block, options ...GCMCrypterOption) (crypto.Crypter, error) {
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	gcm := &GCMCrypter{aead: aead}
	options = append(
		[]GCMCrypterOption{WithBase64CipherCodec()},
		options...,
	)
	for _, opt := range options {
		opt(gcm)
	}
	return gcm, nil
}
