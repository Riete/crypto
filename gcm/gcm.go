package gcm

import (
	"crypto/cipher"

	"github.com/riete/convert/str"
	"github.com/riete/crypto"
)

// Crypter encrypts and decrypts data using GCM mode.
type Crypter struct {
	aead           cipher.AEAD
	codec          *crypto.CipherCodec
	additionalData []byte
}

// Encrypt encrypts plaintext with a random nonce.
func (c *Crypter) Encrypt(plaintext string) ([]byte, error) {
	return c.aead.Seal(nil, nil, str.ToBytes(plaintext), c.additionalData), nil
}

// EncryptToString encrypts plaintext and encodes the ciphertext.
func (c *Crypter) EncryptToString(plaintext string) (string, error) {
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return c.codec.Encode(ciphertext), nil
}

// Decrypt authenticates and decrypts the ciphertext.
func (c *Crypter) Decrypt(ciphertext []byte) (string, error) {
	plaintext, err := c.aead.Open(nil, nil, ciphertext, c.additionalData)
	if err != nil {
		return "", err
	}
	return str.FromBytes(plaintext), nil
}

// DecryptFromString decodes and decrypts the ciphertext.
func (c *Crypter) DecryptFromString(ciphertext string) (string, error) {
	decoded, err := c.codec.Decode(ciphertext)
	if err != nil {
		return "", err
	}
	return c.Decrypt(decoded)
}

// NewCrypter creates a GCM crypter with random nonces and Base64 cipher codec by default.
// Options can override the codec and configure additional authenticated data.
func NewCrypter(block cipher.Block, options ...CrypterOption) (crypto.Crypter, error) {
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	gcm := &Crypter{aead: aead}
	options = append(
		[]CrypterOption{WithBase64CipherCodec()},
		options...,
	)
	for _, opt := range options {
		opt(gcm)
	}
	return gcm, nil
}
