package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"

	"github.com/riete/convert/str"
)

// Encoder converts ciphertext bytes into a string.
type Encoder func([]byte) string

// Decoder converts an encoded ciphertext string into bytes.
type Decoder func(string) ([]byte, error)

// CipherCodec bundles matching ciphertext encoding and decoding functions.
type CipherCodec struct {
	encoder Encoder
	decoder Decoder
}

// Encode converts ciphertext bytes into a string.
func (c *CipherCodec) Encode(b []byte) string {
	return c.encoder(b)
}

// Decode converts an encoded ciphertext string into bytes.
func (c *CipherCodec) Decode(s string) ([]byte, error) {
	return c.decoder(s)
}

// NewCipherCodec creates a codec from matching encoder and decoder functions.
func NewCipherCodec(encoder Encoder, decoder Decoder) *CipherCodec {
	return &CipherCodec{
		encoder: encoder,
		decoder: decoder,
	}
}

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
