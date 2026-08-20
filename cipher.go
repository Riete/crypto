package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"

	"github.com/riete/convert/str"
)

type Encoder func([]byte) string
type Decoder func(string) ([]byte, error)
type CipherCodec struct {
	encoder Encoder
	decoder Decoder
}

func (c *CipherCodec) Encode(b []byte) string {
	return c.encoder(b)
}

func (c *CipherCodec) Decode(s string) ([]byte, error) {
	return c.decoder(s)
}

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
