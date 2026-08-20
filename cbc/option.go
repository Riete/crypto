package cbc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	"github.com/riete/convert/str"
	"github.com/riete/crypto"
)

// CBCCrypterOption configures a CBC crypter.
type CBCCrypterOption func(*CBCCrypter)

// WithFixedIV configures a fixed IV for CBC encryption.
func WithFixedIV(iv string) CBCCrypterOption {
	return func(cbc *CBCCrypter) {
		cbc.iv = func() []byte {
			return str.ToBytes(iv)
		}
	}
}

// WithRandomIV configures random IV generation with the given size.
func WithRandomIV(size int) CBCCrypterOption {
	return func(cbc *CBCCrypter) {
		cbc.iv = func() []byte {
			iv := make([]byte, size)
			_, _ = rand.Read(iv)
			return iv
		}
	}
}

// WithCipherCodec configures a custom ciphertext encoder and decoder.
func WithCipherCodec(encoder crypto.Encoder, decoder crypto.Decoder) CBCCrypterOption {
	return func(cbc *CBCCrypter) {
		cbc.codec = crypto.NewCipherCodec(encoder, decoder)
	}
}

// WithBase64CipherCodec configures standard Base64 ciphertext encoding and decoding.
func WithBase64CipherCodec() CBCCrypterOption {
	return func(cbc *CBCCrypter) {
		cbc.codec = crypto.NewCipherCodec(base64.StdEncoding.EncodeToString, base64.StdEncoding.DecodeString)
	}
}

// WithHexCipherCodec configures hexadecimal ciphertext encoding and decoding.
func WithHexCipherCodec() CBCCrypterOption {
	return func(cbc *CBCCrypter) {
		cbc.codec = crypto.NewCipherCodec(hex.EncodeToString, hex.DecodeString)
	}
}
