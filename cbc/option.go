package cbc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	"github.com/riete/convert/str"
	"github.com/riete/crypto"
)

// CrypterOption configures a CBC crypter.
type CrypterOption func(*Crypter)

// WithFixedIV configures a fixed IV for CBC encryption.
func WithFixedIV(iv string) CrypterOption {
	return func(cbc *Crypter) {
		cbc.iv = func() []byte {
			return str.ToBytes(iv)
		}
	}
}

// WithRandomIV configures random IV generation with the given size.
func WithRandomIV(size int) CrypterOption {
	return func(cbc *Crypter) {
		cbc.iv = func() []byte {
			iv := make([]byte, size)
			_, _ = rand.Read(iv)
			return iv
		}
	}
}

// WithCipherCodec configures a custom ciphertext encoder and decoder.
func WithCipherCodec(encoder crypto.Encoder, decoder crypto.Decoder) CrypterOption {
	return func(cbc *Crypter) {
		cbc.codec = crypto.NewCipherCodec(encoder, decoder)
	}
}

// WithBase64CipherCodec configures standard Base64 ciphertext encoding and decoding.
func WithBase64CipherCodec() CrypterOption {
	return func(cbc *Crypter) {
		cbc.codec = crypto.NewCipherCodec(base64.StdEncoding.EncodeToString, base64.StdEncoding.DecodeString)
	}
}

// WithHexCipherCodec configures hexadecimal ciphertext encoding and decoding.
func WithHexCipherCodec() CrypterOption {
	return func(cbc *Crypter) {
		cbc.codec = crypto.NewCipherCodec(hex.EncodeToString, hex.DecodeString)
	}
}
