package gcm

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"

	"github.com/riete/crypto"
)

// CrypterOption configures a GCM crypter.
type CrypterOption func(*Crypter)

// WithCipherCodec configures a custom ciphertext encoder and decoder.
func WithCipherCodec(encoder crypto.Encoder, decoder crypto.Decoder) CrypterOption {
	return func(gcm *Crypter) {
		gcm.codec = crypto.NewCipherCodec(encoder, decoder)
	}
}

// WithBase64CipherCodec configures standard Base64 ciphertext encoding and decoding.
func WithBase64CipherCodec() CrypterOption {
	return func(gcm *Crypter) {
		gcm.codec = crypto.NewCipherCodec(base64.StdEncoding.EncodeToString, base64.StdEncoding.DecodeString)
	}
}

// WithHexCipherCodec configures hexadecimal ciphertext encoding and decoding.
func WithHexCipherCodec() CrypterOption {
	return func(gcm *Crypter) {
		gcm.codec = crypto.NewCipherCodec(hex.EncodeToString, hex.DecodeString)
	}
}

// WithAdditionalData configures authenticated additional data.
func WithAdditionalData(data []byte) CrypterOption {
	return func(gcm *Crypter) {
		gcm.additionalData = bytes.Clone(data)
	}
}
