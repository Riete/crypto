package gcm

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"

	"github.com/riete/crypto"
)

type GCMCrypterOption func(*GCMCrypter)

func WithCipherCodec(encoder crypto.Encoder, decoder crypto.Decoder) GCMCrypterOption {
	return func(gcm *GCMCrypter) {
		gcm.codec = crypto.NewCipherCodec(encoder, decoder)
	}
}

func WithBase64CipherCodec() GCMCrypterOption {
	return func(gcm *GCMCrypter) {
		gcm.codec = crypto.NewCipherCodec(base64.StdEncoding.EncodeToString, base64.StdEncoding.DecodeString)
	}
}

func WithCipherHexCodec() GCMCrypterOption {
	return func(gcm *GCMCrypter) {
		gcm.codec = crypto.NewCipherCodec(hex.EncodeToString, hex.DecodeString)
	}
}

func WithAdditionalData(data []byte) GCMCrypterOption {
	return func(gcm *GCMCrypter) {
		gcm.additionalData = bytes.Clone(data)
	}
}
