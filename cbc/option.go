package cbc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	"github.com/riete/convert/str"
	"github.com/riete/crypto"
)

type CBCCrypterOption func(*CBCCrypter)

func WithFixedIV(iv string) CBCCrypterOption {
	return func(cbc *CBCCrypter) {
		cbc.iv = func() []byte {
			return str.ToBytes(iv)
		}
	}
}

func WithRandomIV(size int) CBCCrypterOption {
	return func(cbc *CBCCrypter) {
		cbc.iv = func() []byte {
			iv := make([]byte, size)
			_, _ = rand.Read(iv)
			return iv
		}
	}
}

func WithCipherCodec(encoder crypto.Encoder, decoder crypto.Decoder) CBCCrypterOption {
	return func(cbc *CBCCrypter) {
		cbc.codec = crypto.NewCipherCodec(encoder, decoder)
	}
}

func WithBase64CipherCodec() CBCCrypterOption {
	return func(cbc *CBCCrypter) {
		cbc.codec = crypto.NewCipherCodec(base64.StdEncoding.EncodeToString, base64.StdEncoding.DecodeString)
	}
}

func WithCipherHexCodec() CBCCrypterOption {
	return func(cbc *CBCCrypter) {
		cbc.codec = crypto.NewCipherCodec(hex.EncodeToString, hex.DecodeString)
	}
}
