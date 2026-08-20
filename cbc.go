package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"github.com/riete/convert/str"
)

type IVFunc func() []byte

var FixedIV = func(iv string) IVFunc {
	return func() []byte {
		return str.ToBytes(iv)
	}
}

var randomIV = func(size int) IVFunc {
	return func() []byte {
		iv := make([]byte, size)
		_, _ = rand.Read(iv)
		return iv
	}
}

type CBCCrypter struct {
	iv     IVFunc
	cipher cipher.Block
}

func (c *CBCCrypter) Encrypt(plaintext string) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	iv := c.iv()
	if len(iv) != blockSize {
		return nil, errors.New("crypto.CBCCrypter: IV length must equal block size")
	}
	paddedText := PKCS7Padding(str.ToBytes(plaintext), blockSize)
	encrypter := cipher.NewCBCEncrypter(c.cipher, iv)
	ciphertext := make([]byte, len(paddedText))
	encrypter.CryptBlocks(ciphertext, paddedText)
	return PrependIVToCiphertext(iv, ciphertext), nil
}

func (c *CBCCrypter) EncryptToString(plaintext string, encoder Encoder) (string, error) {
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	if encoder == nil {
		encoder = Base64Encoder
	}
	return encoder(ciphertext), nil
}

func (c *CBCCrypter) Decrypt(ciphertext []byte) (string, error) {
	blockSize := c.cipher.BlockSize()
	iv, ciphertext, err := ExtractIVAndCiphertext(ciphertext, blockSize)
	if err != nil {
		return "", err
	}
	if len(ciphertext) == 0 || len(ciphertext)%blockSize != 0 {
		return "", errors.New("crypto.CBCDecrypter: invalid CBC ciphertext length")
	}
	decrypter := cipher.NewCBCDecrypter(c.cipher, iv)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)
	unpaddedText, err := PKCS7Unpadding(plaintext, blockSize)
	if err != nil {
		return "", err
	}
	return str.FromBytes(unpaddedText), nil
}

func (c *CBCCrypter) DecryptFromString(ciphertext string, decoder Decoder) (string, error) {
	if decoder == nil {
		decoder = Base64Decoder
	}
	decoded, err := decoder(ciphertext)
	if err != nil {
		return "", err
	}
	return c.Decrypt(decoded)
}

func NewCBCEncrypter(cipher cipher.Block, iv IVFunc) Encrypter {
	if iv == nil {
		iv = randomIV(cipher.BlockSize())
	}
	return &CBCCrypter{cipher: cipher, iv: iv}
}

func NewCBCDecrypter(cipher cipher.Block) Decrypter {
	return &CBCCrypter{cipher: cipher}
}
