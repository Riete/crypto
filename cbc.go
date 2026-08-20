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

func randomIV(size int) IVFunc {
	return func() []byte {
		iv := make([]byte, size)
		if _, err := rand.Read(iv); err != nil {
			panic(err)
		}
		return iv
	}
}

type CBCEncrypter struct {
	iv     IVFunc
	cipher cipher.Block
}

func (c *CBCEncrypter) Encrypt(plaintext string) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	iv := c.iv()
	if len(iv) != blockSize {
		return nil, errors.New("crypto.CBCEncrypter: IV length must equal block size")
	}
	paddedText := PKCS7Padding(str.ToBytes(plaintext), blockSize)
	encrypter := cipher.NewCBCEncrypter(c.cipher, iv)
	ciphertext := make([]byte, len(paddedText))
	encrypter.CryptBlocks(ciphertext, paddedText)
	return PrependIVToCiphertext(iv, ciphertext), nil
}

func (c *CBCEncrypter) EncryptToString(plaintext string, encoder Encoder) (string, error) {
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	if encoder == nil {
		encoder = str.FromBytes
	}
	return encoder(ciphertext), nil
}

type CBCDecrypter struct {
	cipher cipher.Block
}

func (c *CBCDecrypter) Decrypt(ciphertext []byte) (string, error) {
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

func (c *CBCDecrypter) DecryptFromString(ciphertext string, decoder Decoder) (string, error) {
	if decoder == nil {
		return c.Decrypt(str.ToBytes(ciphertext))
	}
	decoded, err := decoder(ciphertext)
	if err != nil {
		return "", err
	}
	return c.Decrypt(decoded)
}

type CBCEncryptDecrypter struct {
	*CBCEncrypter
	*CBCDecrypter
}

func NewCBCEncrypter(cipher cipher.Block, iv IVFunc) *CBCEncrypter {
	if iv == nil {
		iv = randomIV(cipher.BlockSize())
	}
	return &CBCEncrypter{cipher: cipher, iv: iv}
}

func NewCBCDecrypter(cipher cipher.Block) *CBCDecrypter {
	return &CBCDecrypter{cipher: cipher}
}

func NewCBCEncryptDecrypter(encrypter *CBCEncrypter, decrypter *CBCDecrypter) *CBCEncryptDecrypter {
	return &CBCEncryptDecrypter{encrypter, decrypter}
}
