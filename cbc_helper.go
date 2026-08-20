package crypto

import (
	"bytes"
	"errors"
	"slices"
)

func ExtractIVAndCiphertext(ciphertext []byte, size int) ([]byte, []byte, error) {
	if size <= 0 || len(ciphertext) < size {
		return nil, nil, errors.New("crypto.CBC: ciphertext is missing IV")
	}
	return ciphertext[:size], ciphertext[size:], nil
}

func PrependIVToCiphertext(iv, ciphertext []byte) []byte {
	return slices.Concat(iv, ciphertext)
}

func PKCS7Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	paddedText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, paddedText...)
}

func PKCS7Unpadding(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || blockSize <= 0 || len(data)%blockSize != 0 {
		return nil, errors.New("pksc7: invalid padding length")
	}

	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize || padding > len(data) {
		return nil, errors.New("pksc7: invalid padding")
	}
	for _, value := range data[len(data)-padding:] {
		if int(value) != padding {
			return nil, errors.New("pksc7: invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}
