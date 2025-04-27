package crypto

import (
	"bytes"
)

func PKCS5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	paddedText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, paddedText...)
}

func PKCS5UnPadding(data []byte) []byte {
	length := len(data)
	unPadding := int(data[length-1])
	return data[:(length - unPadding)]
}
