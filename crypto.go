package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"unsafe"
)

func bytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func stringToBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func unPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// Encrypt key length is n * 16
func Encrypt(key, data string) string {
	k := stringToBytes(key)
	block, _ := aes.NewCipher(k)
	blockSize := block.BlockSize()
	padData := padding([]byte(data), blockSize)
	blockMode := cipher.NewCBCEncrypter(block, k[:blockSize])
	encryptData := make([]byte, len(padData))
	blockMode.CryptBlocks(encryptData, padData)
	return base64.StdEncoding.EncodeToString(encryptData)
}

// Decrypt key length is n * 16
func Decrypt(key, data string) string {
	k := stringToBytes(key)
	block, _ := aes.NewCipher(k)
	decodeData, _ := base64.StdEncoding.DecodeString(data)
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, k[:blockSize])
	decryptData := make([]byte, len(decodeData))
	blockMode.CryptBlocks(decryptData, decodeData)
	return bytesToString(unPadding(decryptData))
}
