package crypto

// Crypter provides binary and encoded string encryption and decryption.
type Crypter interface {
	Encrypt(plaintext string) ([]byte, error)
	EncryptToString(plaintext string) (string, error)
	Decrypt(ciphertext []byte) (string, error)
	DecryptFromString(ciphertext string) (string, error)
}
