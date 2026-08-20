package crypto

type Crypter interface {
	Encrypt(string) ([]byte, error)
	EncryptToString(string) (string, error)
	Decrypt([]byte) (string, error)
	DecryptFromString(string) (string, error)
}
