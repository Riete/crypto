package crypto

type Encrypter interface {
	Encrypt(string) []byte
	EncryptToString(string, Encoder) string
}

type Decrypter interface {
	Decrypt([]byte) string
	DecryptFromString(string, Decoder) (string, error)
}

type EncryptDecrypter interface {
	Encrypter
	Decrypter
}
