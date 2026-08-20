package crypto

type Encrypter interface {
	Encrypt(string) ([]byte, error)
	EncryptToString(string, Encoder) (string, error)
}

type Decrypter interface {
	Decrypt([]byte) (string, error)
	DecryptFromString(string, Decoder) (string, error)
}
