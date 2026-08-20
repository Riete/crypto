package crypto

import (
	"bytes"
	"testing"
)

func TestGCMEncryptDecrypt(t *testing.T) {
	block := NewAESCipher("abcdwkjidjfkovdf")

	crypter, err := NewGCMEncryptDecrypter(block, nil)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := "hello GCM"
	ciphertext, err := crypter.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) != len(plaintext)+28 {
		t.Fatalf("unexpected ciphertext length: got %d", len(ciphertext))
	}

	decrypted, err := crypter.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("plaintext: %q, ciphertext: %x, decrypted: %q", plaintext, ciphertext, decrypted)
	if decrypted != plaintext {
		t.Fatalf("decrypted plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}

	secondCiphertext, err := crypter.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ciphertext, secondCiphertext) {
		t.Fatal("random nonce produced identical ciphertext")
	}
}

func TestGCMEncryptDecryptWithEncoding(t *testing.T) {
	block := NewAESCipher("abcdwkjidjfkovdf")

	encrypter, err := NewGCMEncrypter(block, nil)
	if err != nil {
		t.Fatal(err)
	}
	decrypter, err := NewGCMDecrypter(block, nil)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := encrypter.EncryptToString("hello GCM", Base64Encoder)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := decrypter.DecryptFromString(ciphertext, Base64Decoder)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("plaintext: %q, ciphertext: %s, decrypted: %q", "hello GCM", ciphertext, plaintext)
	if plaintext != "hello GCM" {
		t.Fatalf("decrypted plaintext mismatch: got %q", plaintext)
	}
}

func TestGCMRejectsModifiedCiphertext(t *testing.T) {
	block := NewAESCipher("abcdwkjidjfkovdf")

	crypter, err := NewGCMEncryptDecrypter(block, nil)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := crypter.Encrypt("hello GCM")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 1

	if _, err := crypter.DecryptFromString(string(ciphertext), nil); err == nil {
		t.Fatal("modified ciphertext was accepted")
	}
}

func TestGCMAdditionalData(t *testing.T) {
	block := NewAESCipher("abcdwkjidjfkovdf")

	additionalData := []byte("version=1;user=42")
	crypter, err := NewGCMEncryptDecrypter(block, additionalData)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := crypter.Encrypt("hello GCM")
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := crypter.DecryptFromString(string(ciphertext), nil)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != "hello GCM" {
		t.Fatalf("decrypted plaintext mismatch: got %q", plaintext)
	}

	wrongCrypter, err := NewGCMDecrypter(block, []byte("version=1;user=43"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongCrypter.DecryptFromString(string(ciphertext), nil); err == nil {
		t.Fatal("ciphertext was accepted with incorrect additional data")
	}
}
