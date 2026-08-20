package crypto

import (
	"bytes"
	"crypto/cipher"
	"testing"
)

func newGCMTestCrypter(t *testing.T, block cipher.Block, additionalData []byte) (Encrypter, Decrypter) {
	t.Helper()
	encrypter, err := NewGCMEncrypter(block, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	decrypter, err := NewGCMDecrypter(block, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	return encrypter, decrypter
}

func TestGCMEncryptDecrypt(t *testing.T) {
	block := NewAESCipher("abcdwkjidjfkovdf")

	encrypter, decrypter := newGCMTestCrypter(t, block, nil)

	plaintext := "hello GCM"
	ciphertext, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) != len(plaintext)+28 {
		t.Fatalf("unexpected ciphertext length: got %d", len(ciphertext))
	}

	decrypted, err := decrypter.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("plaintext: %q, ciphertext: %x, decrypted: %q", plaintext, ciphertext, decrypted)
	if decrypted != plaintext {
		t.Fatalf("decrypted plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}

	secondCiphertext, err := encrypter.Encrypt(plaintext)
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

	encrypter, decrypter := newGCMTestCrypter(t, block, nil)

	ciphertext, err := encrypter.Encrypt("hello GCM")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 1

	if _, err := decrypter.Decrypt(ciphertext); err == nil {
		t.Fatal("modified ciphertext was accepted")
	}
}

func TestGCMRejectsShortCiphertext(t *testing.T) {
	block := NewAESCipher("abcdwkjidjfkovdf")
	_, decrypter := newGCMTestCrypter(t, block, nil)

	for _, ciphertext := range [][]byte{nil, make([]byte, 27)} {
		if _, err := decrypter.Decrypt(ciphertext); err == nil {
			t.Fatalf("short ciphertext was accepted: %x", ciphertext)
		}
	}
}

func TestGCMRejectsModifiedNonce(t *testing.T) {
	block := NewAESCipher("abcdwkjidjfkovdf")
	encrypter, decrypter := newGCMTestCrypter(t, block, nil)

	ciphertext, err := encrypter.Encrypt("hello GCM")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 1

	if _, err := decrypter.Decrypt(ciphertext); err == nil {
		t.Fatal("modified nonce was accepted")
	}
}

func TestGCMAdditionalData(t *testing.T) {
	block := NewAESCipher("abcdwkjidjfkovdf")

	additionalData := []byte("version=1;user=42")
	encrypter, decrypter := newGCMTestCrypter(t, block, additionalData)

	ciphertext, err := encrypter.EncryptToString("hello GCM", nil)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := decrypter.DecryptFromString(ciphertext, nil)
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

func TestGCMDecryptFromStringReturnsDecodeError(t *testing.T) {
	block := NewAESCipher("abcdwkjidjfkovdf")
	decrypter, err := NewGCMDecrypter(block, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := decrypter.DecryptFromString("not-valid-base64", Base64Decoder); err == nil {
		t.Fatal("invalid encoded ciphertext was accepted")
	}
}

func TestGCMRequiresAESBlock(t *testing.T) {
	block := NewDESCipher("12345678")
	if _, err := NewGCMEncrypter(block, nil); err == nil {
		t.Fatal("non-AES block was accepted")
	}
}
