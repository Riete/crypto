package gcm

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/riete/crypto"
)

func TestGCMEncryptDecrypt(t *testing.T) {
	block := crypto.NewAESCipher("abcdwkjidjfkovdf")
	crypter, err := NewCrypter(block)
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

func TestGCMEncryptDecryptWithDefaultCodec(t *testing.T) {
	block := crypto.NewAESCipher("abcdwkjidjfkovdf")
	crypter, err := NewCrypter(block)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := "hello GCM"
	ciphertext, err := crypter.EncryptToString(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base64.StdEncoding.DecodeString(ciphertext); err != nil {
		t.Fatalf("default ciphertext is not Base64: %v", err)
	}
	decrypted, err := crypter.DecryptFromString(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("plaintext: %q, ciphertext: %s, decrypted: %q", plaintext, ciphertext, decrypted)
	if decrypted != plaintext {
		t.Fatalf("decrypted plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestGCMEncryptDecryptWithHexCodec(t *testing.T) {
	block := crypto.NewAESCipher("abcdwkjidjfkovdf")
	crypter, err := NewCrypter(block, WithHexCipherCodec())
	if err != nil {
		t.Fatal(err)
	}

	plaintext := "hello GCM"
	ciphertext, err := crypter.EncryptToString(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hex.DecodeString(ciphertext); err != nil {
		t.Fatalf("hex codec produced invalid ciphertext: %v", err)
	}
	decrypted, err := crypter.DecryptFromString(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != plaintext {
		t.Fatalf("decrypted plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestGCMRejectsModifiedCiphertext(t *testing.T) {
	block := crypto.NewAESCipher("abcdwkjidjfkovdf")
	crypter, err := NewCrypter(block)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := crypter.Encrypt("hello GCM")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 1

	if _, err := crypter.Decrypt(ciphertext); err == nil {
		t.Fatal("modified ciphertext was accepted")
	}
}

func TestGCMRejectsShortCiphertext(t *testing.T) {
	crypter, err := NewCrypter(crypto.NewAESCipher("abcdwkjidjfkovdf"))
	if err != nil {
		t.Fatal(err)
	}

	for _, ciphertext := range [][]byte{nil, make([]byte, 27)} {
		if _, err := crypter.Decrypt(ciphertext); err == nil {
			t.Fatalf("short ciphertext was accepted: %x", ciphertext)
		}
	}
}

func TestGCMRejectsModifiedNonce(t *testing.T) {
	crypter, err := NewCrypter(crypto.NewAESCipher("abcdwkjidjfkovdf"))
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := crypter.Encrypt("hello GCM")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 1

	if _, err := crypter.Decrypt(ciphertext); err == nil {
		t.Fatal("modified nonce was accepted")
	}
}

func TestGCMAdditionalData(t *testing.T) {
	block := crypto.NewAESCipher("abcdwkjidjfkovdf")
	additionalData := []byte("version=1;user=42")
	crypter, err := NewCrypter(block, WithAdditionalData(additionalData))
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := crypter.EncryptToString("hello GCM")
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := crypter.DecryptFromString(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != "hello GCM" {
		t.Fatalf("decrypted plaintext mismatch: got %q", plaintext)
	}

	wrongCrypter, err := NewCrypter(block, WithAdditionalData([]byte("version=1;user=43")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongCrypter.DecryptFromString(ciphertext); err == nil {
		t.Fatal("ciphertext was accepted with incorrect additional data")
	}
}

func TestGCMDecryptFromStringReturnsDecodeError(t *testing.T) {
	crypter, err := NewCrypter(crypto.NewAESCipher("abcdwkjidjfkovdf"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := crypter.DecryptFromString("not-valid-base64"); err == nil {
		t.Fatal("invalid Base64 ciphertext was accepted")
	}
}

func TestGCMRequiresAESBlock(t *testing.T) {
	if _, err := NewCrypter(crypto.NewDESCipher("12345678")); err == nil {
		t.Fatal("non-AES block was accepted")
	}
}
