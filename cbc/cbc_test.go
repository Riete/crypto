package cbc

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/riete/crypto"
)

func TestCBCEncryptDecrypt(t *testing.T) {
	block := crypto.NewAESCipher("abcdwkjidjfkovdf")
	crypter := NewCrypter(block, WithFixedIV("abcdwxxidjfkovdf"))

	for _, plaintext := range []string{
		"",
		"hello CBC",
		"CBC should support plaintext longer than one AES block.",
	} {
		t.Run(plaintext, func(t *testing.T) {
			ciphertext, err := crypter.Encrypt(plaintext)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := crypter.Decrypt(ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("plaintext: %q, ciphertext: %x, decrypted: %q", plaintext, ciphertext, decrypted)
			if decrypted != plaintext {
				t.Fatalf("decrypted plaintext mismatch: got %q, want %q", decrypted, plaintext)
			}
		})
	}
}

func TestCBCEncryptDecryptWithRandomIV(t *testing.T) {
	block := crypto.NewAESCipher("abcdwkjidjfkovdf")
	crypter := NewCrypter(block)

	ciphertext, err := crypter.Encrypt("hello CBC")
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) != block.BlockSize()+block.BlockSize() {
		t.Fatalf("unexpected ciphertext length: got %d", len(ciphertext))
	}
	plaintext, err := crypter.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("plaintext: %q, ciphertext: %x, decrypted: %q", "hello CBC", ciphertext, plaintext)
	if plaintext != "hello CBC" {
		t.Fatalf("decrypted plaintext mismatch: got %q", plaintext)
	}

	secondCiphertext, err := crypter.Encrypt("hello CBC")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ciphertext, secondCiphertext) {
		t.Fatal("random IV produced identical ciphertext")
	}
}

func TestCBCEncryptDecryptWithDefaultCodec(t *testing.T) {
	block := crypto.NewAESCipher("abcdwkjidjfkovdf")
	crypter := NewCrypter(block, WithFixedIV("abcdwxxidjfkovdf"))

	plaintext := "hello CBC"
	ciphertext, err := crypter.EncryptToString(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Fatalf("default ciphertext is not Base64: %v", err)
	}
	if len(decoded) != block.BlockSize()*2 {
		t.Fatalf("unexpected decoded ciphertext length: got %d", len(decoded))
	}

	decrypted, err := crypter.DecryptFromString(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != plaintext {
		t.Fatalf("decrypted plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestCBCEncryptDecryptWithHexCodec(t *testing.T) {
	block := crypto.NewAESCipher("abcdwkjidjfkovdf")
	crypter := NewCrypter(block, WithFixedIV("abcdwxxidjfkovdf"), WithHexCipherCodec())

	plaintext := "hello CBC"
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

func TestCBCRejectsInvalidCiphertext(t *testing.T) {
	block := crypto.NewAESCipher("abcdwkjidjfkovdf")
	crypter := NewCrypter(block)

	for _, ciphertext := range [][]byte{nil, []byte{1}, make([]byte, block.BlockSize()), make([]byte, block.BlockSize()+1)} {
		if _, err := crypter.Decrypt(ciphertext); err == nil {
			t.Fatalf("invalid ciphertext was accepted: %x", ciphertext)
		}
	}
}

func TestCBCRejectsInvalidIVLength(t *testing.T) {
	block := crypto.NewAESCipher("abcdwkjidjfkovdf")
	crypter := NewCrypter(block, WithFixedIV("short"))

	if _, err := crypter.Encrypt("hello CBC"); err == nil {
		t.Fatal("invalid IV length was accepted")
	}
}

func TestCBCRejectsInvalidPadding(t *testing.T) {
	block := crypto.NewAESCipher("abcdwkjidjfkovdf")
	iv := []byte("abcdwxxidjfkovdf")
	invalidPaddedText := []byte("123456789012345\x02")
	cbcCiphertext := make([]byte, len(invalidPaddedText))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(cbcCiphertext, invalidPaddedText)
	ciphertext := PrependIVToCiphertext(iv, cbcCiphertext)

	if _, err := NewCrypter(block).Decrypt(ciphertext); err == nil {
		t.Fatal("invalid padding was accepted")
	}
}

func TestCBCIVHelpers(t *testing.T) {
	iv := []byte("1234567890123456")
	ciphertext := []byte("ciphertext")
	combined := PrependIVToCiphertext(iv, ciphertext)

	gotIV, gotCiphertext, err := ExtractIVAndCiphertext(combined, len(iv))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotIV, iv) || !bytes.Equal(gotCiphertext, ciphertext) {
		t.Fatalf("unexpected extracted values: iv=%q, ciphertext=%q", gotIV, gotCiphertext)
	}

	if _, _, err := ExtractIVAndCiphertext(ciphertext, len(iv)); err == nil {
		t.Fatal("missing IV was accepted")
	}
}

func TestCBCDecryptFromStringReturnsDecodeError(t *testing.T) {
	crypter := NewCrypter(crypto.NewAESCipher("abcdwkjidjfkovdf"))
	if _, err := crypter.DecryptFromString("not-valid-base64"); err == nil {
		t.Fatal("invalid Base64 ciphertext was accepted")
	}
}

func TestCBCRejectsInvalidAESKeyLength(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("invalid AES key length was accepted")
		}
	}()
	crypto.NewAESCipher("short-key")
}

func TestCBCRejectsInvalidDESKeyLength(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("invalid DES key length was accepted")
		}
	}()
	crypto.NewDESCipher("short-key")
}
