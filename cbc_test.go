package crypto

import (
	"bytes"
	"crypto/cipher"
	"testing"
)

func TestCBCEncryptDecrypt(t *testing.T) {
	cipher := NewAESCipher("abcdwkjidjfkovdf")

	encrypter := NewCBCEncrypter(cipher, FixedIV("abcdwxxidjfkovdf"))
	decrypter := NewCBCDecrypter(cipher)

	tests := []struct {
		name    string
		text    string
		encoder Encoder
		decoder Decoder
	}{
		{name: "empty", text: "", encoder: HexEncoder, decoder: HexDecoder},
		{name: "single block", text: "hello CBC", encoder: HexEncoder, decoder: HexDecoder},
		{
			name:    "multiple blocks",
			text:    "CBC should support plaintext longer than one AES block.",
			encoder: Base64Encoder,
			decoder: Base64Decoder,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := encrypter.EncryptToString(tt.text, tt.encoder)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := decrypter.DecryptFromString(ciphertext, tt.decoder)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("plaintext: %q, ciphertext: %s, decrypted: %q", tt.text, ciphertext, plaintext)
			if plaintext != tt.text {
				t.Fatalf("decrypted plaintext mismatch: got %q, want %q", plaintext, tt.text)
			}
		})
	}
}

func TestCBCEncryptDecryptWithRandomIV(t *testing.T) {
	block := NewAESCipher("abcdwkjidjfkovdf")
	encrypter := NewCBCEncrypter(block, nil)
	decrypter := NewCBCDecrypter(block)

	ciphertext, err := encrypter.Encrypt("hello CBC")
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) != block.BlockSize()+block.BlockSize() {
		t.Fatalf("unexpected ciphertext length: got %d", len(ciphertext))
	}
	plaintext, err := decrypter.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("plaintext: %q, ciphertext: %x, decrypted: %q", "hello CBC", ciphertext, plaintext)
	if plaintext != "hello CBC" {
		t.Fatalf("decrypted plaintext mismatch: got %q", plaintext)
	}

	secondCiphertext, err := encrypter.Encrypt("hello CBC")
	if err != nil {
		t.Fatal(err)
	}
	if string(ciphertext) == string(secondCiphertext) {
		t.Fatal("random IV produced identical ciphertext")
	}
}

func TestCBCEncryptDecryptWithDefaultEncoding(t *testing.T) {
	block := NewAESCipher("abcdwkjidjfkovdf")
	encrypter := NewCBCEncrypter(block, FixedIV("abcdwxxidjfkovdf"))
	decrypter := NewCBCDecrypter(block)

	plaintext := "hello CBC"
	ciphertext, err := encrypter.EncryptToString(plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Base64Decoder(ciphertext)
	if err != nil {
		t.Fatalf("default ciphertext is not Base64: %v", err)
	}
	if len(decoded) != block.BlockSize()*2 {
		t.Fatalf("unexpected decoded ciphertext length: got %d", len(decoded))
	}

	decrypted, err := decrypter.DecryptFromString(ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != plaintext {
		t.Fatalf("decrypted plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestCBCRejectsInvalidCiphertext(t *testing.T) {
	block := NewAESCipher("abcdwkjidjfkovdf")
	decrypter := NewCBCDecrypter(block)

	for _, ciphertext := range [][]byte{nil, []byte{1}, make([]byte, block.BlockSize()), make([]byte, block.BlockSize()+1)} {
		if _, err := decrypter.Decrypt(ciphertext); err == nil {
			t.Fatalf("invalid ciphertext was accepted: %x", ciphertext)
		}
	}
}

func TestCBCRejectsInvalidIVLength(t *testing.T) {
	block := NewAESCipher("abcdwkjidjfkovdf")
	encrypter := NewCBCEncrypter(block, func() []byte { return []byte("short") })

	if _, err := encrypter.Encrypt("hello CBC"); err == nil {
		t.Fatal("invalid IV length was accepted")
	}
}

func TestCBCRejectsInvalidPadding(t *testing.T) {
	block := NewAESCipher("abcdwkjidjfkovdf")
	iv := []byte("abcdwxxidjfkovdf")
	invalidPaddedText := []byte("123456789012345\x02")
	cbcCiphertext := make([]byte, len(invalidPaddedText))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(cbcCiphertext, invalidPaddedText)
	ciphertext := PrependIVToCiphertext(iv, cbcCiphertext)

	if _, err := NewCBCDecrypter(block).Decrypt(ciphertext); err == nil {
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
	cipher := NewAESCipher("abcdwkjidjfkovdf")

	decrypter := NewCBCDecrypter(cipher)
	if _, err := decrypter.DecryptFromString("not-valid-base64", nil); err == nil {
		t.Fatal("invalid Base64 ciphertext was accepted")
	}
}

func TestCBCRejectsInvalidAESKeyLength(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("invalid AES key length was accepted")
		}
	}()
	NewAESCipher("short-key")
}

func TestCBCRejectsInvalidDESKeyLength(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("invalid DES key length was accepted")
		}
	}()
	NewDESCipher("short-key")
}
