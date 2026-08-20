package crypto

import "testing"

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

func TestCBCRejectsInvalidCiphertext(t *testing.T) {
	block := NewAESCipher("abcdwkjidjfkovdf")
	decrypter := NewCBCDecrypter(block)

	for _, ciphertext := range [][]byte{nil, []byte{1}} {
		if _, err := decrypter.Decrypt(ciphertext); err == nil {
			t.Fatalf("invalid ciphertext was accepted: %x", ciphertext)
		}
	}
}

func TestCBCRejectsInvalidPadding(t *testing.T) {
	data := []byte("123456789012345\x02")
	if _, err := PKCS7Unpadding(data, 16); err == nil {
		t.Fatal("invalid padding was accepted")
	}
}

func TestCBCDecryptFromStringReturnsDecodeError(t *testing.T) {
	cipher := NewAESCipher("abcdwkjidjfkovdf")

	decrypter := NewCBCDecrypter(cipher)
	if _, err := decrypter.DecryptFromString("not-valid-hex", HexDecoder); err == nil {
		t.Fatal("invalid encoded ciphertext was accepted")
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
