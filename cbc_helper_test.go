package crypto

import (
	"bytes"
	"testing"
)

func TestPKCS7PaddingRoundTrip(t *testing.T) {
	for _, plaintext := range [][]byte{
		nil,
		[]byte("hello"),
		[]byte("1234567890123456"),
	} {
		padded := PKCS7Padding(bytes.Clone(plaintext), 16)
		unpadded, err := PKCS7Unpadding(padded, 16)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(unpadded, plaintext) {
			t.Fatalf("round trip mismatch: got %q, want %q", unpadded, plaintext)
		}
	}
}

func TestPKCS7UnpaddingRejectsInvalidData(t *testing.T) {
	tests := [][]byte{
		nil,
		[]byte("short"),
		[]byte("123456789012345\x00"),
		[]byte("123456789012345\x11"),
		[]byte("123456789012345\x02"),
	}

	for _, data := range tests {
		if _, err := PKCS7Unpadding(data, 16); err == nil {
			t.Fatalf("invalid padding was accepted: %x", data)
		}
	}
}
