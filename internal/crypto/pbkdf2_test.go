package crypto

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestGenerateSalt(t *testing.T) {
	t.Run("generates salt of correct size", func(t *testing.T) {
		salt, err := GenerateSalt()
		if err != nil {
			t.Fatalf("GenerateSalt() returned error: %v", err)
		}
		if len(salt) != SaltSize {
			t.Errorf("Expected salt size %d, got %d", SaltSize, len(salt))
		}
	})

	t.Run("generates different salts on each call", func(t *testing.T) {
		salt1, err := GenerateSalt()
		if err != nil {
			t.Fatalf("GenerateSalt() returned error: %v", err)
		}
		salt2, err := GenerateSalt()
		if err != nil {
			t.Fatalf("GenerateSalt() returned error: %v", err)
		}
		if string(salt1) == string(salt2) {
			t.Error("Expected different salts, got the same")
		}
	})

	t.Run("generates non-zero salt", func(t *testing.T) {
		salt, err := GenerateSalt()
		if err != nil {
			t.Fatalf("GenerateSalt() returned error: %v", err)
		}
		allZeros := make([]byte, SaltSize)
		if bytes.Equal(salt, allZeros) {
			t.Error("GenerateSalt() returned all zeros, expected random data")
		}
	})

	t.Run("generates salt multiple times without error", func(t *testing.T) {
		const iterations = 100
		for i := range iterations {
			salt, err := GenerateSalt()
			if err != nil {
				t.Fatalf("GenerateSalt() returned error: %v", err)
			}
			if len(salt) != SaltSize {
				t.Errorf("Expected salt size %d, got %d on iteration %d", SaltSize, len(salt), i)
			}
		}
	})
}

func TestDeriveKey(t *testing.T) {
	t.Run("derives key of correct size", func(t *testing.T) {
		password := "testpassword123"
		salt := []byte("testsalt12345678901234567890123")

		key, err := DeriveKey(password, salt)
		if err != nil {
			t.Fatalf("DeriveKey() returned error: %v", err)
		}
		if len(key) != KeySize {
			t.Errorf("Expected key size %d, got %d", KeySize, len(key))
		}
	})

	t.Run("same password and salt produce same key", func(t *testing.T) {
		password := "testpassword123"
		salt := []byte("testsalt12345678901234567890123")

		key1, err := DeriveKey(password, salt)
		if err != nil {
			t.Fatalf("DeriveKey() returned error: %v", err)
		}
		key2, err := DeriveKey(password, salt)
		if err != nil {
			t.Fatalf("DeriveKey() returned error: %v", err)
		}

		if !bytes.Equal(key1, key2) {
			t.Error("Expected keys to be equal for same password and salt")
		}
	})

	t.Run("different passwords produce different keys", func(t *testing.T) {
		password1 := "testpassword123"
		password2 := "differentpassword456"
		salt := []byte("testsalt12345678901234567890123")

		key1, err := DeriveKey(password1, salt)
		if err != nil {
			t.Fatalf("DeriveKey() returned error: %v", err)
		}
		key2, err := DeriveKey(password2, salt)
		if err != nil {
			t.Fatalf("DeriveKey() returned error: %v", err)
		}

		if bytes.Equal(key1, key2) {
			t.Error("Expected keys to be different for different passwords")
		}
	})

	t.Run("different salts produce different keys", func(t *testing.T) {
		password := "testpassword123"
		salt1 := []byte("testsalt12345678901234567890123")
		salt2 := []byte("anotherSalt12345678901234567890")
		key1, err := DeriveKey(password, salt1)
		if err != nil {
			t.Fatalf("DeriveKey() returned error: %v", err)
		}
		key2, err := DeriveKey(password, salt2)
		if err != nil {
			t.Fatalf("DeriveKey() returned error: %v", err)
		}

		if bytes.Equal(key1, key2) {
			t.Error("Expected keys to be different for different salts")
		}
	})

	t.Run("empty password works", func(t *testing.T) {
		salt := []byte("testsalt12345678901234567890123")

		key, err := DeriveKey("", salt)
		if err != nil {
			t.Fatalf("DeriveKey() returned error: %v", err)
		}
		if len(key) != KeySize {
			t.Errorf("Expected key size %d, got %d", KeySize, len(key))
		}
	})

	t.Run("empty salt works", func(t *testing.T) {
		password := "testpassword123"
		salt := make([]byte, SaltSize) // empty salt

		key, err := DeriveKey(password, salt)
		if err != nil {
			t.Fatalf("DeriveKey() returned error: %v", err)
		}
		if len(key) != KeySize {
			t.Errorf("Expected key size %d, got %d", KeySize, len(key))
		}
	})

	t.Run("produces expected output for known inputs", func(t *testing.T) {
		password := "knownpassword"
		salt := []byte("salt")

		key, err := DeriveKey(password, salt)
		if err != nil {
			t.Fatalf("DeriveKey() returned error: %v", err)
		}

		expected, err  := pbkdf2.Key(sha256.New, password, salt, Iterations, KeySize)
		if !bytes.Equal(key, expected) {
			t.Errorf("Expected derived key to match known output, got %x", key)
		}
	})
}

func TestCryptoConstants(t *testing.T) {
	t.Run("constants have expected values", func(t *testing.T) {
		if SaltSize != 32 {
			t.Errorf("Expected SaltSize to be 32, got %d", SaltSize)
		}

		if KeySize != 32 {
			t.Errorf("Expected KeySize to be 32, got %d", KeySize)
		}

		if Iterations != 100000 {
			t.Errorf("Expected Iterations to be 100000, got %d", Iterations)
		}
	})
}

// Benchmark tests
func BenchmarkGenerateSalt(b *testing.B) {
	for b.Loop() {
		_, err := GenerateSalt()
		if err != nil {
			b.Fatalf("GenerateSalt() returned error: %v", err)
		}
	}
}

func BenchmarkDeriveKey(b *testing.B) {
	password := "testpassword123"
	salt := []byte("testsalt12345678901234567890123")

	b.ResetTimer()
	for b.Loop() {
		_, err := DeriveKey(password, salt)
		if err != nil {
			b.Fatalf("DeriveKey() returned error: %v", err)
		}
	}
}

// Example tests (these show up in documentation)
func ExampleGenerateSalt() {
	salt, err := GenerateSalt()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Generated salt length: %d\n", len(salt))
	// Output: Generated salt length: 32
}

func ExampleDeriveKey() {
	password := "mypassword"
	salt, _ := GenerateSalt()

	key, err := DeriveKey(password, salt)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Derived key length: %d\n", len(key))
	// Output: Derived key length: 32
}
