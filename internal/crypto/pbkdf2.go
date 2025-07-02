package crypto

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/rand"
)

const (
	SaltSize = 32
	KeySize = 32
	Iterations = 100000
)

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	_, err := rand.Read(salt)
	return salt, err
}

func DeriveKey(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, Iterations, KeySize)
}
