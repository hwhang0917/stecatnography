package crypto

import (
	"crypto/aes"
	"crypto/rand"
)

func GenerateIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	return iv, err
}

func EncryptAES256(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	block.Encrypt(out, []byte(data))
	return out, nil
}

func DecryptAES256(encryptedData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(encryptedData))
	block.Decrypt(out, encryptedData)
	return out, nil
}
