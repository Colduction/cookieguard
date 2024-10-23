package cookieguard

import (
	"encoding/base64"
	"errors"

	"github.com/colduction/aes"
)

const nonceSize int = 12

// EncryptCookie Encrypts a cookie data with specific encryption key
func EncryptCookie(data, key []byte) ([]byte, error) {
	nonce, err := aes.GenerateRandomBytes(nonceSize)
	if err != nil {
		return nil, err
	}
	encrypted, err := aes.GCM.Encrypt(data, key, nonce, nil, nil, nonce...)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(encrypted)))
	base64.RawURLEncoding.Encode(encoded, encrypted)
	return encoded, nil
}

// DecryptCookie Decrypts a cookie data with specific encryption key
func DecryptCookie(data, key []byte) ([]byte, error) {
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(data)))
	_, err := base64.RawURLEncoding.Decode(decoded, data)
	if err != nil {
		return nil, err
	}
	if len(decoded) < nonceSize {
		return nil, errors.New("encrypted data is not valid")
	}
	decrypted, err := aes.GCM.Decrypt(decoded[nonceSize:], key, decoded[:nonceSize], nil, nil)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// GenerateKey Generates an encryption key according to the length.
// If the length does not match the valid AES block size, it generates a 32-byte encryption key instead.
func GenerateKey(length ...int) []byte {
	var key = make([]byte, 0)
	if len(length) != 0 {
		switch length[0] {
		case 16, 24, 32:
			key, _ = aes.GenerateRandomBytes(length[0])
			return key
		}
	}
	key, _ = aes.GenerateRandomBytes(32)
	return key
}

// Check given cookie key is disabled for encryption or not
func isDisabledBytesK(key []byte, except []string) bool {
	if len(key) == 0 {
		return false
	}
	sKey := string(key)
	for _, k := range except {
		if sKey == k {
			return true
		}
	}

	return false
}
