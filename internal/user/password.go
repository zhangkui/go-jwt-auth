package user

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidPassword = errors.New("invalid password")

func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password is required")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	digest := hash(salt, password)
	return base64.RawStdEncoding.EncodeToString(salt) + ":" + base64.RawStdEncoding.EncodeToString(digest), nil
}

func CheckPassword(encoded, password string) error {
	parts := strings.Split(encoded, ":")
	if len(parts) != 2 {
		return ErrInvalidPassword
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return ErrInvalidPassword
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return ErrInvalidPassword
	}
	if subtle.ConstantTimeCompare(expected, hash(salt, password)) != 1 {
		return ErrInvalidPassword
	}
	return nil
}

func hash(salt []byte, password string) []byte {
	payload := make([]byte, 0, len(salt)+len(password))
	payload = append(payload, salt...)
	payload = append(payload, password...)
	digest := sha256.Sum256(payload)
	return digest[:]
}
