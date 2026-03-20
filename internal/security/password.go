package security

import (
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var ErrWeakPassword = errors.New("weak_password")

func NormalizeLogin(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}

func ValidateLogin(login string) bool {
	return len(NormalizeLogin(login)) >= 3
}

func HashPassword(password string) (string, error) {
	if len(strings.TrimSpace(password)) < 12 {
		return "", ErrWeakPassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func ComparePasswordHash(hash string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
