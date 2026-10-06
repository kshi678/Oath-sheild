package auth

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

const (
	MinPasswordLen = 8
	// bcrypt silently truncates input beyond 72 bytes, so we reject it instead.
	MaxPasswordLen = 72
)

var ErrPasswordLength = errors.New("password must be 8-72 bytes")

func ValidatePassword(p string) error {
	if len(p) < MinPasswordLen || len(p) > MaxPasswordLen {
		return ErrPasswordLength
	}
	return nil
}

func HashPassword(password string, cost int) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(b), err
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
