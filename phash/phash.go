package phash

import (
	"golang.org/x/crypto/bcrypt"
)

type hasher struct{}

var (
	Default = hasher{}
)

// HashPassword hashes given password.
func (h hasher) HashPassword(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, 15)
}

func (h hasher) IsMatch(hashedPassword, password []byte) (bool, error) {
	err := bcrypt.CompareHashAndPassword(hashedPassword, password)
	switch {
	case err == bcrypt.ErrMismatchedHashAndPassword:
		return false, nil
	case err != nil:
		return false, err
	default:
		return true, nil
	}
}
