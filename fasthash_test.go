package sign_test

import (
	"bytes"
)

type fastHash struct{}

func (h fastHash) HashPassword(password []byte) ([]byte, error) {
	return password, nil
}

func (h fastHash) IsMatch(hashedPassword, password []byte) (bool, error) {
	return bytes.Equal(hashedPassword, password), nil
}
