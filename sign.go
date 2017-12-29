package sign

import (
	"errors"
	"sync"

	"github.com/martindrlik/sign/phash"
)

var (
	ErrEmptyUsername     = errors.New("username can't be empty string")
	ErrAlreadyRegistered = errors.New("username already registered")
	ErrNotRegistered     = errors.New("username is not registered")
	ErrPasswordMismatch  = errors.New("username and password does not match")
)

type Hasher interface {
	HashPassword(password []byte) ([]byte, error)
	IsMatch(hashedPassword, password []byte) (bool, error)
}

var (
	PasswordHasher Hasher = phash.Default

	mutex        sync.RWMutex
	userRegister = make(map[string][]byte)
)

func Register(username string) error {
	mutex.Lock()
	defer mutex.Unlock()

	if username == "" {
		return ErrEmptyUsername
	}
	if _, ok := userRegister[username]; ok {
		return ErrAlreadyRegistered
	}
	userRegister[username] = nil
	return nil
}

func Deregister(username string) error {
	mutex.Lock()
	defer mutex.Unlock()

	if _, ok := userRegister[username]; !ok {
		return ErrNotRegistered
	}
	delete(userRegister, username)
	return nil
}

func SetPassword(username, password string) error {
	mutex.Lock()
	defer mutex.Unlock()

	if _, ok := userRegister[username]; !ok {
		return ErrNotRegistered
	}
	b, err := PasswordHasher.HashPassword([]byte(password))
	if err != nil {
		return err
	}
	userRegister[username] = b
	return nil
}

func MatchPassword(username, password string) (bool, error) {
	mutex.RLock()
	defer mutex.RUnlock()

	hash, ok := userRegister[username]
	if !ok {
		return false, ErrNotRegistered
	}
	return PasswordHasher.IsMatch(hash, []byte(password))
}
