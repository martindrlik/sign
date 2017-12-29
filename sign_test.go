package sign_test

import (
	"testing"

	"github.com/martindrlik/sign"
)

const (
	registered      = "registered"
	neverRegistered = "neverRegistered"

	password      = "password"
	wrongPassword = "wrongPassword"
)

func init() {
	sign.PasswordHasher = fastHash{}
}

func TestRegisterSucceeded(t *testing.T) {
	defer sign.Deregister(registered)
	if err := sign.Register(registered); err != nil {
		t.Errorf("expected no error, got %q", err)
	}
}

func TestRegisterAlreadyRegistered(t *testing.T) {
	defer sign.Deregister(registered)
	if err := sign.Register(registered); err != nil {
		t.Fatal(err)
	}
	if err := sign.Register(registered); err != sign.ErrAlreadyRegistered {
		t.Errorf("expected error %q, got %v", sign.ErrAlreadyRegistered, err)
	}
}

func TestRegisterInvalidUsername(t *testing.T) {
	if err := sign.Register(""); err != sign.ErrEmptyUsername {
		t.Errorf("expected error %q, got %q", sign.ErrEmptyUsername, err)
	}
}

func TestDeregisterNotRegistered(t *testing.T) {
	if err := sign.Deregister(neverRegistered); err != sign.ErrNotRegistered {
		t.Errorf("expected error %q, got %v", sign.ErrNotRegistered, err)
	}
}

func TestSetPasswordSucceeded(t *testing.T) {
	defer sign.Deregister(registered)
	if err := sign.Register(registered); err != nil {
		t.Fatal(err)
	}
	if err := sign.SetPassword(registered, password); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestSetPasswordNotRegistered(t *testing.T) {
	if err := sign.SetPassword(neverRegistered, password); err != sign.ErrNotRegistered {
		t.Errorf("expected error %q, got %v", sign.ErrNotRegistered, err)
	}
}

func TestMatchingPassword(t *testing.T) {
	defer sign.Deregister(registered)
	if err := sign.Register(registered); err != nil {
		t.Fatal(err)
	}
	if err := sign.SetPassword(registered, password); err != nil {
		t.Fatal(err)
	}
	if match, err := sign.MatchPassword(registered, password); err != nil {
		t.Errorf("expected no error, got %v", err)
	} else if !match {
		t.Errorf("expected matching password to be true, got false")
	}
}

func TestMatchPasswordNoMatch(t *testing.T) {
	defer sign.Deregister(registered)
	if err := sign.Register(registered); err != nil {
		t.Fatal(err)
	}
	if err := sign.SetPassword(registered, password); err != nil {
		t.Fatal(err)
	}
	if match, err := sign.MatchPassword(registered, wrongPassword); err != nil {
		t.Fatal(err)
	} else if match {
		t.Error("expected matching password to be false, got true")
	}
}

func TestMatchPasswordNotRegistered(t *testing.T) {
	if _, err := sign.MatchPassword(neverRegistered, password); err != sign.ErrNotRegistered {
		t.Errorf("expected error %q, got %v", sign.ErrNotRegistered, err)
	}
}
