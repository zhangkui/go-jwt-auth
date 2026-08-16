package user

import (
	"errors"
	"testing"
)

func TestStoreRegisterAndAuthenticate(t *testing.T) {
	store := NewStore()
	registered, err := store.Register(" Person@Example.com ", "secret", []string{"admin"})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if registered.Email != "person@example.com" {
		t.Fatalf("registered email = %q", registered.Email)
	}
	authenticated, err := store.Authenticate("person@example.com", "secret")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if authenticated.Roles[0] != "admin" {
		t.Fatalf("unexpected roles: %#v", authenticated.Roles)
	}
	_, err = store.Authenticate("person@example.com", "incorrect")
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("Authenticate() error = %v, want invalid password", err)
	}
}

func TestStoreRejectsDuplicateEmail(t *testing.T) {
	store := NewStore()
	if _, err := store.Register("person@example.com", "secret", nil); err != nil {
		t.Fatalf("first Register() error = %v", err)
	}
	if _, err := store.Register("person@example.com", "secret", nil); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("second Register() error = %v, want duplicate error", err)
	}
}
