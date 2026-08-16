package auth

import (
	"errors"
	"testing"
	"time"
)

func TestIssueAndParse(t *testing.T) {
	service := NewTokenService([]byte("test-secret"), time.Minute, time.Hour)
	tokens, err := service.Issue("person@example.com", []string{"user"})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	claims, err := service.Parse(tokens.AccessToken)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if claims.Email != "person@example.com" || claims.TokenType != "access" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestParseExpiredToken(t *testing.T) {
	service := NewTokenService([]byte("test-secret"), time.Minute, time.Hour)
	service.now = func() time.Time { return time.Unix(1000, 0) }
	tokens, err := service.Issue("person@example.com", []string{"user"})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	service.now = time.Now
	_, err = service.Parse(tokens.AccessToken)
	if !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("Parse() error = %v, want expired token", err)
	}
}
