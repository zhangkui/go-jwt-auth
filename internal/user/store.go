package user

import (
	"errors"
	"strings"
	"sync"
)

var (
	ErrAlreadyExists = errors.New("user already exists")
	ErrNotFound      = errors.New("user not found")
)

type User struct {
	Email        string   `json:"email"`
	PasswordHash string   `json:"-"`
	Roles        []string `json:"roles"`
}
type Store struct {
	mu    sync.RWMutex
	users map[string]User
}

func NewStore() *Store { return &Store{users: make(map[string]User)} }

func (s *Store) Register(email, password string, roles []string) (User, error) {
	normalizedEmail := normalizeEmail(email)
	if normalizedEmail == "" {
		return User{}, errors.New("email is required")
	}
	s.mu.RLock()
	_, exists := s.users[normalizedEmail]
	s.mu.RUnlock()
	if exists {
		return User{}, ErrAlreadyExists
	}
	passwordHash, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}
	if len(roles) == 0 {
		roles = []string{"user"}
	}
	created := User{Email: normalizedEmail, PasswordHash: passwordHash, Roles: append([]string(nil), roles...)}
	s.mu.Lock()
	s.users[normalizedEmail] = created
	s.mu.Unlock()
	return created, nil
}
func (s *Store) Authenticate(email, password string) (User, error) {
	current, err := s.FindByEmail(email)
	if err != nil {
		return User{}, err
	}
	if err := CheckPassword(current.PasswordHash, password); err != nil {
		return User{}, ErrInvalidPassword
	}
	return current, nil
}
func (s *Store) FindByEmail(email string) (User, error) {
	s.mu.RLock()
	current, exists := s.users[normalizeEmail(email)]
	s.mu.RUnlock()
	if !exists {
		return User{}, ErrNotFound
	}
	current.Roles = append([]string(nil), current.Roles...)
	return current, nil
}
func normalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }
