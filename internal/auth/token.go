package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("expired token")
)

type Claims struct {
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	TokenType string   `json:"token_type"`
	Subject   string   `json:"sub"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type TokenService struct {
	secret          []byte
	accessLifetime  time.Duration
	refreshLifetime time.Duration
	now             func() time.Time
}

func NewTokenService(secret []byte, accessLifetime, refreshLifetime time.Duration) *TokenService {
	return &TokenService{secret: append([]byte(nil), secret...), accessLifetime: accessLifetime, refreshLifetime: refreshLifetime, now: time.Now}
}

func (s *TokenService) Issue(email string, roles []string) (TokenPair, error) {
	currentTime := s.now().UTC()
	access, err := s.sign(Claims{Email: email, Roles: append([]string(nil), roles...), TokenType: "access", Subject: email, IssuedAt: currentTime.Unix(), ExpiresAt: currentTime.Add(s.accessLifetime).Unix()})
	if err != nil {
		return TokenPair{}, err
	}
	refresh, err := s.sign(Claims{Email: email, Roles: append([]string(nil), roles...), TokenType: "refresh", Subject: email, IssuedAt: currentTime.Unix(), ExpiresAt: currentTime.Add(s.refreshLifetime).Unix()})
	if err != nil {
		return TokenPair{}, err
	}
	return TokenPair{AccessToken: access, RefreshToken: refresh, ExpiresIn: int64(s.accessLifetime.Seconds())}, nil
}

func (s *TokenService) Refresh(token string) (TokenPair, error) {
	claims, err := s.Parse(token)
	if err != nil {
		return TokenPair{}, err
	}
	if claims.TokenType != "refresh" {
		return TokenPair{}, ErrInvalidToken
	}
	return s.Issue(claims.Email, claims.Roles)
}

func (s *TokenService) Parse(tokenString string) (Claims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 || !hmac.Equal(s.signature(parts[0]+"."+parts[1]), decodeSegment(parts[2])) {
		return Claims{}, ErrInvalidToken
	}
	payload, err := decodeSegmentE(parts[1])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Email == "" || claims.Subject != claims.Email {
		return Claims{}, ErrInvalidToken
	}
	if s.now().Unix() >= claims.ExpiresAt {
		return Claims{}, ErrExpiredToken
	}
	claims.Roles = append([]string(nil), claims.Roles...)
	return claims, nil
}

func (s *TokenService) sign(claims Claims) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", fmt.Errorf("encode token header: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode token claims: %w", err)
	}
	unsigned := encodeSegment(header) + "." + encodeSegment(payload)
	return unsigned + "." + encodeSegment(s.signature(unsigned)), nil
}

func (s *TokenService) signature(value string) []byte {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}
func encodeSegment(value []byte) string           { return base64.RawURLEncoding.EncodeToString(value) }
func decodeSegment(value string) []byte           { decoded, _ := decodeSegmentE(value); return decoded }
func decodeSegmentE(value string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(value) }
