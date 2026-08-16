package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go-jwt-auth/internal/auth"
	"go-jwt-auth/internal/user"
)

func TestAuthenticationFlow(t *testing.T) {
	store := user.NewStore()
	if _, err := store.Register("admin@example.com", "secret", []string{"admin"}); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	handler := NewHandler(store, auth.NewTokenService([]byte("test-secret"), time.Minute, time.Hour)).Routes()

	register := request(handler, http.MethodPost, "/register", `{"email":"user@example.com","password":"secret"}`, "")
	if register.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body = %s", register.Code, register.Body.String())
	}
	login := request(handler, http.MethodPost, "/login", `{"email":"admin@example.com","password":"secret"}`, "")
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", login.Code, login.Body.String())
	}
	var tokens auth.TokenPair
	if err := json.Unmarshal(login.Body.Bytes(), &tokens); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	me := request(handler, http.MethodGet, "/me", "", "Bearer "+tokens.AccessToken)
	if me.Code != http.StatusOK {
		t.Fatalf("me status = %d, body = %s", me.Code, me.Body.String())
	}
	admin := request(handler, http.MethodGet, "/admin", "", "Bearer "+tokens.AccessToken)
	if admin.Code != http.StatusOK {
		t.Fatalf("admin status = %d, body = %s", admin.Code, admin.Body.String())
	}
	refreshed := request(handler, http.MethodPost, "/refresh", `{"refresh_token":"`+tokens.RefreshToken+`"}`, "")
	if refreshed.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, body = %s", refreshed.Code, refreshed.Body.String())
	}
}

func TestProtectedRouteRejectsMissingCredentials(t *testing.T) {
	handler := NewHandler(user.NewStore(), auth.NewTokenService([]byte("test-secret"), time.Minute, time.Hour)).Routes()
	response := request(handler, http.MethodGet, "/me", "", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func request(handler http.Handler, method, path, body, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}
