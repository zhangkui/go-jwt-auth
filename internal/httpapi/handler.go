package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"go-jwt-auth/internal/auth"
	"go-jwt-auth/internal/user"
)

type Handler struct {
	users  *user.Store
	tokens *auth.TokenService
}

func NewHandler(users *user.Store, tokens *auth.TokenService) *Handler {
	return &Handler{users: users, tokens: tokens}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", method(http.MethodGet, h.health))
	mux.HandleFunc("/register", method(http.MethodPost, h.register))
	mux.HandleFunc("/login", method(http.MethodPost, h.login))
	mux.HandleFunc("/refresh", method(http.MethodPost, h.refresh))
	mux.Handle("/me", methodHandler(http.MethodGet, h.requireAuth(http.HandlerFunc(h.me))))
	mux.Handle("/admin", methodHandler(http.MethodGet, h.requireAuth(requireRole("admin", http.HandlerFunc(h.admin)))))
	return mux
}

func method(expected string, next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != expected {
			writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		next(writer, request)
	}
}

func methodHandler(expected string, next http.Handler) http.Handler {
	return method(expected, next.ServeHTTP)
}

type credentialsRequest struct {
	Email    string   `json:"email"`
	Password string   `json:"password"`
	Roles    []string `json:"roles"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handler) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}
func (h *Handler) register(writer http.ResponseWriter, request *http.Request) {
	var payload credentialsRequest
	if err := decodeJSON(request, &payload); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid request body")
		return
	}
	created, err := h.users.Register(payload.Email, payload.Password, nil)
	if err != nil {
		if errors.Is(err, user.ErrAlreadyExists) {
			writeError(writer, http.StatusConflict, "email is already registered")
			return
		}
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"user": publicUser(created)})
}
func (h *Handler) login(writer http.ResponseWriter, request *http.Request) {
	var payload credentialsRequest
	if err := decodeJSON(request, &payload); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid request body")
		return
	}
	current, err := h.users.Authenticate(payload.Email, payload.Password)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, "invalid email or password")
		return
	}
	pair, err := h.tokens.Issue(current.Email, current.Roles)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "could not issue token")
		return
	}
	writeJSON(writer, http.StatusOK, pair)
}
func (h *Handler) refresh(writer http.ResponseWriter, request *http.Request) {
	var payload refreshRequest
	if err := decodeJSON(request, &payload); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid request body")
		return
	}
	pair, err := h.tokens.Refresh(payload.RefreshToken)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, "refresh token is invalid or expired")
		return
	}
	writeJSON(writer, http.StatusOK, pair)
}
func (h *Handler) me(writer http.ResponseWriter, request *http.Request) {
	claims, _ := claimsFromContext(request.Context())
	writeJSON(writer, http.StatusOK, map[string]any{"email": claims.Email, "roles": claims.Roles})
}
func (h *Handler) admin(writer http.ResponseWriter, request *http.Request) {
	claims, _ := claimsFromContext(request.Context())
	writeJSON(writer, http.StatusOK, map[string]string{"message": "welcome, " + claims.Email})
}
func decodeJSON(request *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return nil
}
func publicUser(current user.User) map[string]any {
	return map[string]any{"email": current.Email, "roles": current.Roles}
}
