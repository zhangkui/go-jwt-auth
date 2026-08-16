package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"go-jwt-auth/internal/auth"
	"net/http"
	"strings"
)

type contextKey string

const claimsKey contextKey = "auth_claims"

func (h *Handler) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		token, err := bearerToken(request.Header.Get("Authorization"))
		if err != nil {
			writeError(writer, http.StatusUnauthorized, "authentication is required")
			return
		}
		claims, err := h.tokens.Parse(token)
		if err != nil {
			writeError(writer, http.StatusUnauthorized, "authentication is invalid or expired")
			return
		}
		next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), claimsKey, claims)))
	})
}
func requireRole(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		claims, ok := claimsFromContext(request.Context())
		if !ok || !hasRole(claims.Roles, role) {
			writeError(writer, http.StatusForbidden, "insufficient permissions")
			return
		}
		next.ServeHTTP(writer, request)
	})
}
func claimsFromContext(ctx context.Context) (auth.Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(auth.Claims)
	return claims, ok
}
func bearerToken(header string) (string, error) {
	if header == "" {
		return "", errors.New("missing authorization header")
	}
	if !strings.EqualFold(header[:7], "Bearer ") {
		return "", errors.New("invalid authorization header")
	}
	token := strings.TrimSpace(header[7:])
	if token == "" {
		return "", errors.New("empty bearer token")
	}
	return token, nil
}
func hasRole(roles []string, wanted string) bool {
	for _, role := range roles {
		if role == wanted {
			return true
		}
	}
	return false
}
func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{"error": message})
}
