package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"go-jwt-auth/internal/auth"
	"go-jwt-auth/internal/httpapi"
	"go-jwt-auth/internal/user"
)

func main() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "development-secret-change-me"
	}

	store := user.NewStore()
	tokens := auth.NewTokenService([]byte(secret), 15*time.Minute, 24*time.Hour)
	handler := httpapi.NewHandler(store, tokens)

	address := os.Getenv("ADDR")
	if address == "" {
		address = ":8080"
	}

	server := &http.Server{Addr: address, Handler: handler.Routes(), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("go-jwt-auth listening on %s", address)
	log.Fatal(server.ListenAndServe())
}
