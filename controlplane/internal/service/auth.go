package service

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"migration-to-zero-trust/controlplane/internal/repository"
)

const clientTokenTTL = 24 * time.Hour

var jwtSecret []byte

func InitJWT(secret string) {
	if secret == "" {
		panic("JWT secret is required")
	}
	jwtSecret = []byte(secret)
}

type ClientClaims struct {
	ClientID string `json:"client_id"`
	jwt.RegisteredClaims
}

func ClientLogin(ctx context.Context, repo repository.Repository, user, pass string) (string, error) {
	client, err := repo.GetClientByUsername(ctx, user)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", AuthError{Msg: "unauthorized"}
		}
		return "", err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.PasswordHash), []byte(pass)); err != nil {
		return "", AuthError{Msg: "unauthorized"}
	}

	claims := ClientClaims{
		ClientID: client.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(clientTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ValidateClientToken(tokenString string) (ClientClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &ClientClaims{}, func(token *jwt.Token) (any, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return ClientClaims{}, AuthError{Msg: "unauthorized"}
	}

	claims, ok := token.Claims.(*ClientClaims)
	if !ok || !token.Valid {
		return ClientClaims{}, AuthError{Msg: "unauthorized"}
	}

	return *claims, nil
}

// Context helpers

type claimsKey struct{}

func ContextWithClaims(ctx context.Context, claims ClientClaims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

func ClaimsFromContext(ctx context.Context) (ClientClaims, bool) {
	claims, ok := ctx.Value(claimsKey{}).(ClientClaims)
	return claims, ok
}
