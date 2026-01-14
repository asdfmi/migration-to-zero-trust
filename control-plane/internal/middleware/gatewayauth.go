package middleware

import (
	"context"
	"net/http"
	"strings"

	"migration-to-zero-trust/control-plane/internal/model"
	"migration-to-zero-trust/control-plane/internal/repository"
)

type gatewayKey struct{}

func GatewayFromContext(ctx context.Context) (model.Gateway, bool) {
	gw, ok := ctx.Value(gatewayKey{}).(model.Gateway)
	return gw, ok
}

func GatewayAPIKey(repo repository.Repository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
			if apiKey == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			gateway, err := repo.GetGatewayByAPIKey(r.Context(), apiKey)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), gatewayKey{}, gateway)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
