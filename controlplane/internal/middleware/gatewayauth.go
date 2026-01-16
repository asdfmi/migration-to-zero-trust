package middleware

import (
	"context"
	"net/http"
	"strings"

	"migration-to-zero-trust/controlplane/internal/model"
	"migration-to-zero-trust/controlplane/internal/repository"
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

			gatewayID, ok := model.ParseAPIKey(apiKey)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			gateway, err := repo.GetGateway(r.Context(), gatewayID)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if !gateway.VerifyAPIKey(apiKey) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), gatewayKey{}, gateway)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
