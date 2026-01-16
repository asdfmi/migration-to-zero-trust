package middleware

import (
	"context"
	"net/http"
	"strings"

	"migration-to-zero-trust/controlplane/internal/model"
	"migration-to-zero-trust/controlplane/internal/repository"
)

type enforcerKey struct{}

func EnforcerFromContext(ctx context.Context) (model.Enforcer, bool) {
	enf, ok := ctx.Value(enforcerKey{}).(model.Enforcer)
	return enf, ok
}

func EnforcerAPIKey(repo repository.Repository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
			if apiKey == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			enforcerID, ok := model.ParseAPIKey(apiKey)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			enforcer, err := repo.GetEnforcer(r.Context(), enforcerID)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if !enforcer.VerifyAPIKey(apiKey) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), enforcerKey{}, enforcer)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
