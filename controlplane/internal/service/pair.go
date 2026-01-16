package service

import (
	"context"

	"migration-to-zero-trust/controlplane/internal/model"
	"migration-to-zero-trust/controlplane/internal/repository"
)

func CreatePair(ctx context.Context, repo repository.Repository, clientID, resourceID string) (model.Pair, error) {
	if _, err := repo.GetClient(ctx, clientID); err != nil {
		return model.Pair{}, err
	}
	if _, err := repo.GetResource(ctx, resourceID); err != nil {
		return model.Pair{}, err
	}
	p := model.NewPair(clientID, resourceID)
	if err := repo.CreatePair(ctx, &p); err != nil {
		return model.Pair{}, err
	}
	return p, nil
}
