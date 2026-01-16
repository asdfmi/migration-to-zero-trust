package service

import (
	"context"

	"migration-to-zero-trust/controlplane/internal/model"
	"migration-to-zero-trust/controlplane/internal/repository"
)

func CreateClient(ctx context.Context, repo repository.Repository, name, username, password, wgPublicKey string) (model.Client, error) {
	c, err := model.NewClient(name, username, password, wgPublicKey)
	if err != nil {
		return model.Client{}, err
	}
	if err := repo.CreateClient(ctx, &c); err != nil {
		return model.Client{}, err
	}
	return c, nil
}
