package service

import (
	"context"

	"migration-to-zero-trust/controlplane/internal/model"
	"migration-to-zero-trust/controlplane/internal/repository"
)

func CreateGateway(ctx context.Context, repo repository.Repository, name, endpoint, tunnelSubnet string) (model.Gateway, error) {
	g, err := model.NewGateway(name, endpoint, tunnelSubnet)
	if err != nil {
		return model.Gateway{}, err
	}
	if err := repo.CreateGateway(ctx, &g); err != nil {
		return model.Gateway{}, err
	}
	return g, nil
}

func UpdateGatewayPublicKey(ctx context.Context, repo repository.Repository, id, wgPublicKey string) error {
	if _, err := repo.GetGateway(ctx, id); err != nil {
		return err
	}
	return repo.UpdateGatewayPublicKey(ctx, id, wgPublicKey)
}
