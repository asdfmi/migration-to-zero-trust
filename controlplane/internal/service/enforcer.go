package service

import (
	"context"

	"migration-to-zero-trust/controlplane/internal/model"
	"migration-to-zero-trust/controlplane/internal/repository"
)

func CreateEnforcer(ctx context.Context, repo repository.Repository, name, endpoint, tunnelSubnet string) (model.Enforcer, error) {
	e, err := model.NewEnforcer(name, endpoint, tunnelSubnet)
	if err != nil {
		return model.Enforcer{}, err
	}
	if err := repo.CreateEnforcer(ctx, &e); err != nil {
		return model.Enforcer{}, err
	}
	return e, nil
}

func UpdateEnforcerPublicKey(ctx context.Context, repo repository.Repository, id, wgPublicKey string) error {
	if _, err := repo.GetEnforcer(ctx, id); err != nil {
		return err
	}
	return repo.UpdateEnforcerPublicKey(ctx, id, wgPublicKey)
}
