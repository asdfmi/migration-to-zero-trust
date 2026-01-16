package service

import (
	"context"

	"migration-to-zero-trust/controlplane/internal/model"
	"migration-to-zero-trust/controlplane/internal/repository"
)

func CreateResource(ctx context.Context, repo repository.Repository, name, cidr, enforcerID, mode string) (model.Resource, error) {
	if _, err := repo.GetEnforcer(ctx, enforcerID); err != nil {
		return model.Resource{}, err
	}
	r := model.NewResource(name, cidr, enforcerID, mode)
	if err := repo.CreateResource(ctx, &r); err != nil {
		return model.Resource{}, err
	}
	return r, nil
}
