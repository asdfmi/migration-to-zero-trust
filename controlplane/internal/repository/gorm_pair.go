package repository

import (
	"context"

	"migration-to-zero-trust/controlplane/internal/model"
)

func (r *GormRepository) CreatePair(ctx context.Context, p *model.Pair) error {
	return r.db.WithContext(ctx).Create(p).Error
}

func (r *GormRepository) ListPairs(ctx context.Context) ([]model.Pair, error) {
	var out []model.Pair
	if err := r.db.WithContext(ctx).
		Preload("Client").
		Preload("Resource").
		Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) ListPairsByClient(ctx context.Context, clientID string) ([]model.Pair, error) {
	var out []model.Pair
	if err := r.db.WithContext(ctx).
		Preload("Resource").
		Preload("Resource.Gateway").
		Where("client_id = ?", clientID).
		Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) ListPairsByGateway(ctx context.Context, gatewayID string) ([]model.Pair, error) {
	var out []model.Pair
	if err := r.db.WithContext(ctx).
		Preload("Client").
		Preload("Resource").
		Joins("JOIN resources ON resources.id = pairs.resource_id").
		Where("resources.gateway_id = ?", gatewayID).
		Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) DeletePair(ctx context.Context, id string) (bool, error) {
	res := r.db.WithContext(ctx).Delete(&model.Pair{}, "id = ?", id)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}
