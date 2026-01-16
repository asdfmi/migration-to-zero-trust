package repository

import (
	"context"

	"migration-to-zero-trust/controlplane/internal/model"
)

func (r *GormRepository) CreateGateway(ctx context.Context, g *model.Gateway) error {
	return r.db.WithContext(ctx).Create(g).Error
}

func (r *GormRepository) UpsertGateway(ctx context.Context, g *model.Gateway) error {
	return r.db.WithContext(ctx).Save(g).Error
}

func (r *GormRepository) ListGateways(ctx context.Context) ([]model.Gateway, error) {
	var out []model.Gateway
	if err := r.db.WithContext(ctx).Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) GetGateway(ctx context.Context, id string) (model.Gateway, error) {
	var g model.Gateway
	if err := r.db.WithContext(ctx).First(&g, "id = ?", id).Error; err != nil {
		return model.Gateway{}, mapErr(err)
	}
	return g, nil
}

func (r *GormRepository) UpdateGatewayPublicKey(ctx context.Context, id, pubKey string) error {
	return r.db.WithContext(ctx).Model(&model.Gateway{}).Where("id = ?", id).
		Update("wg_public_key", pubKey).Error
}

func (r *GormRepository) DeleteGateway(ctx context.Context, id string) (bool, error) {
	res := r.db.WithContext(ctx).Delete(&model.Gateway{}, "id = ?", id)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (r *GormRepository) FetchGatewayConfigData(ctx context.Context, gatewayID string) (GatewayConfigData, error) {
	var data GatewayConfigData

	if err := r.db.WithContext(ctx).First(&data.Gateway, "id = ?", gatewayID).Error; err != nil {
		return GatewayConfigData{}, mapErr(err)
	}

	if err := r.db.WithContext(ctx).
		Where("gateway_id = ?", gatewayID).
		Find(&data.Resources).Error; err != nil {
		return GatewayConfigData{}, err
	}

	if err := r.db.WithContext(ctx).
		Preload("Client").
		Preload("Resource").
		Joins("JOIN resources ON resources.id = pairs.resource_id").
		Where("resources.gateway_id = ?", gatewayID).
		Find(&data.Pairs).Error; err != nil {
		return GatewayConfigData{}, err
	}

	// Check if there are observe mode resources - if so, fetch all clients
	hasObserve := false
	for _, res := range data.Resources {
		if res.Mode == "observe" {
			hasObserve = true
			break
		}
	}
	if hasObserve {
		if err := r.db.WithContext(ctx).Find(&data.Clients).Error; err != nil {
			return GatewayConfigData{}, err
		}
	}

	return data, nil
}
