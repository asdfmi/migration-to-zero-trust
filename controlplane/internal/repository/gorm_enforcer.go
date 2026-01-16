package repository

import (
	"context"

	"migration-to-zero-trust/controlplane/internal/model"
)

func (r *GormRepository) CreateEnforcer(ctx context.Context, e *model.Enforcer) error {
	return r.db.WithContext(ctx).Create(e).Error
}

func (r *GormRepository) UpsertEnforcer(ctx context.Context, e *model.Enforcer) error {
	return r.db.WithContext(ctx).Save(e).Error
}

func (r *GormRepository) ListEnforcers(ctx context.Context) ([]model.Enforcer, error) {
	var out []model.Enforcer
	if err := r.db.WithContext(ctx).Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) GetEnforcer(ctx context.Context, id string) (model.Enforcer, error) {
	var e model.Enforcer
	if err := r.db.WithContext(ctx).First(&e, "id = ?", id).Error; err != nil {
		return model.Enforcer{}, mapErr(err)
	}
	return e, nil
}

func (r *GormRepository) UpdateEnforcerPublicKey(ctx context.Context, id, pubKey string) error {
	return r.db.WithContext(ctx).Model(&model.Enforcer{}).Where("id = ?", id).
		Update("wg_public_key", pubKey).Error
}

func (r *GormRepository) DeleteEnforcer(ctx context.Context, id string) (bool, error) {
	res := r.db.WithContext(ctx).Delete(&model.Enforcer{}, "id = ?", id)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (r *GormRepository) FetchEnforcerConfigData(ctx context.Context, enforcerID string) (EnforcerConfigData, error) {
	var data EnforcerConfigData

	if err := r.db.WithContext(ctx).First(&data.Enforcer, "id = ?", enforcerID).Error; err != nil {
		return EnforcerConfigData{}, mapErr(err)
	}

	if err := r.db.WithContext(ctx).
		Where("enforcer_id = ?", enforcerID).
		Find(&data.Resources).Error; err != nil {
		return EnforcerConfigData{}, err
	}

	if err := r.db.WithContext(ctx).
		Preload("Client").
		Preload("Resource").
		Joins("JOIN resources ON resources.id = pairs.resource_id").
		Where("resources.enforcer_id = ?", enforcerID).
		Find(&data.Pairs).Error; err != nil {
		return EnforcerConfigData{}, err
	}

	// Check if there are observe mode resources - if so, fetch all clients
	hasObserve := false
	for _, res := range data.Resources {
		if res.Mode == model.ModeObserve {
			hasObserve = true
			break
		}
	}
	if hasObserve {
		if err := r.db.WithContext(ctx).Find(&data.Clients).Error; err != nil {
			return EnforcerConfigData{}, err
		}
	}

	return data, nil
}
