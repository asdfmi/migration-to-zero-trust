package repository

import (
	"context"

	"migration-to-zero-trust/controlplane/internal/model"
)

func (r *GormRepository) CreateResource(ctx context.Context, resrc *model.Resource) error {
	return r.db.WithContext(ctx).Create(resrc).Error
}

func (r *GormRepository) ListResources(ctx context.Context) ([]model.Resource, error) {
	var out []model.Resource
	if err := r.db.WithContext(ctx).Preload("Enforcer").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) GetResource(ctx context.Context, id string) (model.Resource, error) {
	var res model.Resource
	if err := r.db.WithContext(ctx).First(&res, "id = ?", id).Error; err != nil {
		return model.Resource{}, mapErr(err)
	}
	return res, nil
}

func (r *GormRepository) UpdateResourceMode(ctx context.Context, id, mode string) error {
	res := r.db.WithContext(ctx).Model(&model.Resource{}).Where("id = ?", id).Update("mode", mode)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *GormRepository) DeleteResource(ctx context.Context, id string) (bool, error) {
	res := r.db.WithContext(ctx).Delete(&model.Resource{}, "id = ?", id)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}
