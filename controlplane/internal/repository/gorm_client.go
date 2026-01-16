package repository

import (
	"context"

	"migration-to-zero-trust/controlplane/internal/model"
)

func (r *GormRepository) CreateClient(ctx context.Context, c *model.Client) error {
	return r.db.WithContext(ctx).Create(c).Error
}

func (r *GormRepository) ListClients(ctx context.Context) ([]model.Client, error) {
	var out []model.Client
	if err := r.db.WithContext(ctx).Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) GetClient(ctx context.Context, id string) (model.Client, error) {
	var c model.Client
	if err := r.db.WithContext(ctx).First(&c, "id = ?", id).Error; err != nil {
		return model.Client{}, mapErr(err)
	}
	return c, nil
}

func (r *GormRepository) GetClientByUsername(ctx context.Context, username string) (model.Client, error) {
	var c model.Client
	if err := r.db.WithContext(ctx).First(&c, "username = ?", username).Error; err != nil {
		return model.Client{}, mapErr(err)
	}
	return c, nil
}

func (r *GormRepository) DeleteClient(ctx context.Context, id string) (bool, error) {
	res := r.db.WithContext(ctx).Delete(&model.Client{}, "id = ?", id)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (r *GormRepository) FetchClientConfigData(ctx context.Context, clientID string) (ClientConfigData, error) {
	var data ClientConfigData

	if err := r.db.WithContext(ctx).First(&data.Client, "id = ?", clientID).Error; err != nil {
		return ClientConfigData{}, mapErr(err)
	}

	if err := r.db.WithContext(ctx).
		Preload("Resource").
		Preload("Resource.Enforcer").
		Where("client_id = ?", clientID).
		Find(&data.Pairs).Error; err != nil {
		return ClientConfigData{}, err
	}

	// Collect enforcer IDs from pairs (for enforce mode)
	enforcerIDs := make(map[string]struct{})
	for _, p := range data.Pairs {
		enforcerIDs[p.Resource.EnforcerID] = struct{}{}
	}

	// Also collect enforcers that have observe mode resources
	var observeResources []model.Resource
	if err := r.db.WithContext(ctx).
		Preload("Enforcer").
		Where("mode = ?", model.ModeObserve).
		Find(&observeResources).Error; err != nil {
		return ClientConfigData{}, err
	}
	for _, res := range observeResources {
		enforcerIDs[res.EnforcerID] = struct{}{}
	}

	// Fetch all resources for each enforcer
	data.EnforcerResources = make(map[string][]model.Resource)
	data.Enforcers = make(map[string]model.Enforcer)
	for enforcerID := range enforcerIDs {
		var resources []model.Resource
		if err := r.db.WithContext(ctx).
			Preload("Enforcer").
			Where("enforcer_id = ?", enforcerID).
			Find(&resources).Error; err != nil {
			return ClientConfigData{}, err
		}
		data.EnforcerResources[enforcerID] = resources
		if len(resources) > 0 {
			data.Enforcers[enforcerID] = resources[0].Enforcer
		}
	}

	return data, nil
}
