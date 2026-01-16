package repository

import (
	"context"

	"migration-to-zero-trust/controlplane/internal/model"
)

func (r *GormRepository) CreateLog(ctx context.Context, entry *model.LogEntry) error {
	return r.db.WithContext(ctx).Create(entry).Error
}

func (r *GormRepository) ListLogsByEnforcer(ctx context.Context, enforcerID string, limit int) ([]LogEntryWithPair, error) {
	var out []LogEntryWithPair
	query := r.db.WithContext(ctx).
		Table("logs").
		Select("logs.*, (pairs.id IS NOT NULL) as has_pair").
		Joins("LEFT JOIN pairs ON logs.client_id = pairs.client_id AND logs.resource_id = pairs.resource_id").
		Where("logs.enforcer_id = ?", enforcerID).
		Order("logs.timestamp DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if err := query.Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) ListLogsByEnforcerAndResourceID(ctx context.Context, enforcerID, resourceID string, limit int) ([]LogEntryWithPair, error) {
	var out []LogEntryWithPair
	query := r.db.WithContext(ctx).
		Table("logs").
		Select("logs.*, (pairs.id IS NOT NULL) as has_pair").
		Joins("LEFT JOIN pairs ON logs.client_id = pairs.client_id AND logs.resource_id = pairs.resource_id").
		Where("logs.enforcer_id = ? AND logs.resource_id = ?", enforcerID, resourceID).
		Order("logs.timestamp DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if err := query.Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}
