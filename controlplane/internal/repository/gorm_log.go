package repository

import (
	"context"

	"migration-to-zero-trust/controlplane/internal/model"
)

func (r *GormRepository) CreateLog(ctx context.Context, entry *model.LogEntry) error {
	return r.db.WithContext(ctx).Create(entry).Error
}

func (r *GormRepository) ListLogsByGateway(ctx context.Context, gatewayID string, limit int) ([]LogEntryWithPair, error) {
	var out []LogEntryWithPair
	query := r.db.WithContext(ctx).
		Table("logs").
		Select("logs.*, (pairs.id IS NOT NULL) as has_pair").
		Joins("LEFT JOIN pairs ON logs.client_id = pairs.client_id AND logs.resource_id = pairs.resource_id").
		Where("logs.gateway_id = ?", gatewayID).
		Order("logs.timestamp DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if err := query.Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) ListLogsByGatewayAndResourceID(ctx context.Context, gatewayID, resourceID string, limit int) ([]LogEntryWithPair, error) {
	var out []LogEntryWithPair
	query := r.db.WithContext(ctx).
		Table("logs").
		Select("logs.*, (pairs.id IS NOT NULL) as has_pair").
		Joins("LEFT JOIN pairs ON logs.client_id = pairs.client_id AND logs.resource_id = pairs.resource_id").
		Where("logs.gateway_id = ? AND logs.resource_id = ?", gatewayID, resourceID).
		Order("logs.timestamp DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if err := query.Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}
