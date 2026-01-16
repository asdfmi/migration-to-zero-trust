package repository

import (
	"context"

	"gorm.io/gorm"
)

func (r *GormRepository) FetchPairsPageData(ctx context.Context) (PairsPageData, error) {
	var data PairsPageData
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Preload("Client").Preload("Resource").Find(&data.Pairs).Error; err != nil {
			return err
		}
		if err := tx.Find(&data.Clients).Error; err != nil {
			return err
		}
		if err := tx.Preload("Enforcer").Find(&data.Resources).Error; err != nil {
			return err
		}
		return nil
	})
	return data, err
}

func (r *GormRepository) FetchResourcesPageData(ctx context.Context) (ResourcesPageData, error) {
	var data ResourcesPageData
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Preload("Enforcer").Find(&data.Resources).Error; err != nil {
			return err
		}
		if err := tx.Find(&data.Enforcers).Error; err != nil {
			return err
		}
		return nil
	})
	return data, err
}

func (r *GormRepository) FetchEnforcerDetailPageData(ctx context.Context, enforcerID, resourceID string, logLimit int) (EnforcerDetailPageData, error) {
	var data EnforcerDetailPageData
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&data.Enforcer, "id = ?", enforcerID).Error; err != nil {
			return mapErr(err)
		}
		if err := tx.Where("enforcer_id = ?", enforcerID).Find(&data.Resources).Error; err != nil {
			return err
		}
		query := tx.Table("logs").
			Select("logs.*, (pairs.id IS NOT NULL) as has_pair").
			Joins("LEFT JOIN pairs ON logs.client_id = pairs.client_id AND logs.resource_id = pairs.resource_id").
			Where("logs.enforcer_id = ?", enforcerID).
			Order("logs.timestamp DESC")
		if resourceID != "" {
			query = query.Where("logs.resource_id = ?", resourceID)
		}
		if logLimit > 0 {
			query = query.Limit(logLimit)
		}
		if err := query.Find(&data.Logs).Error; err != nil {
			return err
		}
		return nil
	})
	return data, err
}
