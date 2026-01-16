package model

import "github.com/google/uuid"

type Pair struct {
	ID         string   `gorm:"primaryKey" json:"id"`
	ClientID   string   `gorm:"not null;uniqueIndex:idx_pair_client_resource" json:"client_id"`
	ResourceID string   `gorm:"not null;uniqueIndex:idx_pair_client_resource" json:"resource_id"`
	Client     Client   `gorm:"constraint:OnDelete:CASCADE;foreignKey:ClientID" json:"client,omitempty"`
	Resource   Resource `gorm:"constraint:OnDelete:CASCADE;foreignKey:ResourceID" json:"resource,omitempty"`
}

func NewPair(clientID, resourceID string) Pair {
	return Pair{
		ID:         uuid.NewString(),
		ClientID:   clientID,
		ResourceID: resourceID,
	}
}
