package model

import "github.com/google/uuid"

// Resource access modes for Zero Trust migration.
const (
	ModeObserve = "observe" // Log traffic without blocking (migration phase)
	ModeEnforce = "enforce" // Block unauthorized access (post-migration)
)

type Resource struct {
	ID        string  `gorm:"primaryKey" json:"id"`
	Name      string  `gorm:"not null" json:"name"`
	CIDR      string  `gorm:"not null" json:"cidr"`
	Mode      string  `gorm:"not null;default:observe" json:"mode"`
	GatewayID string  `gorm:"column:gateway_id;not null" json:"gateway_id"`
	Gateway   Gateway `gorm:"constraint:OnDelete:CASCADE;foreignKey:GatewayID" json:"gateway,omitempty"`
}

func NewResource(name, cidr, gatewayID, mode string) Resource {
	return Resource{
		ID:        uuid.NewString(),
		Name:      name,
		CIDR:      cidr,
		Mode:      mode,
		GatewayID: gatewayID,
	}
}
