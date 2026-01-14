package model

import "time"

type Client struct {
	ID           string `gorm:"primaryKey" json:"id"`
	Name         string `gorm:"not null" json:"name"`
	Username     string `gorm:"uniqueIndex" json:"username"`
	WGPublicKey  string `gorm:"column:wg_public_key;uniqueIndex" json:"wg_public_key"`
	Password     string `gorm:"-" json:"password,omitempty"`
	PasswordHash string `gorm:"column:password_hash" json:"-"`
}

type Resource struct {
	ID        string  `gorm:"primaryKey" json:"id"`
	Name      string  `gorm:"not null" json:"name"`
	CIDR      string  `gorm:"not null" json:"cidr"`
	Mode      string  `gorm:"not null;default:observe" json:"mode"`
	GatewayID string  `gorm:"column:gateway_id;not null" json:"gateway_id"`
	Gateway   Gateway `gorm:"constraint:OnDelete:CASCADE;foreignKey:GatewayID" json:"gateway,omitempty"`
}

type Gateway struct {
	ID           string `gorm:"primaryKey" json:"id"`
	Name         string `gorm:"uniqueIndex;not null" json:"name"`
	APIKey       string `gorm:"column:api_key;uniqueIndex;not null" json:"api_key,omitempty"`
	WGPublicKey  string `gorm:"column:wg_public_key" json:"wg_public_key"`
	Endpoint     string `gorm:"not null" json:"endpoint"`
	TunnelSubnet string `gorm:"column:tunnel_subnet;not null" json:"tunnel_subnet"`
}

type Pair struct {
	ID         string   `gorm:"primaryKey" json:"id"`
	ClientID   string   `gorm:"not null;uniqueIndex:idx_pair_client_resource" json:"client_id"`
	ResourceID string   `gorm:"not null;uniqueIndex:idx_pair_client_resource" json:"resource_id"`
	Client     Client   `gorm:"constraint:OnDelete:CASCADE;foreignKey:ClientID" json:"client,omitempty"`
	Resource   Resource `gorm:"constraint:OnDelete:CASCADE;foreignKey:ResourceID" json:"resource,omitempty"`
}

type LogEntry struct {
	ID         string    `gorm:"primaryKey" json:"id"`
	GatewayID  string    `gorm:"column:gateway_id;index" json:"gateway_id"`
	ClientID   string    `gorm:"column:client_id;index" json:"client_id"`
	ClientName string    `gorm:"column:client_name" json:"client_name"`
	SrcIP      string    `gorm:"column:src_ip;index" json:"src_ip"`
	DstIP      string    `gorm:"column:dst_ip;index" json:"dst_ip"`
	Protocol   string    `gorm:"column:protocol" json:"protocol"`
	SrcPort    int       `gorm:"column:src_port" json:"src_port"`
	DstPort    int       `gorm:"column:dst_port" json:"dst_port"`
	Timestamp  time.Time `gorm:"column:timestamp;index" json:"timestamp"`
}

func (LogEntry) TableName() string {
	return "logs"
}

type ClientSession struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	ClientID  string    `gorm:"not null;index" json:"client_id"`
	GatewayID string    `gorm:"column:gateway_id;not null" json:"gateway_id"`
	Token     string    `gorm:"uniqueIndex;not null" json:"token"`
	TunnelIP  string    `gorm:"column:tunnel_ip" json:"tunnel_ip"`
	ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
	Client    Client    `gorm:"constraint:OnDelete:CASCADE;foreignKey:ClientID" json:"client,omitempty"`
	Gateway   Gateway   `gorm:"constraint:OnDelete:CASCADE;foreignKey:GatewayID" json:"gateway,omitempty"`
}

type Policy struct {
	ClientID      string         `json:"client_id"`
	ClientName    string         `json:"client_name"`
	WGPublicKey   string         `json:"wg_public_key"`
	AllowedIPs    []string       `json:"allowed_ips"`
	AllowedCIDRs  []PolicyTarget `json:"allowed_cidrs"`
	ResourceCount int            `json:"resource_count"`
}

type PolicyTarget struct {
	CIDR string `json:"cidr"`
	Mode string `json:"mode"`
}

type ClientConfig struct {
	ClientID         string   `json:"client_id"`
	WGPublicKey      string   `json:"wg_public_key"`
	Address          string   `json:"address"`
	GatewayPublicKey string   `json:"gateway_public_key"`
	GatewayEndpoint  string   `json:"gateway_endpoint"`
	AllowedCIDRs     []string `json:"allowed_cidrs"`
}

type GatewayConfig struct {
	GatewayID     string   `json:"gateway_id"`
	TunnelAddress string   `json:"tunnel_address"`
	Policies      []Policy `json:"policies"`
}
