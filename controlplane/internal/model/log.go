package model

import (
	"time"

	"github.com/google/uuid"
)

type LogEntry struct {
	ID           string    `gorm:"primaryKey" json:"id"`
	EnforcerID   string    `gorm:"column:enforcer_id;index" json:"enforcer_id"`
	ClientID     string    `gorm:"column:client_id;index" json:"client_id"`
	ClientName   string    `gorm:"column:client_name" json:"client_name"`
	ResourceID   string    `gorm:"column:resource_id;index" json:"resource_id"`
	ResourceName string    `gorm:"column:resource_name" json:"resource_name"`
	SrcIP        string    `gorm:"column:src_ip;index" json:"src_ip"`
	DstIP        string    `gorm:"column:dst_ip;index" json:"dst_ip"`
	Protocol     string    `gorm:"column:protocol" json:"protocol"`
	SrcPort      int       `gorm:"column:src_port" json:"src_port"`
	DstPort      int       `gorm:"column:dst_port" json:"dst_port"`
	Timestamp    time.Time `gorm:"column:timestamp;index" json:"timestamp"`
}

func NewLogEntry(enforcerID, clientID, clientName, resourceID, resourceName, srcIP, dstIP, protocol string, srcPort, dstPort int, timestamp time.Time) LogEntry {
	return LogEntry{
		ID:           uuid.NewString(),
		EnforcerID:   enforcerID,
		ClientID:     clientID,
		ClientName:   clientName,
		ResourceID:   resourceID,
		ResourceName: resourceName,
		SrcIP:        srcIP,
		DstIP:        dstIP,
		Protocol:     protocol,
		SrcPort:      srcPort,
		DstPort:      dstPort,
		Timestamp:    timestamp,
	}
}

func (LogEntry) TableName() string {
	return "logs"
}
