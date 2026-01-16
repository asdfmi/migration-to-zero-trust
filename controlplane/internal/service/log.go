package service

import (
	"context"
	"time"

	"migration-to-zero-trust/controlplane/internal/model"
	"migration-to-zero-trust/controlplane/internal/repository"
)

func CreateLog(ctx context.Context, repo repository.Repository, enforcerID, clientID, clientName, resourceID, resourceName, srcIP, dstIP, protocol string, srcPort, dstPort int, timestamp time.Time) error {
	entry := model.NewLogEntry(enforcerID, clientID, clientName, resourceID, resourceName, srcIP, dstIP, protocol, srcPort, dstPort, timestamp)
	return repo.CreateLog(ctx, &entry)
}
