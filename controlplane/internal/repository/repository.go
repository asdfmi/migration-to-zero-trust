package repository

import (
	"context"
	"errors"

	"migration-to-zero-trust/controlplane/internal/model"
)

var ErrNotFound = errors.New("not found")

type GatewayConfigData struct {
	Gateway   model.Gateway
	Resources []model.Resource
	Pairs     []model.Pair    // with Client preloaded
	Clients   []model.Client  // all clients (for observe mode)
}

type ClientConfigData struct {
	Client           model.Client
	Pairs            []model.Pair                // with Resource and Gateway preloaded
	GatewayResources map[string][]model.Resource // gatewayID -> resources (for observe mode per gateway)
	Gateways         map[string]model.Gateway    // gatewayID -> gateway (includes observe gateways without pairs)
}

type LogEntryWithPair struct {
	model.LogEntry
	HasPair bool `gorm:"column:has_pair"`
}

// UI page data structs
type PairsPageData struct {
	Pairs     []model.Pair
	Clients   []model.Client
	Resources []model.Resource
}

type ResourcesPageData struct {
	Resources []model.Resource
	Gateways  []model.Gateway
}

type GatewayDetailPageData struct {
	Gateway   model.Gateway
	Resources []model.Resource
	Logs      []LogEntryWithPair
}

type Repository interface {
	WithTx(ctx context.Context, fn func(repo Repository) error) error

	CreateClient(ctx context.Context, c *model.Client) error
	ListClients(ctx context.Context) ([]model.Client, error)
	GetClient(ctx context.Context, id string) (model.Client, error)
	GetClientByUsername(ctx context.Context, username string) (model.Client, error)
	DeleteClient(ctx context.Context, id string) (bool, error)
	FetchClientConfigData(ctx context.Context, clientID string) (ClientConfigData, error)

	CreateResource(ctx context.Context, r *model.Resource) error
	ListResources(ctx context.Context) ([]model.Resource, error)
	GetResource(ctx context.Context, id string) (model.Resource, error)
	UpdateResourceMode(ctx context.Context, id, mode string) error
	DeleteResource(ctx context.Context, id string) (bool, error)

	CreateGateway(ctx context.Context, g *model.Gateway) error
	UpsertGateway(ctx context.Context, g *model.Gateway) error
	ListGateways(ctx context.Context) ([]model.Gateway, error)
	GetGateway(ctx context.Context, id string) (model.Gateway, error)
	UpdateGatewayPublicKey(ctx context.Context, id, pubKey string) error
	DeleteGateway(ctx context.Context, id string) (bool, error)
	FetchGatewayConfigData(ctx context.Context, gatewayID string) (GatewayConfigData, error)

	CreatePair(ctx context.Context, p *model.Pair) error
	ListPairs(ctx context.Context) ([]model.Pair, error)
	ListPairsByClient(ctx context.Context, clientID string) ([]model.Pair, error)
	ListPairsByGateway(ctx context.Context, gatewayID string) ([]model.Pair, error)
	DeletePair(ctx context.Context, id string) (bool, error)

	CreateLog(ctx context.Context, entry *model.LogEntry) error
	ListLogsByGateway(ctx context.Context, gatewayID string, limit int) ([]LogEntryWithPair, error)
	ListLogsByGatewayAndResourceID(ctx context.Context, gatewayID, resourceID string, limit int) ([]LogEntryWithPair, error)

	// UI page data
	FetchPairsPageData(ctx context.Context) (PairsPageData, error)
	FetchResourcesPageData(ctx context.Context) (ResourcesPageData, error)
	FetchGatewayDetailPageData(ctx context.Context, gatewayID, resourceID string, logLimit int) (GatewayDetailPageData, error)
}
