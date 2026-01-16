package repository

import (
	"context"
	"errors"

	"migration-to-zero-trust/controlplane/internal/model"
)

var ErrNotFound = errors.New("not found")

type EnforcerConfigData struct {
	Enforcer  model.Enforcer
	Resources []model.Resource
	Pairs     []model.Pair   // with Client preloaded
	Clients   []model.Client // all clients (for observe mode)
}

type ClientConfigData struct {
	Client            model.Client
	Pairs             []model.Pair                 // with Resource and Enforcer preloaded
	EnforcerResources map[string][]model.Resource  // enforcerID -> resources (for observe mode per enforcer)
	Enforcers         map[string]model.Enforcer    // enforcerID -> enforcer (includes observe enforcers without pairs)
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
	Enforcers []model.Enforcer
}

type EnforcerDetailPageData struct {
	Enforcer  model.Enforcer
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

	CreateEnforcer(ctx context.Context, e *model.Enforcer) error
	UpsertEnforcer(ctx context.Context, e *model.Enforcer) error
	ListEnforcers(ctx context.Context) ([]model.Enforcer, error)
	GetEnforcer(ctx context.Context, id string) (model.Enforcer, error)
	UpdateEnforcerPublicKey(ctx context.Context, id, pubKey string) error
	DeleteEnforcer(ctx context.Context, id string) (bool, error)
	FetchEnforcerConfigData(ctx context.Context, enforcerID string) (EnforcerConfigData, error)

	CreatePair(ctx context.Context, p *model.Pair) error
	ListPairs(ctx context.Context) ([]model.Pair, error)
	ListPairsByClient(ctx context.Context, clientID string) ([]model.Pair, error)
	ListPairsByEnforcer(ctx context.Context, enforcerID string) ([]model.Pair, error)
	DeletePair(ctx context.Context, id string) (bool, error)

	CreateLog(ctx context.Context, entry *model.LogEntry) error
	ListLogsByEnforcer(ctx context.Context, enforcerID string, limit int) ([]LogEntryWithPair, error)
	ListLogsByEnforcerAndResourceID(ctx context.Context, enforcerID, resourceID string, limit int) ([]LogEntryWithPair, error)

	// UI page data
	FetchPairsPageData(ctx context.Context) (PairsPageData, error)
	FetchResourcesPageData(ctx context.Context) (ResourcesPageData, error)
	FetchEnforcerDetailPageData(ctx context.Context, enforcerID, resourceID string, logLimit int) (EnforcerDetailPageData, error)
}
