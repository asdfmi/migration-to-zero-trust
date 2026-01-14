package repository

import (
	"context"
	"errors"

	"migration-to-zero-trust/control-plane/internal/model"
)

var ErrNotFound = errors.New("not found")

type Repository interface {
	WithTx(ctx context.Context, fn func(repo Repository) error) error

	CreateClient(ctx context.Context, c *model.Client) error
	ListClients(ctx context.Context) ([]model.Client, error)
	GetClient(ctx context.Context, id string) (model.Client, error)
	GetClientByUsername(ctx context.Context, username string) (model.Client, error)
	DeleteClient(ctx context.Context, id string) (bool, error)

	CreateResource(ctx context.Context, r *model.Resource) error
	ListResources(ctx context.Context) ([]model.Resource, error)
	ListResourcesByGateway(ctx context.Context, gatewayID string) ([]model.Resource, error)
	GetResource(ctx context.Context, id string) (model.Resource, error)
	UpdateResourceMode(ctx context.Context, id, mode string) error
	DeleteResource(ctx context.Context, id string) (bool, error)

	CreateGateway(ctx context.Context, g *model.Gateway) error
	UpsertGateway(ctx context.Context, g *model.Gateway) error
	ListGateways(ctx context.Context) ([]model.Gateway, error)
	GetGateway(ctx context.Context, id string) (model.Gateway, error)
	GetGatewayByAPIKey(ctx context.Context, apiKey string) (model.Gateway, error)
	UpdateGatewayPublicKey(ctx context.Context, id, pubKey string) error
	DeleteGateway(ctx context.Context, id string) (bool, error)

	CreatePair(ctx context.Context, p *model.Pair) error
	ListPairs(ctx context.Context) ([]model.Pair, error)
	ListPairsByClient(ctx context.Context, clientID string) ([]model.Pair, error)
	ListPairsByGateway(ctx context.Context, gatewayID string) ([]model.Pair, error)
	DeletePair(ctx context.Context, id string) (bool, error)

	CreateLog(ctx context.Context, entry *model.LogEntry) error
	ListLogsByGateway(ctx context.Context, gatewayID string, limit int) ([]model.LogEntry, error)
	ListLogsByGatewayAndDstIP(ctx context.Context, gatewayID, dstIPPrefix string, limit int) ([]model.LogEntry, error)
	CreateClientSession(ctx context.Context, session *model.ClientSession) error
	GetClientSessionByToken(ctx context.Context, token string) (model.ClientSession, error)
	ListActiveSessions(ctx context.Context) ([]model.ClientSession, error)

	UpdateClientPublicKey(ctx context.Context, clientID, pubKey string) error
}
