package repository

import (
	"context"
	"errors"
	"time"

	"migration-to-zero-trust/control-plane/internal/model"

	"gorm.io/gorm"
)

type GormRepository struct {
	db *gorm.DB
}

func NewGormRepository(db *gorm.DB) *GormRepository {
	return &GormRepository{db: db}
}

func (r *GormRepository) WithTx(ctx context.Context, fn func(repo Repository) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(&GormRepository{db: tx})
	})
}

func (r *GormRepository) CreateClient(ctx context.Context, c *model.Client) error {
	return r.db.WithContext(ctx).Create(c).Error
}

func (r *GormRepository) ListClients(ctx context.Context) ([]model.Client, error) {
	var out []model.Client
	if err := r.db.WithContext(ctx).Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) GetClient(ctx context.Context, id string) (model.Client, error) {
	var c model.Client
	if err := r.db.WithContext(ctx).First(&c, "id = ?", id).Error; err != nil {
		return model.Client{}, mapErr(err)
	}
	return c, nil
}

func (r *GormRepository) GetClientByUsername(ctx context.Context, username string) (model.Client, error) {
	var c model.Client
	if err := r.db.WithContext(ctx).First(&c, "username = ?", username).Error; err != nil {
		return model.Client{}, mapErr(err)
	}
	return c, nil
}

func (r *GormRepository) DeleteClient(ctx context.Context, id string) (bool, error) {
	res := r.db.WithContext(ctx).Delete(&model.Client{}, "id = ?", id)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (r *GormRepository) CreateResource(ctx context.Context, resrc *model.Resource) error {
	return r.db.WithContext(ctx).Create(resrc).Error
}

func (r *GormRepository) ListResources(ctx context.Context) ([]model.Resource, error) {
	var out []model.Resource
	if err := r.db.WithContext(ctx).Preload("Gateway").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) ListResourcesByGateway(ctx context.Context, gatewayID string) ([]model.Resource, error) {
	var out []model.Resource
	if err := r.db.WithContext(ctx).Where("gateway_id = ?", gatewayID).Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) GetResource(ctx context.Context, id string) (model.Resource, error) {
	var res model.Resource
	if err := r.db.WithContext(ctx).First(&res, "id = ?", id).Error; err != nil {
		return model.Resource{}, mapErr(err)
	}
	return res, nil
}

func (r *GormRepository) UpdateResourceMode(ctx context.Context, id, mode string) error {
	res := r.db.WithContext(ctx).Model(&model.Resource{}).Where("id = ?", id).Update("mode", mode)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *GormRepository) DeleteResource(ctx context.Context, id string) (bool, error) {
	res := r.db.WithContext(ctx).Delete(&model.Resource{}, "id = ?", id)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (r *GormRepository) CreateGateway(ctx context.Context, g *model.Gateway) error {
	return r.db.WithContext(ctx).Create(g).Error
}

func (r *GormRepository) UpsertGateway(ctx context.Context, g *model.Gateway) error {
	return r.db.WithContext(ctx).Save(g).Error
}

func (r *GormRepository) ListGateways(ctx context.Context) ([]model.Gateway, error) {
	var out []model.Gateway
	if err := r.db.WithContext(ctx).Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) GetGateway(ctx context.Context, id string) (model.Gateway, error) {
	var g model.Gateway
	if err := r.db.WithContext(ctx).First(&g, "id = ?", id).Error; err != nil {
		return model.Gateway{}, mapErr(err)
	}
	return g, nil
}

func (r *GormRepository) GetGatewayByAPIKey(ctx context.Context, apiKey string) (model.Gateway, error) {
	var g model.Gateway
	if err := r.db.WithContext(ctx).First(&g, "api_key = ?", apiKey).Error; err != nil {
		return model.Gateway{}, mapErr(err)
	}
	return g, nil
}

func (r *GormRepository) UpdateGatewayPublicKey(ctx context.Context, id, pubKey string) error {
	return r.db.WithContext(ctx).Model(&model.Gateway{}).Where("id = ?", id).
		Update("wg_public_key", pubKey).Error
}

func (r *GormRepository) DeleteGateway(ctx context.Context, id string) (bool, error) {
	res := r.db.WithContext(ctx).Delete(&model.Gateway{}, "id = ?", id)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (r *GormRepository) CreatePair(ctx context.Context, p *model.Pair) error {
	return r.db.WithContext(ctx).Create(p).Error
}

func (r *GormRepository) ListPairs(ctx context.Context) ([]model.Pair, error) {
	var out []model.Pair
	if err := r.db.WithContext(ctx).
		Preload("Client").
		Preload("Resource").
		Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) ListPairsByClient(ctx context.Context, clientID string) ([]model.Pair, error) {
	var out []model.Pair
	if err := r.db.WithContext(ctx).
		Preload("Resource").
		Preload("Resource.Gateway").
		Where("client_id = ?", clientID).
		Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) ListPairsByGateway(ctx context.Context, gatewayID string) ([]model.Pair, error) {
	var out []model.Pair
	if err := r.db.WithContext(ctx).
		Preload("Client").
		Preload("Resource").
		Joins("JOIN resources ON resources.id = pairs.resource_id").
		Where("resources.gateway_id = ?", gatewayID).
		Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) DeletePair(ctx context.Context, id string) (bool, error) {
	res := r.db.WithContext(ctx).Delete(&model.Pair{}, "id = ?", id)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (r *GormRepository) CreateLog(ctx context.Context, entry *model.LogEntry) error {
	return r.db.WithContext(ctx).Create(entry).Error
}

func (r *GormRepository) ListLogsByGateway(ctx context.Context, gatewayID string, limit int) ([]model.LogEntry, error) {
	var out []model.LogEntry
	query := r.db.WithContext(ctx).Where("gateway_id = ?", gatewayID).Order("timestamp DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if err := query.Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) ListLogsByGatewayAndDstIP(ctx context.Context, gatewayID, dstIPPrefix string, limit int) ([]model.LogEntry, error) {
	var out []model.LogEntry
	query := r.db.WithContext(ctx).Where("gateway_id = ? AND dst_ip LIKE ?", gatewayID, dstIPPrefix+"%").Order("timestamp DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if err := query.Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *GormRepository) CreateClientSession(ctx context.Context, session *model.ClientSession) error {
	return r.db.WithContext(ctx).Create(session).Error
}

func (r *GormRepository) GetClientSessionByToken(ctx context.Context, token string) (model.ClientSession, error) {
	var session model.ClientSession
	if err := r.db.WithContext(ctx).First(&session, "token = ?", token).Error; err != nil {
		return model.ClientSession{}, mapErr(err)
	}
	return session, nil
}

func (r *GormRepository) UpdateClientPublicKey(ctx context.Context, clientID, pubKey string) error {
	return r.db.WithContext(ctx).Model(&model.Client{}).Where("id = ?", clientID).
		Update("wg_public_key", pubKey).Error
}

func (r *GormRepository) ListActiveSessions(ctx context.Context) ([]model.ClientSession, error) {
	var sessions []model.ClientSession
	if err := r.db.WithContext(ctx).Preload("Client").Where("expires_at > ?", time.Now()).Find(&sessions).Error; err != nil {
		return nil, mapErr(err)
	}
	return sessions, nil
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}
