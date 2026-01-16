package api

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"

	"migration-to-zero-trust/controlplane/internal/middleware"
	"migration-to-zero-trust/controlplane/internal/repository"
	"migration-to-zero-trust/controlplane/internal/service"
)

type Handler struct {
	repo repository.Repository
}

func NewHandler(repo repository.Repository) *Handler {
	return &Handler{repo: repo}
}

// --- Request/Response types ---

type LoginInput struct {
	Body struct {
		Username string `json:"username" required:"true"`
		Password string `json:"password" required:"true"`
	}
}

type LoginOutput struct {
	Body struct {
		Token string `json:"token"`
	}
}

type ClientConfigOutput struct {
	Body service.ClientConfig
}

type UpdateKeyInput struct {
	Body struct {
		WGPublicKey string `json:"wg_public_key" required:"true"`
	}
}

type StatusOutput struct {
	Body struct {
		Status string `json:"status"`
	}
}

type LogEntry struct {
	Timestamp    time.Time `json:"ts" required:"true"`
	SrcIP        string    `json:"src_ip" required:"true"`
	SrcPort      int       `json:"src_port"`
	DstIP        string    `json:"dst_ip" required:"true"`
	DstPort      int       `json:"dst_port"`
	Protocol     string    `json:"proto" required:"true"`
	ClientID     string    `json:"client_id"`
	ClientName   string    `json:"client_name"`
	ResourceID   string    `json:"resource_id"`
	ResourceName string    `json:"resource_name"`
	Length       int       `json:"length"`
}

type IngestLogsInput struct {
	Body []LogEntry
}

type GatewayConfigOutput struct {
	Body service.GatewayConfig
}

// --- Register routes ---

func (h *Handler) RegisterRoutes(r chi.Router) {
	// Public endpoint
	r.Group(func(r chi.Router) {
		api := humachi.New(r, huma.DefaultConfig("Zero Trust API", "1.0.0"))
		huma.Register(api, huma.Operation{
			OperationID: "client-login",
			Method:      http.MethodPost,
			Path:        "/api/client/login",
			Summary:     "Client login",
		}, h.clientLogin)
	})

	// Client auth endpoints
	r.Group(func(r chi.Router) {
		r.Use(middleware.ClientTokenAuth)
		api := humachi.New(r, huma.DefaultConfig("Zero Trust API", "1.0.0"))
		huma.Register(api, huma.Operation{
			OperationID: "client-config",
			Method:      http.MethodGet,
			Path:        "/api/client/config",
			Summary:     "Get client configuration",
		}, h.clientConfig)
	})

	// Gateway auth endpoints
	r.Group(func(r chi.Router) {
		r.Use(middleware.GatewayAPIKey(h.repo))
		api := humachi.New(r, huma.DefaultConfig("Zero Trust API", "1.0.0"))
		huma.Register(api, huma.Operation{
			OperationID: "gateway-config",
			Method:      http.MethodGet,
			Path:        "/api/gateway/config",
			Summary:     "Get gateway configuration",
		}, h.gatewayConfig)
		huma.Register(api, huma.Operation{
			OperationID: "update-gateway-key",
			Method:      http.MethodPut,
			Path:        "/api/gateway/public-key",
			Summary:     "Update gateway public key",
		}, h.updateGatewayKey)
		huma.Register(api, huma.Operation{
			OperationID: "ingest-logs",
			Method:      http.MethodPost,
			Path:        "/api/logs",
			Summary:     "Ingest logs from gateway",
		}, h.ingestLogs)
	})
}

// --- Handlers ---

func (h *Handler) clientLogin(ctx context.Context, input *LoginInput) (*LoginOutput, error) {
	token, err := service.ClientLogin(ctx, h.repo, input.Body.Username, input.Body.Password)
	if err != nil {
		return nil, toHumaError(err)
	}
	resp := &LoginOutput{}
	resp.Body.Token = token
	return resp, nil
}

func (h *Handler) clientConfig(ctx context.Context, input *struct{}) (*ClientConfigOutput, error) {
	claims, ok := service.ClaimsFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("unauthorized")
	}
	cfg, err := service.GetClientConfig(ctx, h.repo, claims)
	if err != nil {
		return nil, toHumaError(err)
	}
	return &ClientConfigOutput{Body: cfg}, nil
}

func (h *Handler) gatewayConfig(ctx context.Context, input *struct{}) (*GatewayConfigOutput, error) {
	gateway, ok := middleware.GatewayFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("unauthorized")
	}
	cfg, err := service.GetGatewayConfig(ctx, h.repo, gateway.ID)
	if err != nil {
		return nil, toHumaError(err)
	}
	return &GatewayConfigOutput{Body: cfg}, nil
}

func (h *Handler) updateGatewayKey(ctx context.Context, input *UpdateKeyInput) (*StatusOutput, error) {
	gateway, ok := middleware.GatewayFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("unauthorized")
	}
	if err := service.UpdateGatewayPublicKey(ctx, h.repo, gateway.ID, input.Body.WGPublicKey); err != nil {
		return nil, toHumaError(err)
	}
	resp := &StatusOutput{}
	resp.Body.Status = "ok"
	return resp, nil
}

func (h *Handler) ingestLogs(ctx context.Context, input *IngestLogsInput) (*StatusOutput, error) {
	gateway, ok := middleware.GatewayFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("unauthorized")
	}
	for _, e := range input.Body {
		if err := service.CreateLog(ctx, h.repo, gateway.ID, e.ClientID, e.ClientName, e.ResourceID, e.ResourceName, e.SrcIP, e.DstIP, e.Protocol, e.SrcPort, e.DstPort, e.Timestamp); err != nil {
			return nil, toHumaError(err)
		}
	}
	resp := &StatusOutput{}
	resp.Body.Status = "ok"
	return resp, nil
}

func toHumaError(err error) error {
	if service.IsValidation(err) {
		return huma.Error400BadRequest(err.Error())
	}
	if service.IsNotFound(err) {
		return huma.Error404NotFound("not found")
	}
	if service.IsAuth(err) {
		return huma.Error401Unauthorized("unauthorized")
	}
	return huma.Error500InternalServerError(err.Error())
}
