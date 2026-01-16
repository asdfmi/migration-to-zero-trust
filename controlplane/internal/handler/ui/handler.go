package ui

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"

	"migration-to-zero-trust/controlplane/internal/repository"
	"migration-to-zero-trust/controlplane/internal/service"
)

//go:embed templates/*.html
var templatesFS embed.FS

var validate = validator.New()

type Handler struct {
	repo      repository.Repository
	templates *template.Template
}

func NewHandler(repo repository.Repository) (*Handler, error) {
	tmpl, err := template.New("").ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Handler{repo: repo, templates: tmpl}, nil
}

type createClientRequest struct {
	Name        string `validate:"required"`
	Username    string `validate:"required"`
	Password    string `validate:"required"`
	WGPublicKey string `validate:"required"`
}

type createResourceRequest struct {
	Name      string `validate:"required"`
	CIDR      string `validate:"required,cidr"`
	GatewayID string `validate:"required"`
	Mode      string `validate:"required,oneof=observe enforce"`
}

type createGatewayRequest struct {
	Name         string `validate:"required"`
	Endpoint     string `validate:"required"`
	TunnelSubnet string `validate:"required,cidr"`
}

type createPairRequest struct {
	ClientID   string `validate:"required"`
	ResourceID string `validate:"required"`
}

type updateModeRequest struct {
	Mode string `validate:"required,oneof=observe enforce"`
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/pairs", http.StatusFound)
	})
	r.Get("/clients", h.clients)
	r.Post("/clients", h.createClient)
	r.Post("/clients/{id}/delete", h.deleteClient)

	r.Get("/resources", h.resources)
	r.Post("/resources", h.createResource)
	r.Post("/resources/{id}/mode", h.updateResourceMode)
	r.Post("/resources/{id}/delete", h.deleteResource)

	r.Get("/gateways", h.gateways)
	r.Get("/gateways/{id}", h.gatewayDetail)
	r.Post("/gateways", h.createGateway)
	r.Post("/gateways/{id}/delete", h.deleteGateway)

	r.Get("/pairs", h.pairs)
	r.Post("/pairs", h.createPair)
	r.Post("/pairs/{id}/delete", h.deletePair)
	return r
}

func (h *Handler) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func handleForm[T any](w http.ResponseWriter, r *http.Request, req T, action func() error, redirect string) {
	if err := validate.Struct(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := action(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func (h *Handler) clients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.repo.ListClients(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.render(w, "clients.html", clients)
}

func (h *Handler) createClient(w http.ResponseWriter, r *http.Request) {
	req := createClientRequest{
		Name:        r.FormValue("name"),
		Username:    r.FormValue("username"),
		Password:    r.FormValue("password"),
		WGPublicKey: r.FormValue("wg_public_key"),
	}
	handleForm(w, r, req, func() error {
		_, err := service.CreateClient(r.Context(), h.repo, req.Name, req.Username, req.Password, req.WGPublicKey)
		return err
	}, "/clients")
}

func (h *Handler) deleteClient(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.repo.DeleteClient(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/clients", http.StatusSeeOther)
}

func (h *Handler) resources(w http.ResponseWriter, r *http.Request) {
	pageData, err := h.repo.FetchResourcesPageData(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.render(w, "resources.html", pageData)
}

func (h *Handler) createResource(w http.ResponseWriter, r *http.Request) {
	req := createResourceRequest{
		Name:      r.FormValue("name"),
		CIDR:      r.FormValue("cidr"),
		GatewayID: r.FormValue("gateway_id"),
		Mode:      r.FormValue("mode"),
	}
	handleForm(w, r, req, func() error {
		_, err := service.CreateResource(r.Context(), h.repo, req.Name, req.CIDR, req.GatewayID, req.Mode)
		return err
	}, "/resources")
}

func (h *Handler) updateResourceMode(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	req := updateModeRequest{
		Mode: r.FormValue("mode"),
	}
	handleForm(w, r, req, func() error {
		return h.repo.UpdateResourceMode(r.Context(), id, req.Mode)
	}, "/resources")
}

func (h *Handler) deleteResource(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.repo.DeleteResource(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/resources", http.StatusSeeOther)
}

func (h *Handler) gateways(w http.ResponseWriter, r *http.Request) {
	gateways, err := h.repo.ListGateways(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.render(w, "gateways.html", gateways)
}

func (h *Handler) gatewayDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	resourceID := r.URL.Query().Get("resource_id")
	pageData, err := h.repo.FetchGatewayDetailPageData(r.Context(), id, resourceID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	h.render(w, "gateway_detail.html", struct {
		repository.GatewayDetailPageData
		SelectedResourceID string
	}{pageData, resourceID})
}

func (h *Handler) createGateway(w http.ResponseWriter, r *http.Request) {
	req := createGatewayRequest{
		Name:         r.FormValue("name"),
		Endpoint:     r.FormValue("endpoint"),
		TunnelSubnet: r.FormValue("tunnel_subnet"),
	}
	if err := validate.Struct(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	gateway, err := service.CreateGateway(r.Context(), h.repo, req.Name, req.Endpoint, req.TunnelSubnet)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.render(w, "gateway_created.html", map[string]any{"Gateway": gateway})
}

func (h *Handler) deleteGateway(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.repo.DeleteGateway(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/gateways", http.StatusSeeOther)
}

func (h *Handler) pairs(w http.ResponseWriter, r *http.Request) {
	pageData, err := h.repo.FetchPairsPageData(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.render(w, "pairs.html", pageData)
}

func (h *Handler) createPair(w http.ResponseWriter, r *http.Request) {
	req := createPairRequest{
		ClientID:   r.FormValue("client_id"),
		ResourceID: r.FormValue("resource_id"),
	}
	handleForm(w, r, req, func() error {
		_, err := service.CreatePair(r.Context(), h.repo, req.ClientID, req.ResourceID)
		return err
	}, "/pairs")
}

func (h *Handler) deletePair(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.repo.DeletePair(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/pairs", http.StatusSeeOther)
}
