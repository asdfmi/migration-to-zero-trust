package ui

import (
	"embed"
	"html/template"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"migration-to-zero-trust/control-plane/internal/model"
	"migration-to-zero-trust/control-plane/internal/service"
)

//go:embed templates/*.html
var templatesFS embed.FS

type Handler struct {
	svc       *service.Service
	templates *template.Template
}

func NewHandler(svc *service.Service) (*Handler, error) {
	tmpl, err := template.New("").ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Handler{svc: svc, templates: tmpl}, nil
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

func (h *Handler) clients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.svc.ListClients(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := struct {
		Title   string
		Clients []model.Client
	}{
		Title:   "Clients",
		Clients: clients,
	}
	h.render(w, "clients.html", data)
}

func (h *Handler) createClient(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := strings.TrimSpace(r.FormValue("password"))
	if _, err := h.svc.CreateClient(r.Context(), name, username, password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/clients", http.StatusSeeOther)
}

func (h *Handler) deleteClient(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.svc.DeleteClient(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/clients", http.StatusSeeOther)
}

func (h *Handler) resources(w http.ResponseWriter, r *http.Request) {
	resources, err := h.svc.ListResources(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	gateways, err := h.svc.ListGateways(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := struct {
		Title     string
		Resources []model.Resource
		Gateways  []model.Gateway
	}{
		Title:     "Protected Resources",
		Resources: resources,
		Gateways:  gateways,
	}
	h.render(w, "resources.html", data)
}

func (h *Handler) createResource(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	cidr := strings.TrimSpace(r.FormValue("cidr"))
	gatewayID := strings.TrimSpace(r.FormValue("gateway_id"))
	mode := strings.TrimSpace(r.FormValue("mode"))
	if _, err := h.svc.CreateResource(r.Context(), name, cidr, gatewayID, mode); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/resources", http.StatusSeeOther)
}

func (h *Handler) updateResourceMode(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	mode := strings.TrimSpace(r.FormValue("mode"))
	if err := h.svc.UpdateResourceMode(r.Context(), id, mode); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/resources", http.StatusSeeOther)
}

func (h *Handler) deleteResource(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.svc.DeleteResource(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/resources", http.StatusSeeOther)
}

func (h *Handler) gateways(w http.ResponseWriter, r *http.Request) {
	gateways, err := h.svc.ListGateways(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := struct {
		Title    string
		Gateways []model.Gateway
	}{
		Title:    "Gateways",
		Gateways: gateways,
	}
	h.render(w, "gateways.html", data)
}

func (h *Handler) gatewayDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	gateway, err := h.svc.GetGateway(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	resources, err := h.svc.ListResourcesByGateway(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resourceID := r.URL.Query().Get("resource_id")
	logs, err := h.svc.ListLogsByGateway(r.Context(), id, resourceID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := struct {
		Title              string
		Gateway            model.Gateway
		Resources          []model.Resource
		Logs               []model.LogEntry
		SelectedResourceID string
	}{
		Title:              "Gateway: " + gateway.Name,
		Gateway:            gateway,
		Resources:          resources,
		Logs:               logs,
		SelectedResourceID: resourceID,
	}
	h.render(w, "gateway_detail.html", data)
}

func (h *Handler) createGateway(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	endpoint := strings.TrimSpace(r.FormValue("endpoint"))
	tunnelSubnet := strings.TrimSpace(r.FormValue("tunnel_subnet"))
	if _, err := h.svc.CreateGateway(r.Context(), name, endpoint, tunnelSubnet); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/gateways", http.StatusSeeOther)
}

func (h *Handler) deleteGateway(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.svc.DeleteGateway(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/gateways", http.StatusSeeOther)
}

func (h *Handler) pairs(w http.ResponseWriter, r *http.Request) {
	pairs, err := h.svc.ListPairs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	clients, err := h.svc.ListClients(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resources, err := h.svc.ListResources(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := struct {
		Title     string
		Pairs     []model.Pair
		Clients   []model.Client
		Resources []model.Resource
	}{
		Title:     "Client/Resource Pairs",
		Pairs:     pairs,
		Clients:   clients,
		Resources: resources,
	}
	h.render(w, "pairs.html", data)
}

func (h *Handler) createPair(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	resourceID := strings.TrimSpace(r.FormValue("resource_id"))
	if _, err := h.svc.CreatePair(r.Context(), clientID, resourceID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/pairs", http.StatusSeeOther)
}

func (h *Handler) deletePair(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.svc.DeletePair(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/pairs", http.StatusSeeOther)
}
