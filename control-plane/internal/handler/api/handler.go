package api

import (
	"encoding/json"
	"net/http"
	"time"

	"migration-to-zero-trust/control-plane/internal/middleware"
	"migration-to-zero-trust/control-plane/internal/service"
)

type Handler struct {
	svc *service.Service
}

func NewHandler(svc *service.Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) GatewayConfig(w http.ResponseWriter, r *http.Request) {
	gateway, ok := middleware.GatewayFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	cfg, err := h.svc.GetGatewayConfig(r.Context(), gateway.ID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (h *Handler) UpdateGatewayPublicKey(w http.ResponseWriter, r *http.Request) {
	gateway, ok := middleware.GatewayFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var input struct {
		WGPublicKey string `json:"wg_public_key"`
	}
	if err := decodeJSON(r, &input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.svc.UpdateGatewayPublicKey(r.Context(), gateway.ID, input.WGPublicKey); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) IngestLogs(w http.ResponseWriter, r *http.Request) {
	gateway, ok := middleware.GatewayFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var entries []struct {
		Timestamp  time.Time `json:"ts"`
		SrcIP      string    `json:"src_ip"`
		SrcPort    int       `json:"src_port"`
		DstIP      string    `json:"dst_ip"`
		DstPort    int       `json:"dst_port"`
		Protocol   string    `json:"proto"`
		ClientID   string    `json:"client_id"`
		ClientName string    `json:"client_name"`
	}
	if err := decodeJSON(r, &entries); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	for _, e := range entries {
		if err := h.svc.CreateLog(r.Context(), gateway.ID, e.ClientID, e.ClientName, e.SrcIP, e.DstIP, e.Protocol, e.SrcPort, e.DstPort, e.Timestamp); err != nil {
			writeServiceError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "ok"})
}

func (h *Handler) ClientLogin(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	session, err := h.svc.ClientLogin(r.Context(), input.Username, input.Password)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	resp := struct {
		ClientID  string `json:"client_id"`
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}{
		ClientID:  session.ClientID,
		Token:     session.Token,
		ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) ClientConfigSelf(w http.ResponseWriter, r *http.Request) {
	session, ok := service.SessionFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	cfg, err := h.svc.GetClientConfig(r.Context(), session)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (h *Handler) ClientUpdateKey(w http.ResponseWriter, r *http.Request) {
	session, ok := service.SessionFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var input struct {
		WGPublicKey string `json:"wg_public_key"`
	}
	if err := decodeJSON(r, &input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.svc.UpdateClientPublicKey(r.Context(), session.ClientID, input.WGPublicKey); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
	}
}

func writeServiceError(w http.ResponseWriter, err error) {
	if service.IsValidation(err) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if service.IsNotFound(err) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if service.IsAuth(err) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
