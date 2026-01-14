package service

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"migration-to-zero-trust/control-plane/internal/model"
	"migration-to-zero-trust/control-plane/internal/repository"
)

type ValidationError struct {
	Msg string
}

func (e ValidationError) Error() string {
	return e.Msg
}

type Service struct {
	repo repository.Repository
}

const clientSessionTTL = 24 * time.Hour

func New(repo repository.Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) CreateClient(ctx context.Context, name, username, password string) (model.Client, error) {
	name = strings.TrimSpace(name)
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if name == "" || username == "" || password == "" {
		return model.Client{}, ValidationError{Msg: "name, username, password are required"}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return model.Client{}, err
	}
	c := model.Client{
		ID:           uuid.NewString(),
		Name:         name,
		Username:     username,
		PasswordHash: string(hash),
	}
	if err := s.repo.CreateClient(ctx, &c); err != nil {
		return model.Client{}, err
	}
	return c, nil
}

func (s *Service) ListClients(ctx context.Context) ([]model.Client, error) {
	return s.repo.ListClients(ctx)
}

func (s *Service) DeleteClient(ctx context.Context, id string) (bool, error) {
	return s.repo.DeleteClient(ctx, strings.TrimSpace(id))
}

func (s *Service) CreateResource(ctx context.Context, name, cidr, gatewayID, mode string) (model.Resource, error) {
	name = strings.TrimSpace(name)
	cidr = strings.TrimSpace(cidr)
	gatewayID = strings.TrimSpace(gatewayID)
	mode = strings.TrimSpace(mode)
	if name == "" || cidr == "" || gatewayID == "" {
		return model.Resource{}, ValidationError{Msg: "name, cidr, gateway_id are required"}
	}
	if !validCIDR(cidr) {
		return model.Resource{}, ValidationError{Msg: "cidr is invalid"}
	}
	if mode == "" {
		mode = "observe"
	}
	if mode != "observe" && mode != "enforce" {
		return model.Resource{}, ValidationError{Msg: "mode must be observe or enforce"}
	}
	// Verify gateway exists
	if _, err := s.repo.GetGateway(ctx, gatewayID); err != nil {
		return model.Resource{}, ValidationError{Msg: "gateway not found"}
	}
	r := model.Resource{
		ID:        uuid.NewString(),
		Name:      name,
		CIDR:      cidr,
		Mode:      mode,
		GatewayID: gatewayID,
	}
	if err := s.repo.CreateResource(ctx, &r); err != nil {
		return model.Resource{}, err
	}
	return r, nil
}

func (s *Service) ListResources(ctx context.Context) ([]model.Resource, error) {
	return s.repo.ListResources(ctx)
}

func (s *Service) ListResourcesByGateway(ctx context.Context, gatewayID string) ([]model.Resource, error) {
	return s.repo.ListResourcesByGateway(ctx, strings.TrimSpace(gatewayID))
}

func (s *Service) DeleteResource(ctx context.Context, id string) (bool, error) {
	return s.repo.DeleteResource(ctx, strings.TrimSpace(id))
}

func (s *Service) UpdateResourceMode(ctx context.Context, id, mode string) error {
	id = strings.TrimSpace(id)
	mode = strings.TrimSpace(mode)
	if mode != "observe" && mode != "enforce" {
		return ValidationError{Msg: "mode must be observe or enforce"}
	}
	return s.repo.UpdateResourceMode(ctx, id, mode)
}

func (s *Service) ListLogsByGateway(ctx context.Context, gatewayID string, resourceID string, limit int) ([]model.LogEntry, error) {
	gatewayID = strings.TrimSpace(gatewayID)
	resourceID = strings.TrimSpace(resourceID)
	if gatewayID == "" {
		return nil, ValidationError{Msg: "gateway_id is required"}
	}
	// If resourceID is provided, filter by destination IP
	if resourceID != "" {
		resource, err := s.repo.GetResource(ctx, resourceID)
		if err != nil {
			return nil, err
		}
		// Extract IP prefix from CIDR (e.g., "10.0.0.2/32" -> "10.0.0.2")
		ip, _, err := net.ParseCIDR(resource.CIDR)
		if err != nil {
			return nil, ValidationError{Msg: "invalid resource CIDR"}
		}
		return s.repo.ListLogsByGatewayAndDstIP(ctx, gatewayID, ip.String(), limit)
	}
	return s.repo.ListLogsByGateway(ctx, gatewayID, limit)
}

func (s *Service) CreateGateway(ctx context.Context, name, endpoint, tunnelSubnet string) (model.Gateway, error) {
	name = strings.TrimSpace(name)
	endpoint = strings.TrimSpace(endpoint)
	tunnelSubnet = strings.TrimSpace(tunnelSubnet)
	if name == "" || endpoint == "" || tunnelSubnet == "" {
		return model.Gateway{}, ValidationError{Msg: "name, endpoint, tunnel_subnet are required"}
	}
	if !validCIDR(tunnelSubnet) {
		return model.Gateway{}, ValidationError{Msg: "tunnel_subnet must be valid CIDR"}
	}
	g := model.Gateway{
		ID:           uuid.NewString(),
		Name:         name,
		APIKey:       "gw_" + uuid.NewString(),
		Endpoint:     endpoint,
		TunnelSubnet: tunnelSubnet,
	}
	if err := s.repo.CreateGateway(ctx, &g); err != nil {
		return model.Gateway{}, err
	}
	return g, nil
}

func (s *Service) ListGateways(ctx context.Context) ([]model.Gateway, error) {
	return s.repo.ListGateways(ctx)
}

func (s *Service) GetGateway(ctx context.Context, id string) (model.Gateway, error) {
	return s.repo.GetGateway(ctx, strings.TrimSpace(id))
}

func (s *Service) DeleteGateway(ctx context.Context, id string) (bool, error) {
	return s.repo.DeleteGateway(ctx, strings.TrimSpace(id))
}

func (s *Service) UpdateGatewayPublicKey(ctx context.Context, id, wgPublicKey string) error {
	id = strings.TrimSpace(id)
	wgPublicKey = strings.TrimSpace(wgPublicKey)
	if id == "" || wgPublicKey == "" {
		return ValidationError{Msg: "id and wg_public_key are required"}
	}

	if _, err := s.repo.GetGateway(ctx, id); err != nil {
		return err
	}

	return s.repo.UpdateGatewayPublicKey(ctx, id, wgPublicKey)
}

func (s *Service) CreatePair(ctx context.Context, clientID, resourceID string) (model.Pair, error) {
	clientID = strings.TrimSpace(clientID)
	resourceID = strings.TrimSpace(resourceID)
	if clientID == "" || resourceID == "" {
		return model.Pair{}, ValidationError{Msg: "client_id and resource_id are required"}
	}

	var created model.Pair
	err := s.repo.WithTx(ctx, func(tx repository.Repository) error {
		if _, err := tx.GetClient(ctx, clientID); err != nil {
			return err
		}
		if _, err := tx.GetResource(ctx, resourceID); err != nil {
			return err
		}
		p := model.Pair{
			ID:         uuid.NewString(),
			ClientID:   clientID,
			ResourceID: resourceID,
		}
		if err := tx.CreatePair(ctx, &p); err != nil {
			return err
		}
		created = p
		return nil
	})
	if err != nil {
		return model.Pair{}, err
	}
	return created, nil
}

func (s *Service) ListPairs(ctx context.Context) ([]model.Pair, error) {
	return s.repo.ListPairs(ctx)
}

func (s *Service) DeletePair(ctx context.Context, id string) (bool, error) {
	return s.repo.DeletePair(ctx, strings.TrimSpace(id))
}

func (s *Service) GetClientConfig(ctx context.Context, session model.ClientSession) (model.ClientConfig, error) {
	client, err := s.repo.GetClient(ctx, session.ClientID)
	if err != nil {
		return model.ClientConfig{}, err
	}

	gateway, err := s.repo.GetGateway(ctx, session.GatewayID)
	if err != nil {
		return model.ClientConfig{}, ValidationError{Msg: "gateway not configured"}
	}

	// Get pairs only for resources belonging to this gateway
	pairs, err := s.repo.ListPairsByClient(ctx, client.ID)
	if err != nil {
		return model.ClientConfig{}, err
	}
	cidrs := make([]string, 0, len(pairs))
	for _, p := range pairs {
		// Only include resources from the session's gateway
		if p.Resource.GatewayID == session.GatewayID {
			cidrs = append(cidrs, p.Resource.CIDR)
		}
	}
	sort.Strings(cidrs)

	// Convert /32 to subnet mask for interface address
	address := strings.Replace(session.TunnelIP, "/32", "/24", 1)

	return model.ClientConfig{
		ClientID:         client.ID,
		WGPublicKey:      client.WGPublicKey,
		Address:          address,
		GatewayPublicKey: gateway.WGPublicKey,
		GatewayEndpoint:  gateway.Endpoint,
		AllowedCIDRs:     cidrs,
	}, nil
}

func (s *Service) GetGatewayConfig(ctx context.Context, id string) (model.GatewayConfig, error) {
	id = strings.TrimSpace(id)
	gateway, err := s.repo.GetGateway(ctx, id)
	if err != nil {
		return model.GatewayConfig{}, err
	}

	tunnelAddr, err := getGatewayAddress(gateway.TunnelSubnet)
	if err != nil {
		return model.GatewayConfig{}, err
	}

	// Get active sessions to map client -> tunnel IP
	sessions, err := s.repo.ListActiveSessions(ctx)
	if err != nil {
		return model.GatewayConfig{}, err
	}
	sessionMap := make(map[string]model.ClientSession)
	for _, sess := range sessions {
		sessionMap[sess.ClientID] = sess
	}

	// Get all resources for this gateway
	resources, err := s.repo.ListResourcesByGateway(ctx, id)
	if err != nil {
		return model.GatewayConfig{}, err
	}

	// Separate observe and enforce resources
	var observeResources []model.Resource
	enforceResourceIDs := make(map[string]model.Resource)
	for _, r := range resources {
		if r.Mode == "observe" {
			observeResources = append(observeResources, r)
		} else {
			enforceResourceIDs[r.ID] = r
		}
	}

	// Get pairs only for resources belonging to this gateway
	pairs, err := s.repo.ListPairsByGateway(ctx, id)
	if err != nil {
		return model.GatewayConfig{}, err
	}

	// Build policy map: client -> allowed CIDRs
	policyMap := make(map[string]*model.Policy)

	// For each active session, add observe resources to all clients
	for _, sess := range sessions {
		if sess.TunnelIP == "" || sess.GatewayID != id {
			continue
		}
		client, err := s.repo.GetClient(ctx, sess.ClientID)
		if err != nil {
			continue
		}
		entry := &model.Policy{
			ClientID:    sess.ClientID,
			ClientName:  client.Name,
			WGPublicKey: client.WGPublicKey,
			AllowedIPs:  []string{sess.TunnelIP},
		}
		// Add all observe resources
		for _, r := range observeResources {
			entry.AllowedCIDRs = append(entry.AllowedCIDRs, model.PolicyTarget{
				CIDR: r.CIDR,
				Mode: r.Mode,
			})
		}
		policyMap[sess.ClientID] = entry
	}

	// Add enforce resources based on pairs
	for _, p := range pairs {
		// Skip if resource is not enforce mode
		res, isEnforce := enforceResourceIDs[p.ResourceID]
		if !isEnforce {
			continue
		}
		// Skip clients without active session
		sess, hasSession := sessionMap[p.ClientID]
		if !hasSession || sess.TunnelIP == "" {
			continue
		}
		entry := policyMap[p.ClientID]
		if entry == nil {
			entry = &model.Policy{
				ClientID:    p.ClientID,
				ClientName:  p.Client.Name,
				WGPublicKey: p.Client.WGPublicKey,
				AllowedIPs:  []string{sess.TunnelIP},
			}
			policyMap[p.ClientID] = entry
		}
		entry.AllowedCIDRs = append(entry.AllowedCIDRs, model.PolicyTarget{
			CIDR: res.CIDR,
			Mode: res.Mode,
		})
	}

	policies := make([]model.Policy, 0, len(policyMap))
	for _, entry := range policyMap {
		sort.Slice(entry.AllowedCIDRs, func(i, j int) bool {
			return entry.AllowedCIDRs[i].CIDR < entry.AllowedCIDRs[j].CIDR
		})
		entry.ResourceCount = len(entry.AllowedCIDRs)
		policies = append(policies, *entry)
	}
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].ClientID < policies[j].ClientID
	})

	return model.GatewayConfig{
		GatewayID:     id,
		TunnelAddress: tunnelAddr,
		Policies:      policies,
	}, nil
}

func (s *Service) CreateLog(ctx context.Context, gatewayID, clientID, clientName, srcIP, dstIP, protocol string, srcPort, dstPort int, timestamp time.Time) error {
	entry := model.LogEntry{
		ID:         uuid.NewString(),
		GatewayID:  gatewayID,
		ClientID:   clientID,
		ClientName: clientName,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		Protocol:   protocol,
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Timestamp:  timestamp,
	}
	return s.repo.CreateLog(ctx, &entry)
}

type AuthError struct {
	Msg string
}

func (e AuthError) Error() string {
	return e.Msg
}

func (s *Service) ClientLogin(ctx context.Context, user, pass string) (model.ClientSession, error) {
	user = strings.TrimSpace(user)
	pass = strings.TrimSpace(pass)
	if user == "" || pass == "" {
		return model.ClientSession{}, ValidationError{Msg: "username and password are required"}
	}
	client, err := s.repo.GetClientByUsername(ctx, user)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return model.ClientSession{}, AuthError{Msg: "unauthorized"}
		}
		return model.ClientSession{}, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.PasswordHash), []byte(pass)); err != nil {
		return model.ClientSession{}, AuthError{Msg: "unauthorized"}
	}

	// Find gateway based on client's resource pairs
	pairs, err := s.repo.ListPairsByClient(ctx, client.ID)
	if err != nil {
		return model.ClientSession{}, err
	}
	if len(pairs) == 0 {
		return model.ClientSession{}, ValidationError{Msg: "no resources assigned to client"}
	}

	// Use the gateway of the first resource
	gateway, err := s.repo.GetGateway(ctx, pairs[0].Resource.GatewayID)
	if err != nil {
		return model.ClientSession{}, ValidationError{Msg: "gateway not configured"}
	}

	tunnelIP, err := s.allocateTunnelIP(ctx, gateway.TunnelSubnet)
	if err != nil {
		return model.ClientSession{}, err
	}

	session := model.ClientSession{
		ID:        uuid.NewString(),
		ClientID:  client.ID,
		GatewayID: gateway.ID,
		Token:     uuid.NewString(),
		TunnelIP:  tunnelIP,
		ExpiresAt: time.Now().UTC().Add(clientSessionTTL),
	}
	if err := s.repo.CreateClientSession(ctx, &session); err != nil {
		return model.ClientSession{}, err
	}
	return session, nil
}

func (s *Service) UpdateClientPublicKey(ctx context.Context, clientID, pubKey string) error {
	clientID = strings.TrimSpace(clientID)
	pubKey = strings.TrimSpace(pubKey)
	if clientID == "" || pubKey == "" {
		return ValidationError{Msg: "client_id and wg_public_key are required"}
	}
	if err := s.repo.UpdateClientPublicKey(ctx, clientID, pubKey); err != nil {
		return err
	}
	return nil
}

func (s *Service) ValidateClientToken(ctx context.Context, token string) (model.ClientSession, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return model.ClientSession{}, AuthError{Msg: "unauthorized"}
	}
	session, err := s.repo.GetClientSessionByToken(ctx, token)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return model.ClientSession{}, AuthError{Msg: "unauthorized"}
		}
		return model.ClientSession{}, err
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		return model.ClientSession{}, AuthError{Msg: "unauthorized"}
	}
	return session, nil
}

func IsNotFound(err error) bool {
	return errors.Is(err, repository.ErrNotFound)
}

func IsValidation(err error) bool {
	var v ValidationError
	return errors.As(err, &v)
}

func IsAuth(err error) bool {
	var a AuthError
	return errors.As(err, &a)
}

type sessionKey struct{}

func ContextWithSession(ctx context.Context, session model.ClientSession) context.Context {
	return context.WithValue(ctx, sessionKey{}, session)
}

func SessionFromContext(ctx context.Context) (model.ClientSession, bool) {
	session, ok := ctx.Value(sessionKey{}).(model.ClientSession)
	return session, ok
}

func validCIDR(val string) bool {
	_, _, err := net.ParseCIDR(val)
	return err == nil
}

// allocateTunnelIP finds the next available IP in the subnet for a client session.
// Gateway gets .1, clients get .2, .3, etc.
func (s *Service) allocateTunnelIP(ctx context.Context, subnet string) (string, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", ValidationError{Msg: "invalid subnet"}
	}

	// Get all active session IPs
	sessions, err := s.repo.ListActiveSessions(ctx)
	if err != nil {
		return "", err
	}
	usedIPs := make(map[string]bool)
	for _, sess := range sessions {
		if sess.TunnelIP != "" {
			ip := strings.TrimSuffix(sess.TunnelIP, "/32")
			usedIPs[ip] = true
		}
	}

	// Start from .2 (gateway is .1)
	ip := ipNet.IP.To4()
	if ip == nil {
		return "", ValidationError{Msg: "only IPv4 supported"}
	}

	// Start at .2
	ip[3] = 2
	for ip[3] < 255 {
		candidate := ip.String()
		if !usedIPs[candidate] && ipNet.Contains(ip) {
			return candidate + "/32", nil
		}
		ip[3]++
	}

	return "", ValidationError{Msg: "no available IP in subnet"}
}

// getGatewayAddress returns the gateway's tunnel address (first usable IP in subnet).
func getGatewayAddress(subnet string) (string, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		return "", errors.New("only IPv4 supported")
	}
	ip[3] = 1
	ones, _ := ipNet.Mask.Size()
	return ip.String() + "/" + strconv.Itoa(ones), nil
}
