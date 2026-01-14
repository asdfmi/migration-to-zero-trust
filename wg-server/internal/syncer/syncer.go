package syncer

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"migration-to-zero-trust/wg-server/internal/controlplane"
	"migration-to-zero-trust/wg-server/internal/firewall"
	"migration-to-zero-trust/wg-server/internal/logging"
	"migration-to-zero-trust/wg-server/internal/wireguard"
)

const pollInterval = 30 * time.Second

type Syncer struct {
	cp         *controlplane.Client
	wg         *wireguard.Manager
	fw         *firewall.Manager
	logger     *logging.Logger
	lastConfig string
}

func New(cp *controlplane.Client, wg *wireguard.Manager, fw *firewall.Manager) *Syncer {
	return &Syncer{
		cp: cp,
		wg: wg,
		fw: fw,
	}
}

func (s *Syncer) SetLogger(logger *logging.Logger) {
	s.logger = logger
}

func (s *Syncer) Run(ctx context.Context) error {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.sync(ctx); err != nil {
				log.Printf("sync error: %v", err)
			}
		}
	}
}

func (s *Syncer) sync(ctx context.Context) error {
	cfg, err := s.cp.FetchConfig(ctx)
	if err != nil {
		return err
	}

	hash, err := configHash(cfg)
	if err != nil {
		return err
	}

	if hash == s.lastConfig {
		return nil
	}

	log.Printf("config changed, applying updates")

	if err := s.wg.ApplyPeers(cfg.Policies); err != nil {
		return err
	}

	if err := s.fw.ApplyPolicies(cfg.Policies); err != nil {
		return err
	}

	if s.logger != nil {
		s.logger.UpdatePeers(cfg.Policies)
	}

	s.lastConfig = hash
	log.Printf("config applied successfully")

	return nil
}

func (s *Syncer) SyncOnce(ctx context.Context) error {
	cfg, err := s.cp.FetchConfig(ctx)
	if err != nil {
		return err
	}

	if err := s.wg.ApplyPeers(cfg.Policies); err != nil {
		return err
	}

	if err := s.fw.ApplyPolicies(cfg.Policies); err != nil {
		return err
	}

	if s.logger != nil {
		s.logger.UpdatePeers(cfg.Policies)
	}

	hash, _ := configHash(cfg)
	s.lastConfig = hash

	return nil
}

// FetchConfig fetches config from control plane without applying it
func (s *Syncer) FetchConfig(ctx context.Context) (*controlplane.GatewayConfig, error) {
	return s.cp.FetchConfig(ctx)
}

func configHash(cfg *controlplane.GatewayConfig) (string, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
