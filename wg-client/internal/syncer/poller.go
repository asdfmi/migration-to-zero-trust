package syncer

import (
	"context"
	"log"
	"reflect"
	"time"

	"migration-to-zero-trust/wg-client/internal/config"
	"migration-to-zero-trust/wg-client/internal/controlplane"
	"migration-to-zero-trust/wg-client/internal/state"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Poller struct {
	ControlPlane    *controlplane.Client
	ControlPlaneURL string
	Username        string
	Password        string
	Interface       string
	PrivateKey      wgtypes.Key
	Interval        time.Duration
	StatePath       string
}

func (p *Poller) Run(ctx context.Context) error {
	interval := p.Interval
	if interval <= 0 {
		interval = config.DefaultPollInterval
	}

	var token string
	var lastCfg *controlplane.ClientConfig

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if token == "" {
			session, err := p.ControlPlane.Login(ctx, p.Username, p.Password)
			if err != nil {
				log.Printf("login failed: %v", err)
				wait(ctx, interval)
				continue
			}
			token = session.Token
		}

		cfg, err := p.ControlPlane.FetchConfig(ctx, token)
		if err != nil {
			if err == controlplane.ErrUnauthorized {
				token = ""
				continue
			}
			log.Printf("fetch config failed: %v", err)
			wait(ctx, interval)
			continue
		}

		if lastCfg == nil || !reflect.DeepEqual(*lastCfg, cfg) {
			if err := Apply(p.Interface, p.PrivateKey, cfg); err != nil {
				log.Printf("apply failed: %v", err)
			} else {
				lastCfg = &cfg
				if p.StatePath != "" {
					if err := state.Save(p.StatePath, state.State{
						ControlPlaneURL: p.ControlPlaneURL,
						InterfaceName:   p.Interface,
						Config:          cfg,
					}); err != nil {
						log.Printf("state write failed: %v", err)
					}
				}
			}
		}

		wait(ctx, interval)
	}
}

func wait(ctx context.Context, interval time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(interval):
	}
}
