package controlplane

import (
	"context"
	"log"
	"reflect"
	"time"
)

const DefaultPollInterval = 15 * time.Second

type Poller struct {
	Client   *Client
	Username string
	Password string
	Interval time.Duration
	OnChange func(cfg ClientConfig) error
}

func (p *Poller) Run(ctx context.Context) error {
	interval := p.Interval
	if interval <= 0 {
		interval = DefaultPollInterval
	}

	var token string
	var lastCfg *ClientConfig

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if token == "" {
			session, err := p.Client.Login(ctx, p.Username, p.Password)
			if err != nil {
				log.Printf("login failed: %v", err)
				wait(ctx, interval)
				continue
			}
			token = session.Token
		}

		cfg, err := p.Client.FetchConfig(ctx, token)
		if err != nil {
			if err == ErrUnauthorized {
				token = ""
				wait(ctx, interval)
				continue
			}
			log.Printf("fetch config failed: %v", err)
			wait(ctx, interval)
			continue
		}

		if lastCfg == nil || !reflect.DeepEqual(*lastCfg, cfg) {
			if p.OnChange != nil {
				if err := p.OnChange(cfg); err != nil {
					log.Printf("apply failed: %v", err)
				} else {
					lastCfg = &cfg
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
