package controlplane

import (
	"context"
	"log"
	"reflect"
	"time"
)

const DefaultPollInterval = 30 * time.Second

type Poller struct {
	Client   *Client
	Interval time.Duration
	OnChange func(cfg *EnforcerConfig) error
}

func (p *Poller) Run(ctx context.Context) error {
	interval := p.Interval
	if interval <= 0 {
		interval = DefaultPollInterval
	}

	var lastCfg *EnforcerConfig

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		cfg, err := p.Client.FetchConfig(ctx)
		if err != nil {
			log.Printf("fetch config failed: %v", err)
			wait(ctx, interval)
			continue
		}

		if lastCfg == nil || !reflect.DeepEqual(*lastCfg, *cfg) {
			if p.OnChange != nil {
				if err := p.OnChange(cfg); err != nil {
					log.Printf("apply failed: %v", err)
				} else {
					lastCfg = cfg
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
