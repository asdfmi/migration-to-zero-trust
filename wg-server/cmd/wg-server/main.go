package main

import (
	"flag"
	"log"

	"migration-to-zero-trust/wg-server/internal/config"
	"migration-to-zero-trust/wg-server/internal/logging"
	"migration-to-zero-trust/wg-server/internal/wg"
)

func main() {
	configPath := flag.String("config", "/etc/wg-server/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("config invalid: %v", err)
	}

	log.Printf("starting wg-server iface=%s authz_mode=%s logging_enabled=%t", cfg.WG.Iface, cfg.Authz.Mode, cfg.Logging.Enabled)

	if err := wg.Apply(cfg); err != nil {
		log.Fatalf("wg apply failed: %v", err)
	}

	log.Printf("wg-server configured successfully")

	if cfg.Logging.Enabled {
		log.Printf("logging enabled group=%d path=%s", cfg.Logging.Group, cfg.Logging.Path)
		if err := logging.Run(cfg); err != nil {
			log.Fatalf("logging failed: %v", err)
		}
	}
}
