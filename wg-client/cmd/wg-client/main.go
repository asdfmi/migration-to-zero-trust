package main

import (
	"flag"
	"log"

	"migration-to-zero-trust/wg-client/internal/config"
	"migration-to-zero-trust/wg-client/internal/wg"
)

func main() {
	configPath := flag.String("config", "/etc/wg-client/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("config invalid: %v", err)
	}

	log.Printf("starting wg-client iface=%s", cfg.WG.Iface)

	if err := wg.Apply(cfg); err != nil {
		log.Fatalf("wg apply failed: %v", err)
	}

	log.Printf("wg-client configured successfully")
}
