package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"

	"migration-to-zero-trust/wg-server/internal/config"
	"migration-to-zero-trust/wg-server/internal/controlplane"
	"migration-to-zero-trust/wg-server/internal/firewall"
	"migration-to-zero-trust/wg-server/internal/logging"
	"migration-to-zero-trust/wg-server/internal/syncer"
	"migration-to-zero-trust/wg-server/internal/wireguard"
)

func main() {
	_ = godotenv.Load()

	env, err := config.LoadEnv()
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	if err := env.Validate(); err != nil {
		log.Fatalf("config invalid: %v", err)
	}

	log.Printf("starting wg-server iface=%s", env.WGInterface)

	// Load or generate WireGuard key pair
	keyPair, err := wireguard.LoadOrGenerateKeyPair(config.DefaultKeyDir)
	if err != nil {
		log.Fatalf("key pair failed: %v", err)
	}
	log.Printf("wireguard public key: %s", keyPair.PublicKey.String())

	// Create control plane client
	cp := controlplane.NewClient(env.ControlPlaneURL, env.APIKey)

	// Update public key in control plane
	ctx := context.Background()
	if err := cp.UpdatePublicKey(ctx, keyPair.PublicKey.String()); err != nil {
		log.Fatalf("update public key failed: %v", err)
	}
	log.Printf("public key registered with control plane")

	// Fetch initial config from control plane
	cfg, err := cp.FetchConfig(ctx)
	if err != nil {
		log.Fatalf("fetch config failed: %v", err)
	}
	log.Printf("config fetched: tunnel_address=%s", cfg.TunnelAddress)

	// Setup WireGuard interface
	wgMgr, err := wireguard.NewManager(env.WGInterface, env.WGListenPort, keyPair)
	if err != nil {
		log.Fatalf("wireguard manager init failed: %v", err)
	}

	if err := wgMgr.Setup(cfg.TunnelAddress); err != nil {
		log.Fatalf("wireguard setup failed: %v", err)
	}
	log.Printf("wireguard interface %s configured", env.WGInterface)

	// Setup firewall
	fwMgr := firewall.NewManager(env.WGInterface)

	if err := fwMgr.Setup(); err != nil {
		log.Fatalf("firewall setup failed: %v", err)
	}
	log.Printf("firewall configured")

	// Create syncer
	sync := syncer.New(cp, wgMgr, fwMgr)

	// Setup logger (always enabled)
	const loggingGroup = 100
	logger, err := logging.NewLogger(loggingGroup, cp)
	if err != nil {
		log.Fatalf("logger init failed: %v", err)
	}
	sync.SetLogger(logger)
	log.Printf("logging enabled (group %d)", loggingGroup)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Apply initial policies
	log.Printf("applying initial policies")
	if err := sync.SyncOnce(ctx); err != nil {
		log.Fatalf("initial sync failed: %v", err)
	}
	log.Printf("initial config applied")

	// Start syncer
	go func() {
		if err := sync.Run(ctx); err != nil {
			log.Printf("syncer error: %v", err)
		}
	}()

	// Start logger
	log.Printf("starting logger")
	if err := logger.Run(ctx); err != nil {
		log.Printf("logger error: %v", err)
	}

	logger.Close()

	log.Printf("shutting down")
}
