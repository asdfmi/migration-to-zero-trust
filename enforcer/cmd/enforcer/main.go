package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"

	"migration-to-zero-trust/enforcer/internal/config"
	"migration-to-zero-trust/enforcer/internal/controlplane"
	"migration-to-zero-trust/enforcer/internal/firewall"
	"migration-to-zero-trust/enforcer/internal/logging"
	"migration-to-zero-trust/enforcer/internal/wireguard"
)

func main() {
	_ = godotenv.Load()

	env, err := config.LoadEnv()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	log.Printf("starting enforcer iface=%s", env.WGInterface)

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
	if err := wireguard.Setup(env.WGInterface, env.WGListenPort, keyPair, cfg.TunnelAddress); err != nil {
		log.Fatalf("wireguard setup failed: %v", err)
	}
	log.Printf("wireguard interface %s configured", env.WGInterface)

	// Setup firewall
	fwMgr := firewall.NewManager(env.WGInterface)

	if err := fwMgr.Setup(); err != nil {
		log.Fatalf("firewall setup failed: %v", err)
	}
	log.Printf("firewall configured")

	// Setup logger
	logger, err := logging.NewLogger(firewall.DefaultLoggingGroup, cp)
	if err != nil {
		log.Fatalf("logger init failed: %v", err)
	}
	log.Printf("logging enabled (group %d)", firewall.DefaultLoggingGroup)

	// Define apply function
	applyFn := func(cfg *controlplane.EnforcerConfig) error {
		if err := wireguard.ApplyPeers(env.WGInterface, cfg.Policies); err != nil {
			return err
		}
		if err := fwMgr.ApplyPolicies(cfg.Policies); err != nil {
			return err
		}
		logger.UpdateLookupTables(cfg.Policies)
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Apply initial policies
	log.Printf("applying initial policies")
	if err := applyFn(cfg); err != nil {
		log.Fatalf("initial apply failed: %v", err)
	}
	log.Printf("initial config applied")

	// Start poller
	poller := &controlplane.Poller{
		Client:   cp,
		Interval: controlplane.DefaultPollInterval,
		OnChange: applyFn,
	}
	go func() {
		if err := poller.Run(ctx); err != nil {
			log.Printf("poller error: %v", err)
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
