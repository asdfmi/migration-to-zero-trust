package main

import (
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"

	apiHandler "migration-to-zero-trust/control-plane/internal/handler/api"
	uiHandler "migration-to-zero-trust/control-plane/internal/handler/ui"
	"migration-to-zero-trust/control-plane/internal/infra"
	appmw "migration-to-zero-trust/control-plane/internal/middleware"
	"migration-to-zero-trust/control-plane/internal/model"
	"migration-to-zero-trust/control-plane/internal/repository"
	"migration-to-zero-trust/control-plane/internal/service"
)

type config struct {
	basicUser string
	basicPass string
}

const (
	defaultAddr   = ":8080"
	defaultDBPath = "control-plane.db"
)

func main() {
	_ = godotenv.Load("control-plane/.env")
	_ = godotenv.Load(".env")

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	db, err := infra.OpenDB(defaultDBPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&model.Client{}, &model.Resource{}, &model.Gateway{}, &model.Pair{}, &model.LogEntry{}, &model.ClientSession{}); err != nil {
		log.Fatal(err)
	}

	repo := repository.NewGormRepository(db)
	svc := service.New(repo)

	ui, err := uiHandler.NewHandler(svc)
	if err != nil {
		log.Fatal(err)
	}

	api := apiHandler.NewHandler(svc)

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	r.Route("/api", func(r chi.Router) {
		// Public (no auth)
		r.Post("/client/login", api.ClientLogin)

		// Client auth (Bearer token)
		r.Group(func(r chi.Router) {
			r.Use(appmw.ClientTokenAuth(svc))
			r.Get("/client/config", api.ClientConfigSelf)
			r.Put("/client/keys", api.ClientUpdateKey)
		})

		// Gateway auth (gateway-specific API key)
		r.Group(func(r chi.Router) {
			r.Use(appmw.GatewayAPIKey(repo))
			r.Put("/gateway/public-key", api.UpdateGatewayPublicKey)
			r.Get("/gateway/config", api.GatewayConfig)
			r.Post("/logs", api.IngestLogs)
		})
	})

	r.Group(func(r chi.Router) {
		r.Use(appmw.BasicAuth(cfg.basicUser, cfg.basicPass))
		r.Mount("/", ui.Routes())
	})

	log.Printf("control-plane listening on %s", defaultAddr)
	if err := http.ListenAndServe(defaultAddr, r); err != nil {
		log.Fatal(err)
	}
}

func loadConfig() (config, error) {
	cfg := config{
		basicUser: os.Getenv("CONTROL_PLANE_BASIC_USER"),
		basicPass: os.Getenv("CONTROL_PLANE_BASIC_PASS"),
	}
	if cfg.basicUser == "" || cfg.basicPass == "" {
		return config{}, errors.New("CONTROL_PLANE_BASIC_USER and CONTROL_PLANE_BASIC_PASS are required")
	}
	return cfg, nil
}
