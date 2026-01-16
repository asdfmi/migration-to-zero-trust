package main

import (
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"

	apiHandler "migration-to-zero-trust/controlplane/internal/handler/api"
	uiHandler "migration-to-zero-trust/controlplane/internal/handler/ui"
	"migration-to-zero-trust/controlplane/internal/infra"
	appmw "migration-to-zero-trust/controlplane/internal/middleware"
	"migration-to-zero-trust/controlplane/internal/model"
	"migration-to-zero-trust/controlplane/internal/repository"
	"migration-to-zero-trust/controlplane/internal/service"
)

type config struct {
	basicUser string
	basicPass string
	jwtSecret string
}

const (
	defaultAddr   = ":8080"
	defaultDBPath = "controlplane.db"
)

func main() {
	_ = godotenv.Load("controlplane/.env")
	_ = godotenv.Load(".env")

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	service.InitJWT(cfg.jwtSecret)

	db, err := infra.OpenDB(defaultDBPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&model.Client{}, &model.Resource{}, &model.Enforcer{}, &model.Pair{}, &model.LogEntry{}); err != nil {
		log.Fatal(err)
	}

	repo := repository.NewGormRepository(db)

	ui, err := uiHandler.NewHandler(repo)
	if err != nil {
		log.Fatal(err)
	}

	api := apiHandler.NewHandler(repo)

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Register API routes with Huma
	api.RegisterRoutes(r)

	// UI routes with basic auth
	r.Group(func(r chi.Router) {
		r.Use(appmw.BasicAuth(cfg.basicUser, cfg.basicPass))
		r.Mount("/", ui.Routes())
	})

	log.Printf("controlplane listening on %s", defaultAddr)
	if err := http.ListenAndServe(defaultAddr, r); err != nil {
		log.Fatal(err)
	}
}

func loadConfig() (config, error) {
	cfg := config{
		basicUser: os.Getenv("CONTROLPLANE_BASIC_USER"),
		basicPass: os.Getenv("CONTROLPLANE_BASIC_PASS"),
		jwtSecret: os.Getenv("JWT_SECRET"),
	}
	if cfg.basicUser == "" || cfg.basicPass == "" {
		return config{}, errors.New("CONTROLPLANE_BASIC_USER and CONTROLPLANE_BASIC_PASS are required")
	}
	if cfg.jwtSecret == "" {
		return config{}, errors.New("JWT_SECRET is required")
	}
	return cfg, nil
}
