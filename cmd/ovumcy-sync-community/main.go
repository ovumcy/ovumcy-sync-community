package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/api"
	"github.com/ovumcy/ovumcy-sync-community/internal/config"
	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/services"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatalf("%v", err)
	}
}

func shutdownSignal() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	return ch
}

func run(args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}

	switch command {
	case "serve":
		return runServe(cfg)
	case "migrate":
		return runMigrate(cfg)
	default:
		return fmt.Errorf("unknown command %q; use `serve` or `migrate`", command)
	}
}

func runMigrate(cfg config.Config) error {
	store, err := db.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer store.Close()

	if err := store.ApplyMigrations(context.Background()); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	log.Printf("applied database migrations for %s", cfg.DBPath)
	return nil
}

func runServe(cfg config.Config) error {
	store, err := db.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer store.Close()

	ready, err := store.SchemaReady(context.Background())
	if err != nil {
		return fmt.Errorf("check schema readiness: %w", err)
	}
	if !ready {
		return fmt.Errorf("database schema is not initialized; run `ovumcy-sync-community migrate` first")
	}

	authService := services.NewAuthService(store, cfg.SessionTTL)
	syncService := services.NewSyncService(store, services.SyncOptions{
		MaxDevices:   cfg.MaxDevices,
		MaxBlobBytes: cfg.MaxBlobBytes,
	})
	managedBridgeService := services.NewManagedBridgeService(store, authService)

	server := &http.Server{
		Addr: cfg.BindAddr,
		Handler: api.NewServer(
			authService,
			syncService,
			managedBridgeService,
			api.ServerOptions{
				ManagedBridgeToken:  cfg.ManagedBridgeToken,
				AllowedOrigins:      cfg.AllowedOrigins,
				AuthRateLimitCount:  cfg.AuthRateLimitCount,
				AuthRateLimitWindow: cfg.AuthRateLimitWindow,
				MaxBlobBytes:        cfg.MaxBlobBytes,
				ReadinessCheck:      store.Ping,
				TrustedProxyCIDRs:   cfg.TrustedProxyCIDRs,
			},
		),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		<-shutdownSignal()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	log.Printf("ovumcy-sync-community listening on %s", cfg.BindAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}

	return nil
}
