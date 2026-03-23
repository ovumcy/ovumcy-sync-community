package main

import (
	"context"
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
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	store, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer store.Close()

	if err := store.ApplyMigrations(context.Background()); err != nil {
		log.Fatalf("apply migrations: %v", err)
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
		log.Fatalf("serve: %v", err)
	}
}

func shutdownSignal() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	return ch
}
