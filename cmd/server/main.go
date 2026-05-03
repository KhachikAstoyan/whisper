package main

import (
	"context"
	"log/slog"
	"os"

	"whisper/internal/config"
	"whisper/internal/db"
	"whisper/internal/httpserver"
	"whisper/internal/logger"
	"whisper/internal/repository"
	"whisper/internal/service"
)

func main() {
	cfg := config.Load()

	log := logger.New(cfg.Env)
	slog.SetDefault(log)

	slog.Info("starting whisper server", "port", cfg.ServerPort, "env", cfg.Env, "storage", cfg.StoragePath)

	ctx := context.Background()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()
	slog.Info("database connected")

	if err := db.Migrate(ctx, pool); err != nil {
		slog.Error("migration failed", "error", err)
		os.Exit(1)
	}
	slog.Info("migrations applied")

	userRepo := repository.NewUserRepo(pool)
	keyRepo := repository.NewKeyRepo(pool)
	transferRepo := repository.NewTransferRepo(pool)

	authSvc := service.NewAuthService(userRepo, cfg.JWTSecret)
	keySvc := service.NewKeyService(keyRepo, userRepo)
	transferSvc := service.NewTransferService(transferRepo, keyRepo, userRepo, cfg.StoragePath)

	router := httpserver.NewRouter(authSvc, keySvc, transferSvc)

	slog.Info("server listening", "addr", ":"+cfg.ServerPort)
	if err := httpserver.Run(":"+cfg.ServerPort, router); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
