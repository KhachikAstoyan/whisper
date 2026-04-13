package main

import (
	"context"
	"fmt"
	"os"

	"whisper/internal/config"
	"whisper/internal/db"
	"whisper/internal/httpserver"
	"whisper/internal/repository"
	"whisper/internal/service"
)

func main() {
	cfg := config.Load()

	ctx := context.Background()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "database: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		fmt.Fprintf(os.Stderr, "migration: %v\n", err)
		os.Exit(1)
	}

	userRepo := repository.NewUserRepo(pool)
	authSvc := service.NewAuthService(userRepo, cfg.JWTSecret)
	router := httpserver.NewRouter(authSvc)

	if err := httpserver.Run(":"+cfg.ServerPort, router); err != nil {
		fmt.Fprintf(os.Stderr, "server: %v\n", err)
		os.Exit(1)
	}
}
