package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	ServerPort  string `envconfig:"SERVER_PORT"  default:"8080"`
	DatabaseURL string `envconfig:"DATABASE_URL" required:"true"`
	StoragePath string `envconfig:"STORAGE_PATH" default:"./storage"`
	JWTSecret   string `envconfig:"JWT_SECRET"   required:"true"`
	Env         string `envconfig:"ENV"          default:"dev"`
}

func Load() *Config {
	loadDotEnv()

	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: configuration error: %v\n", err)
		os.Exit(1)
	}
	return &cfg
}

func loadDotEnv() {
	data, err := os.ReadFile(".env")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if os.Getenv(key) == "" {
			os.Setenv(key, val)
		}
	}
}
