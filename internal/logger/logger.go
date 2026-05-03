package logger

import (
	"log/slog"
	"os"
)

// New returns a slog.Logger configured for the environment.
// "prod" → JSON to stdout. Anything else → human-readable text.
func New(env string) *slog.Logger {
	var handler slog.Handler
	if env == "prod" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	}
	return slog.New(handler)
}
