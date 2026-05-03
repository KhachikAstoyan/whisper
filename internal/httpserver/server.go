package httpserver

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"whisper/internal/httpserver/handlers"
	"whisper/internal/httpserver/middleware"
	"whisper/internal/service"
)

func NewRouter(authSvc *service.AuthService, keySvc *service.KeyService, transferSvc *service.TransferService) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestLogger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.StripSlashes)

	authHandler := handlers.NewAuthHandler(authSvc)
	keyHandler := handlers.NewKeyHandler(keySvc)
	transferHandler := handlers.NewTransferHandler(transferSvc)

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/auth/register", authHandler.Register)
		r.Post("/auth/login", authHandler.Login)

		// Public key lookup — no auth required so senders can fetch recipient keys.
		r.Get("/keys/id/{user_id}", keyHandler.GetKeyByID)
		r.Get("/keys/{username}", keyHandler.GetKey)

		r.Group(func(r chi.Router) {
			r.Use(middleware.Authenticate(authSvc))

			r.Get("/auth/me", authHandler.Me)

			r.Put("/keys", keyHandler.UploadKey)

			r.Post("/transfers", transferHandler.Upload)
			r.Get("/transfers", transferHandler.List)
			r.Get("/transfers/{id}", transferHandler.Download)
		})
	})

	return r
}

func Run(addr string, handler http.Handler) error {
	slog.Info("server listening", "addr", addr)
	return http.ListenAndServe(addr, handler)
}
