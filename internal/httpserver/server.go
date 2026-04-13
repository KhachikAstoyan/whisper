package httpserver

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"whisper/internal/httpserver/handlers"
	"whisper/internal/httpserver/middleware"
	"whisper/internal/service"
)

func NewRouter(authSvc *service.AuthService) http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.StripSlashes)

	authHandler := handlers.NewAuthHandler(authSvc)

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/auth/register", authHandler.Register)
		r.Post("/auth/login", authHandler.Login)

		r.Group(func(r chi.Router) {
			r.Use(middleware.Authenticate(authSvc))
			r.Get("/auth/me", authHandler.Me)
		})
	})

	return r
}

func Run(addr string, handler http.Handler) error {
	fmt.Printf("server listening on %s\n", addr)
	return http.ListenAndServe(addr, handler)
}
