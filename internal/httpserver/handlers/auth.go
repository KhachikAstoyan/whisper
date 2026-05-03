package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"whisper/internal/httpserver/middleware"
	"whisper/internal/service"
)

type AuthHandler struct {
	authSvc *service.AuthService
}

func NewAuthHandler(authSvc *service.AuthService) *AuthHandler {
	return &AuthHandler{authSvc: authSvc}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	user, err := h.authSvc.Register(r.Context(), req.Username, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrUserExists) {
			slog.Warn("registration conflict", "username", req.Username)
			writeError(w, http.StatusConflict, "username already taken")
			return
		}
		slog.Error("registration failed", "username", req.Username, "error", err)
		writeError(w, http.StatusInternalServerError, "registration failed")
		return
	}
	slog.Info("user registered", "username", user.Username, "id", user.ID)
	writeJSON(w, http.StatusCreated, map[string]string{
		"id":       user.ID,
		"username": user.Username,
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	token, user, err := h.authSvc.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCreds) {
			slog.Warn("login failed — bad credentials", "username", req.Username)
			writeError(w, http.StatusUnauthorized, "invalid username or password")
			return
		}
		slog.Error("login error", "username", req.Username, "error", err)
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	slog.Info("user logged in", "username", user.Username, "id", user.ID)
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"id":       user.ID,
		"username": user.Username,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
