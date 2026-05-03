package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"whisper/internal/httpserver/middleware"
	"whisper/internal/service"
)

type KeyHandler struct {
	keySvc *service.KeyService
}

func NewKeyHandler(keySvc *service.KeyService) *KeyHandler {
	return &KeyHandler{keySvc: keySvc}
}

// PUT /api/v1/keys — upload or replace the caller's RSA public key.
func (h *KeyHandler) UploadKey(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "public_key is required")
		return
	}
	if err := h.keySvc.UpsertKey(r.Context(), user.ID, req.PublicKey); err != nil {
		slog.Error("key upsert failed", "user_id", user.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to store key")
		return
	}
	slog.Info("public key uploaded", "user_id", user.ID, "username", user.Username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// GET /api/v1/keys/{username} — look up a user's public key by username.
func (h *KeyHandler) GetKey(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	result, err := h.keySvc.GetKeyByUsername(r.Context(), username)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusNotFound, "public key not found")
		return
	}
	slog.Debug("public key fetched by username", "username", username, "user_id", result.UserID)
	writeJSON(w, http.StatusOK, map[string]string{
		"user_id":    result.UserID,
		"username":   result.Username,
		"public_key": result.KeyPEM,
	})
}

// GET /api/v1/keys/id/{user_id} — look up a user's public key by user ID.
func (h *KeyHandler) GetKeyByID(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "user_id")
	result, err := h.keySvc.GetKeyByUserID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "public key not found")
		return
	}
	slog.Debug("public key fetched by id", "user_id", userID, "username", result.Username)
	writeJSON(w, http.StatusOK, map[string]string{
		"user_id":    result.UserID,
		"username":   result.Username,
		"public_key": result.KeyPEM,
	})
}

