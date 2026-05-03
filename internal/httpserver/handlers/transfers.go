package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	cryptopkg "whisper/internal/crypto"
	"whisper/internal/httpserver/middleware"
	"whisper/internal/service"
)

type TransferHandler struct {
	transferSvc *service.TransferService
}

func NewTransferHandler(transferSvc *service.TransferService) *TransferHandler {
	return &TransferHandler{transferSvc: transferSvc}
}

// POST /api/v1/transfers — upload an encrypted package.
func (h *TransferHandler) Upload(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var pkg cryptopkg.EncryptedPackage
	if err := json.NewDecoder(r.Body).Decode(&pkg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid package")
		return
	}
	transfer, err := h.transferSvc.Upload(r.Context(), user.ID, &pkg)
	if err != nil {
		slog.Warn("transfer upload rejected",
			"sender_id", user.ID,
			"recipient_id", pkg.RecipientID,
			"filename", pkg.Filename,
			"error", err,
		)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Info("transfer uploaded",
		"id", transfer.ID,
		"sender_id", user.ID,
		"recipient_id", transfer.RecipientID,
		"filename", transfer.Filename,
	)
	writeJSON(w, http.StatusCreated, map[string]string{
		"id":       transfer.ID,
		"filename": transfer.Filename,
	})
}

// GET /api/v1/transfers — list transfers where the caller is the recipient.
func (h *TransferHandler) List(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	transfers, err := h.transferSvc.ListForUser(r.Context(), user.ID)
	if err != nil {
		slog.Error("list transfers failed", "user_id", user.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list transfers")
		return
	}
	type item struct {
		ID        string `json:"id"`
		SenderID  string `json:"sender_id"`
		Filename  string `json:"filename"`
		CreatedAt string `json:"created_at"`
	}
	items := make([]item, 0, len(transfers))
	for _, t := range transfers {
		items = append(items, item{
			ID:        t.ID,
			SenderID:  t.SenderID,
			Filename:  t.Filename,
			CreatedAt: t.CreatedAt.Format(time.RFC3339),
		})
	}
	slog.Debug("transfers listed", "user_id", user.ID, "count", len(items))
	writeJSON(w, http.StatusOK, items)
}

// GET /api/v1/transfers/{id} — download an encrypted package (recipient only).
func (h *TransferHandler) Download(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := chi.URLParam(r, "id")
	pkg, err := h.transferSvc.Download(r.Context(), id, user.ID)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			writeError(w, http.StatusNotFound, "transfer not found")
			return
		}
		slog.Warn("transfer download denied", "transfer_id", id, "user_id", user.ID, "error", err)
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	slog.Info("transfer downloaded", "transfer_id", id, "recipient_id", user.ID)
	writeJSON(w, http.StatusOK, pkg)
}
