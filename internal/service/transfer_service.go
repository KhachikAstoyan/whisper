package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	cryptopkg "whisper/internal/crypto"
	"whisper/internal/models"
	"whisper/internal/repository"
)

type TransferService struct {
	transfers   *repository.TransferRepo
	keys        *repository.KeyRepo
	users       *repository.UserRepo
	storagePath string
}

func NewTransferService(
	transfers *repository.TransferRepo,
	keys *repository.KeyRepo,
	users *repository.UserRepo,
	storagePath string,
) *TransferService {
	return &TransferService{
		transfers:   transfers,
		keys:        keys,
		users:       users,
		storagePath: storagePath,
	}
}

// Upload validates, signature-checks, persists the encrypted package, and records metadata.
func (s *TransferService) Upload(ctx context.Context, senderID string, pkg *cryptopkg.EncryptedPackage) (*models.Transfer, error) {
	if pkg.SenderID != senderID {
		return nil, fmt.Errorf("sender_id mismatch")
	}
	if _, err := s.users.GetByID(ctx, pkg.RecipientID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("recipient not found")
		}
		return nil, err
	}

	senderKeyPEM, err := s.keys.GetByUserID(ctx, senderID)
	if err != nil {
		return nil, fmt.Errorf("sender has no public key registered")
	}
	senderPub, err := cryptopkg.ParsePublicKey([]byte(senderKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse sender public key: %w", err)
	}

	signable, err := cryptopkg.SignableBytes(pkg)
	if err != nil {
		return nil, fmt.Errorf("marshal package: %w", err)
	}
	rawSig, err := base64.StdEncoding.DecodeString(pkg.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if err := cryptopkg.Verify(senderPub, signable, rawSig); err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	if err := os.MkdirAll(s.storagePath, 0700); err != nil {
		return nil, fmt.Errorf("create storage dir: %w", err)
	}
	id := newUUID()
	filePath := filepath.Join(s.storagePath, id+".pkg")
	data, err := json.Marshal(pkg)
	if err != nil {
		return nil, fmt.Errorf("marshal package: %w", err)
	}
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return nil, fmt.Errorf("write package: %w", err)
	}

	return s.transfers.Create(ctx, id, senderID, pkg.RecipientID, pkg.Filename, filePath)
}

func (s *TransferService) ListForUser(ctx context.Context, userID string) ([]*models.Transfer, error) {
	return s.transfers.ListForRecipient(ctx, userID)
}

// Download fetches and returns the encrypted package; only the intended recipient may download.
func (s *TransferService) Download(ctx context.Context, transferID, recipientID string) (*cryptopkg.EncryptedPackage, error) {
	t, err := s.transfers.GetByID(ctx, transferID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if t.RecipientID != recipientID {
		return nil, fmt.Errorf("access denied")
	}
	data, err := os.ReadFile(t.FilePath)
	if err != nil {
		return nil, fmt.Errorf("read package: %w", err)
	}
	var pkg cryptopkg.EncryptedPackage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parse package: %w", err)
	}
	return &pkg, nil
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
