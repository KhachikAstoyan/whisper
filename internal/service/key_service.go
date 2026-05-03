package service

import (
	"context"
	"errors"
	"fmt"

	"whisper/internal/repository"
)

var ErrNotFound = errors.New("not found")

type PublicKeyResult struct {
	UserID   string
	Username string
	KeyPEM   string
}

type KeyService struct {
	keys  *repository.KeyRepo
	users *repository.UserRepo
}

func NewKeyService(keys *repository.KeyRepo, users *repository.UserRepo) *KeyService {
	return &KeyService{keys: keys, users: users}
}

func (s *KeyService) UpsertKey(ctx context.Context, userID, keyPEM string) error {
	return s.keys.Upsert(ctx, userID, keyPEM)
}

func (s *KeyService) GetKeyByUsername(ctx context.Context, username string) (*PublicKeyResult, error) {
	user, err := s.users.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user: %w", err)
	}
	keyPEM, err := s.keys.GetByUserID(ctx, user.ID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("user has no public key registered")
		}
		return nil, fmt.Errorf("get key: %w", err)
	}
	return &PublicKeyResult{UserID: user.ID, Username: user.Username, KeyPEM: keyPEM}, nil
}

func (s *KeyService) GetKeyByUserID(ctx context.Context, userID string) (*PublicKeyResult, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user: %w", err)
	}
	keyPEM, err := s.keys.GetByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("user has no public key registered")
		}
		return nil, fmt.Errorf("get key: %w", err)
	}
	return &PublicKeyResult{UserID: userID, Username: user.Username, KeyPEM: keyPEM}, nil
}
