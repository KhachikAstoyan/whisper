package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type KeyRepo struct {
	db *pgxpool.Pool
}

func NewKeyRepo(db *pgxpool.Pool) *KeyRepo {
	return &KeyRepo{db: db}
}

func (r *KeyRepo) Upsert(ctx context.Context, userID, keyData string) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO public_keys (user_id, key_data)
		 VALUES ($1, $2)
		 ON CONFLICT (user_id) DO UPDATE
		 SET key_data = EXCLUDED.key_data, created_at = NOW()`,
		userID, keyData,
	)
	return err
}

func (r *KeyRepo) GetByUserID(ctx context.Context, userID string) (string, error) {
	var keyData string
	err := r.db.QueryRow(ctx,
		`SELECT key_data FROM public_keys WHERE user_id = $1`,
		userID,
	).Scan(&keyData)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("get key: %w", err)
	}
	return keyData, nil
}
