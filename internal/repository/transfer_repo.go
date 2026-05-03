package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whisper/internal/models"
)

type TransferRepo struct {
	db *pgxpool.Pool
}

func NewTransferRepo(db *pgxpool.Pool) *TransferRepo {
	return &TransferRepo{db: db}
}

func (r *TransferRepo) Create(ctx context.Context, id, senderID, recipientID, filename, filePath string) (*models.Transfer, error) {
	t := &models.Transfer{}
	err := r.db.QueryRow(ctx,
		`INSERT INTO transfers (id, sender_id, recipient_id, filename, file_path)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, sender_id, recipient_id, filename, file_path, created_at`,
		id, senderID, recipientID, filename, filePath,
	).Scan(&t.ID, &t.SenderID, &t.RecipientID, &t.Filename, &t.FilePath, &t.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create transfer: %w", err)
	}
	return t, nil
}

func (r *TransferRepo) ListForRecipient(ctx context.Context, recipientID string) ([]*models.Transfer, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, sender_id, recipient_id, filename, file_path, created_at
		 FROM transfers WHERE recipient_id = $1
		 ORDER BY created_at DESC`,
		recipientID,
	)
	if err != nil {
		return nil, fmt.Errorf("list transfers: %w", err)
	}
	defer rows.Close()

	var transfers []*models.Transfer
	for rows.Next() {
		t := &models.Transfer{}
		if err := rows.Scan(&t.ID, &t.SenderID, &t.RecipientID, &t.Filename, &t.FilePath, &t.CreatedAt); err != nil {
			return nil, err
		}
		transfers = append(transfers, t)
	}
	return transfers, rows.Err()
}

func (r *TransferRepo) GetByID(ctx context.Context, id string) (*models.Transfer, error) {
	t := &models.Transfer{}
	err := r.db.QueryRow(ctx,
		`SELECT id, sender_id, recipient_id, filename, file_path, created_at
		 FROM transfers WHERE id = $1`,
		id,
	).Scan(&t.ID, &t.SenderID, &t.RecipientID, &t.Filename, &t.FilePath, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get transfer: %w", err)
	}
	return t, nil
}
