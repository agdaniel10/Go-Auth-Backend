package passwordreset

import (
	"context"
	"database/sql"
	"fmt"
)

type PasswordResetRepository interface {
	Create(ctx context.Context, token PasswordResetToken) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*PasswordResetToken, error)
	Delete(ctx context.Context, tokenHash string) error
	IncrementTokenResetCount(ctx context.Context, tokenHash string) (int, error)
}

type SQLPasswordResetRepository struct {
	db *sql.DB
}

func NewPasswordResetRepository(db *sql.DB) *SQLPasswordResetRepository {
	return &SQLPasswordResetRepository{db: db}
}

func (r *SQLPasswordResetRepository) Create(ctx context.Context, token PasswordResetToken) error {
	query := `
		INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`
	_, err := r.db.ExecContext(ctx, query, token.UserID, token.TokenHash, token.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create reset token: %w", err)
	}
	return nil
}

func (r *SQLPasswordResetRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*PasswordResetToken, error) {
	query := `
		SELECT id, user_id, token_hash, expires_at, created_at
		FROM password_reset_tokens
		WHERE token_hash = $1
	`
	result := &PasswordResetToken{}
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&result.ID,
		&result.UserID,
		&result.TokenHash,
		&result.ExpiresAt,
		&result.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("token not found")
	}
	if err != nil {
		return nil, fmt.Errorf("get reset token: %w", err)
	}
	return result, nil
}

func (r *SQLPasswordResetRepository) IncrementTokenResetCount(ctx context.Context, tokenHash string) (int, error) {
	query := `
		UPDATE password_reset_tokens
		SET reset_count = reset_count + 1
		WHERE token_hash = $1
		RETURNING reset_count
	`

	var updatedCount int
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(&updatedCount)
	if err != nil {
		return 0, err
	}

	return updatedCount, nil
}

func (r *SQLPasswordResetRepository) Delete(ctx context.Context, tokenHash string) error {
	query := `DELETE FROM password_reset_tokens WHERE token_hash = $1`
	_, err := r.db.ExecContext(ctx, query, tokenHash)
	if err != nil {
		return fmt.Errorf("delete reset token: %w", err)
	}
	return nil
}
