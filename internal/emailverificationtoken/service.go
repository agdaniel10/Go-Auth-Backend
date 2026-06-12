package emailverificationtoken

import (
	"context"
	"database/sql"
	"fmt"
)

type EmailVerificationTokenRepo interface {
	Insert(ctx context.Context, token *EmailVerificationToken) error
	GetByHash(ctx context.Context, hash string) (*EmailVerificationToken, error)
	DeleteByUserID(ctx context.Context, userID int) error
}

type SQLEmailVerificationTokenRepo struct {
	db *sql.DB
}

func NewSQLEmailVerificationTokenRepo(db *sql.DB) *SQLEmailVerificationTokenRepo {
	return &SQLEmailVerificationTokenRepo{db: db}
}

func (e *SQLEmailVerificationTokenRepo) Insert(ctx context.Context, token *EmailVerificationToken) error {
	query := `
		INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`

	_, err := e.db.ExecContext(
		ctx,
		query,
		token.UserID,
		token.TokenHash,
		token.ExpiresAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create email verification token: %w", err)
	}

	return nil
}

func (e *SQLEmailVerificationTokenRepo) GetByHash(ctx context.Context, hash string) (*EmailVerificationToken, error) {
	query := `
		SELECT id, user_id, token_hash, expires_at, created_at
		FROM email_verification_tokens
		WHERE token_hash = $1
	`

	res := &EmailVerificationToken{}
	err := e.db.QueryRowContext(ctx, query, hash).Scan(
		&res.ID,
		&res.UserID,
		&res.TokenHash,
		&res.ExpiresAt,
		&res.CreatedAt,
	)

	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("token not found")
	}

	if err != nil {
		return nil, fmt.Errorf("get email token: %w", err)
	}

	return res, nil
}
