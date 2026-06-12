package tokens

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type TokenRepository interface {
	Insert(ctx context.Context, token Token) error
	GetByHash(ctx context.Context, hash string) (*Token, error)
	DeleteByUserID(ctx context.Context, userID int) error
	DeleteExpired(ctx context.Context) error
	InvalidateAllTokens(ctx context.Context, userID int) error
	MarkAsUsed(ctx context.Context, hash string) error
	RevokeTokenFamily(ctx context.Context, family_id uuid.UUID) error
}

type SQLTokenRepository struct {
	db *sql.DB
}

func NewSQLTokenRepository(db *sql.DB) TokenRepository {
	return &SQLTokenRepository{db: db}
}

func (r *SQLTokenRepository) Insert(ctx context.Context, token Token) error {
	query := `
		INSERT INTO tokens (user_id, token_hash, expires_at, family_id, parent_id)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at
	`
	return r.db.QueryRowContext(ctx, query, token.UserID, token.Hash, token.ExpiresAt, token.FamilyID, token.ParentID).Scan(
		&token.ID,
		&token.CreatedAt,
	)
}

func (r *SQLTokenRepository) GetByHash(ctx context.Context, hash string) (*Token, error) {
	query := `
		SELECT id, user_id, token_hash, expires_at, created_at
		FROM tokens
		WHERE token_hash = $1
	`
	token := &Token{}
	err := r.db.QueryRowContext(ctx, query, hash).Scan(
		&token.ID,
		&token.UserID,
		&token.Hash,
		&token.ExpiresAt,
		&token.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (r *SQLTokenRepository) DeleteByUserID(ctx context.Context, userID int) error {
	query := `DELETE FROM tokens WHERE user_id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

func (r *SQLTokenRepository) InvalidateAllTokens(ctx context.Context, userID int) error {
	query := `
		DELETE FROM tokens 
		WHERE user_id = $1
	`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

func (r *SQLTokenRepository) RevokeTokenFamily(ctx context.Context, family_id uuid.UUID) error {
	query := `
		UPDATE tokens
		SET used = true
		WHERE family_id = $1
	`

	_, err := r.db.ExecContext(ctx, query, family_id)
	if err != nil {
		return err
	}

	return nil
}

func (r *SQLTokenRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM tokens WHERE expires_at < NOW()`
	_, err := r.db.ExecContext(ctx, query)
	return err
}

func (r *SQLTokenRepository) MarkAsUsed(ctx context.Context, hash string) error {
	query := `
		UPDATE tokens 
		SET used = true
		WHERE token_hash = $1
	`

	res, err := r.db.ExecContext(ctx, query, hash)
	if err != nil {
		return err
	}

	rows, err := res.RowsAffected()
	if err == nil && rows == 0 {
		return errors.New("token not found")
	}

	return nil
}

// Helper functions
func GenerateRefreshToken() (raw string, hash string, err error) {
	bytes := make([]byte, 32)
	if _, err = rand.Read(bytes); err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	raw = hex.EncodeToString(bytes)
	hash = HashToken(raw)
	return raw, hash, nil
}

func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func NewRefreshToken(userID int) (*Token, string, error) {
	raw, hash, err := GenerateRefreshToken()
	if err != nil {
		return nil, "", err
	}

	token := &Token{
		UserID:    userID,
		Hash:      hash,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7),
	}

	return token, raw, nil
}
