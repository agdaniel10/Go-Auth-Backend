package emailverificationtoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	ErrExpiredToken           = errors.New("token has expired")
	ErrEmailVerificationFaied = errors.New("failed to verify email")
)

type UserService interface {
	SetEmailVerified(ctx context.Context, userID int) error
}

type EmailVerificationService struct {
	repo        EmailVerificationTokenRepo
	userService UserService
}

func NewEmailVerificationService(
	repo EmailVerificationTokenRepo,
	userService UserService,
) *EmailVerificationService {
	return &EmailVerificationService{
		repo:        repo,
		userService: userService,
	}
}

func GenerateSecureToken() (string, string, error) {
	max := big.NewInt(10000000)

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate random number: %w", err)
	}

	raw := fmt.Sprintf("%06d", n.Int64())
	hashBytes := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(hashBytes[:])

	return raw, hash, err
}

func (e *EmailVerificationService) CreateEmailVerificationToken(ctx context.Context, userID int) (string, error) {
	raw, hash, err := GenerateSecureToken()
	if err != nil {
		return "", err
	}

	token := &EmailVerificationToken{
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		CreatedAt: time.Now(),
	}

	err = e.repo.Insert(ctx, token)
	if err != nil {
		return "", fmt.Errorf("failed to create verification token: %w", err)
	}

	return raw, nil
}

func (e *EmailVerificationService) VerifyEmail(ctx context.Context, rawToken string) error {
	hash := HashEmailVerificationToken(rawToken)

	token, err := e.repo.GetByHash(ctx, hash)
	if err != nil {
		return err
	}

	if time.Now().After(token.ExpiresAt) {
		return ErrExpiredToken
	}

	err = e.userService.SetEmailVerified(ctx, token.UserID)
	if err != nil {
		return ErrEmailVerificationFaied
	}

	err = e.repo.DeleteByUserID(ctx, token.UserID)
	if err != nil {
		return fmt.Errorf("failed to delete verification token: %w", err)
	}

	return nil
}

func HashEmailVerificationToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
