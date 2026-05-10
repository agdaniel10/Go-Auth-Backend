package passwordreset

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"go-auth-backend/internal/helper"
	"go-auth-backend/internal/users"
	"time"
)

type PasswordService struct {
	repo        PasswordResetRepository
	userService users.UserService
}

func NewPasswordService(repo PasswordResetRepository, userService users.UserService) *PasswordService {
	return &PasswordService{repo: repo, userService: userService}
}

func (p *PasswordService) Create(ctx context.Context, id int) (string, error) {

	_, err := p.userService.GetByID(ctx, id)
	if err != nil {
		return "", fmt.Errorf("user not found: %w", err)
	}

	rawBytes := make([]byte, 32)
	_, err = rand.Read(rawBytes)
	if err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}

	rawToken := hex.EncodeToString(rawBytes)

	hashedToken, err := helper.HashPasswordResetToken(rawToken)
	if err != nil {
		return "", fmt.Errorf("hash token: %w", err)
	}

	token := PasswordResetToken{
		UserID:    id,
		Token:     rawToken,
		TokenHash: hashedToken,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		CreatedAt: time.Now(),
	}

	err = p.repo.Create(ctx, token)
	if err != nil {
		return "", fmt.Errorf("save token: %w", err)
	}

	return rawToken, nil
}
