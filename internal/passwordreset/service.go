package passwordreset

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
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

func (s *PasswordService) ForgotPassword(ctx context.Context, email string) error {
	user, err := s.userService.GetByEmail(ctx, email)

	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	rawToken, err := s.Create(ctx, user.ID)
	if err != nil {
		return fmt.Errorf("token failed to be created")
	}

	body := fmt.Sprintf("<p>%s</p>", rawToken)
	err = helper.SendResetToken(user.Email, "Password reset token", body)
	if err != nil {
		hashedToken, _ := helper.HashPasswordResetToken(rawToken)
		s.repo.Delete(ctx, hashedToken)
		return fmt.Errorf("failed to send password reset token: %w", err)
	}

	return nil

}

func (s *PasswordService) ResetPassword(ctx context.Context, token, newPassword string) error {
	hashedToken, err := helper.HashPasswordResetToken(token)
	if err != nil {
		return fmt.Errorf("failed to hask token")
	}
	resultToken, err := s.repo.GetByTokenHash(ctx, hashedToken)
	if err != nil {
		return fmt.Errorf("token does not exist: %w", err)
	}

	if resultToken.ExpiresAt.Before(time.Now()) {
		return errors.New("reset token expired")
	}

	if len(newPassword) < 8 {
		return fmt.Errorf("invalid password")
	}

	hashNewPassword, err := helper.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hask new password")
	}

	err = s.userService.UpdatePassword(ctx, resultToken.UserID, hashNewPassword)
	if err != nil {
		return fmt.Errorf("failed to update the password")
	}

	err = s.repo.Delete(ctx, hashedToken)
	if err != nil {
		return fmt.Errorf("failed to delete token")
	}

	return nil

}
