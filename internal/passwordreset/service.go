package passwordreset

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"go-auth-backend/internal/helper"
	"go-auth-backend/internal/users"
	"math/big"
	"time"
)

type PasswordService struct {
	repo        PasswordResetRepository
	userService users.UserService
}

func NewPasswordService(repo PasswordResetRepository, userService users.UserService) *PasswordService {
	return &PasswordService{repo: repo, userService: userService}
}

func generateOTP() (int, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return 0, err
	}

	return int(nBig.Int64()) + 100000, nil
}
func (p *PasswordService) Create(ctx context.Context, id int) (string, error) {
	// Check if user exists
	_, err := p.userService.GetByID(ctx, id)
	if err != nil {
		return "", fmt.Errorf("user not found: %w", err)
	}

	// Generate random 6-digit number (100000 to 999999)
	randomNum, err := generateOTP()
	if err != nil {
		return "", err
	}
	tokenStr := fmt.Sprintf("%06d", randomNum)

	// Hash the token before saving to database
	hashedToken, err := helper.HashPasswordResetToken(tokenStr)
	if err != nil {
		return "", fmt.Errorf("hash token: %w", err)
	}

	// Save to DB
	resetToken := PasswordResetToken{
		UserID:    id,
		TokenHash: hashedToken,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		CreatedAt: time.Now(),
	}

	if err = p.repo.Create(ctx, resetToken); err != nil {
		return "", fmt.Errorf("save token: %w", err)
	}

	// Return the plain 6-digit code to the user
	return tokenStr, nil
}

func (s *PasswordService) ForgotPassword(ctx context.Context, email string) error {
	user, err := s.userService.GetByEmail(ctx, email)

	if err != nil {
		return nil
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
		return fmt.Errorf("failed to hash token")
	}
	resultToken, err := s.repo.GetByTokenHash(ctx, hashedToken)
	if err != nil {
		return fmt.Errorf("token does not exist: %w", err)
	}

	if resultToken.ExpiresAt.Before(time.Now()) {
		return errors.New("reset token expired")
	}

	acceptedResetCount := 5
	resetCount, err := s.repo.IncrementTokenResetCount(ctx, hashedToken)
	if err != nil {
		return err
	}

	if resetCount >= acceptedResetCount {
		s.repo.Delete(ctx, hashedToken)
		return fmt.Errorf("too many attempts, please request a new code")
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
		return fmt.Errorf("failed to update the password: %w", err)
	}

	err = s.repo.Delete(ctx, hashedToken)
	if err != nil {
		return fmt.Errorf("failed to delete token")
	}

	return nil

}
