package users

import (
	"context"
	"errors"
	"fmt"
	"go-auth-backend/internal/emailverificationtoken"
	"go-auth-backend/internal/helper"
	"net/mail"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrExpiredToken           = errors.New("token has expired")
	ErrEmailVerificationFaied = errors.New("failed to verify email")
)

type UserServiceRepository interface {
	CreateUser(ctx context.Context, user *User) error
	GetUsers(ctx context.Context) ([]User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByID(ctx context.Context, id int) (*User, error)
	Update(ctx context.Context, user User) (*User, error)
	Delete(ctx context.Context, id int) error
	UpdatePassword(ctx context.Context, userID int, hashedContext string) error
	SetEmailVerified(ctx context.Context, userID int) error
}

type UserService struct {
	repo         UserServiceRepository
	emailService emailverificationtoken.EmailVerificationService
}

func NewUserService(repo UserServiceRepository, emailService emailverificationtoken.EmailVerificationService) *UserService {
	return &UserService{repo: repo, emailService: emailService}
}

// Implement helper functions
func (u *User) Normalize() {
	u.Email = strings.ToLower(strings.TrimSpace(u.Email))
	u.Name = strings.TrimSpace(u.Name)
}

func isUniqueConstraintError(err error) bool {
	return strings.Contains(err.Error(), "duplicate key")
}

func VerifyPassword(hashedPassword, plainPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
}

func (u *User) Validate() error {
	if u.Name == "" {
		return ErrNameRequired
	}

	if u.Email == "" {
		return ErrEmailRequired
	}

	if _, err := mail.ParseAddress(u.Email); err != nil {
		return ErrInvalidEmail
	}

	if u.Password == "" {
		return ErrPasswordRequired
	}

	if len(u.Password) < 8 {
		return ErrPasswordTooShort
	}

	return nil
}

func (s *UserService) CreateUser(ctx context.Context, input *User) error {
	if input == nil {
		return ErrUserRequired
	}

	input.Normalize()

	if err := input.Validate(); err != nil {
		return err
	}

	hashedPassword, err := helper.HashPassword(input.Password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	input.Password = hashedPassword

	if err = s.repo.CreateUser(ctx, input); err != nil {
		if isUniqueConstraintError(err) {
			return ErrEmailAlreadyExists
		}
		return fmt.Errorf("create user: %w", err)
	}

	return nil
}

func (s *UserService) GetByID(ctx context.Context, id int) (*User, error) {
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *UserService) GetByEmail(ctx context.Context, email string) (*User, error) {
	user, err := s.repo.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *UserService) Update(ctx context.Context, id int, user User) (*User, error) {
	result, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if user.Name != "" {
		result.Name = strings.TrimSpace(user.Name)
	}

	if user.Email != "" {
		result.Email = user.Email
	}

	updatedUser, err := s.repo.Update(ctx, *result)
	if err != nil {
		if isUniqueConstraintError(err) {
			return nil, ErrEmailAlreadyExists
		}

		return nil, fmt.Errorf("update user: %w", err)
	}

	return updatedUser, nil

}

func (s *UserService) SetEmailVerified(ctx context.Context, userID int) error {
	err := s.repo.SetEmailVerified(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to verify user: %w", err)
	}

	return nil
}

func (s *UserService) UpdatePassword(ctx context.Context, userID int, hashedContext string) error {

	user, err := s.repo.GetByID(ctx, userID)

	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	err = s.repo.UpdatePassword(ctx, user.ID, hashedContext)

	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	return nil

}
