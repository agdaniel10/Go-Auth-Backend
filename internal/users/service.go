package users

import (
	"context"
	"fmt"
	"go-auth-backend/internal/helper"
	"net/mail"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type UserServiceRepository interface {
	CreateUser(ctx context.Context, user *User) error
	GetUsers(ctx context.Context) ([]User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByID(ctx context.Context, id int) (*User, error)
	Update(ctx context.Context, user User) (*User, error)
	Delete(ctx context.Context, id int) error
}

type UserService struct {
	repo UserServiceRepository
}

func NewUserService(repo UserServiceRepository) *UserService {
	return &UserService{repo: repo}
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

	if err = helper.SendEmail(input.Email, "Welcome to AG's backend", "<p>This is what it takes to be great</p>"); err != nil {
		return fmt.Errorf("failed to send welcome email: %w", err)
	}

	return nil
}
