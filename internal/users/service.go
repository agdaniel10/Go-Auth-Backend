package users

import (
	"context"
	"fmt"
	"go-auth-backend/internal/helper"
	"net/mail"
	"strings"
)

type UserServiceRepository interface {
	CreateUser(ctx context.Context, user *User) error
	GetUsers(ctx context.Context) ([]User, error)
	GetByEmail(ctx context.Context, email string) ([]User, error)
	GetByID(ctx context.Context, id string) (*User, error)
	Update(ctx context.Context, user User) (*User, error)
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

	// Normalise
	input.Normalize()

	// Validation checks
	err := input.Validate()
	if err != nil {
		return err
	}

	// HashPassword
	hashedPassword, err := helper.HashPassword(input.Password)
	if err != nil {
		return fmt.Errorf("Failed to hash password")
	}
	input.Password = hashedPassword

	// Create User
	if err = s.repo.CreateUser(ctx, input); err != nil {
		// Handle contraint at DB level
		if isUniqueConstraintError(err) {
			return ErrEmailAlreadyExists
		}
	}

	subject := "Welcome to AG's backend"
	html := "<p> This is what it takes to be great </p>"
	err = helper.SendEmail(input.Email, subject, html)

	return nil

}
