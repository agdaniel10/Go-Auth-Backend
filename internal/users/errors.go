package users

import "errors"

var (
	ErrUserRequired       = errors.New("user is required")
	ErrNameRequired       = errors.New("name is required")
	ErrEmailRequired      = errors.New("email is required")
	ErrInvalidEmail       = errors.New("invalid email address")
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrPasswordRequired   = errors.New("password is required")
	ErrPasswordTooShort   = errors.New("password must be at least 8 characters")
	ErrToken              = errors.New("Token not recognised")
)
