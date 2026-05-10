package passwordreset

import (
	"time"
)

type PasswordResetToken struct {
	ID        int
	UserID    int
	Token     string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}
