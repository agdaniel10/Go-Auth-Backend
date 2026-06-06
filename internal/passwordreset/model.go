package passwordreset

import (
	"time"
)

type PasswordResetToken struct {
	ID         int
	UserID     int
	TokenHash  string
	ResetCount int
	ExpiresAt  time.Time
	CreatedAt  time.Time
}
