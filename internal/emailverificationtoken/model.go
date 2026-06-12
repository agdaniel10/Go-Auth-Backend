package emailverificationtoken

import "time"

type EmailVerificationToken struct {
	ID        int
	UserID    int
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}
