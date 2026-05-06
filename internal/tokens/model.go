package tokens

import "time"

type Token struct {
	ID        int
	UserID    int
	Hash      string
	ExpiresAt time.Time
	CreatedAt time.Time
}
