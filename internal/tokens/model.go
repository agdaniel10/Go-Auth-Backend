package tokens

import "time"

type Token struct {
	ID        int
	UserID    int
	Hash      string
	Used      bool
	ExpiresAt time.Time
	CreatedAt time.Time
}
