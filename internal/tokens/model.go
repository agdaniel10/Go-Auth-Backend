package tokens

import (
	"time"

	"github.com/google/uuid"
)

type Token struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Hash      string    `json:"token_hash"`
	Used      bool      `json:"used"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	FamilyID  uuid.UUID `json:"family_id"`
	ParentID  *int      `json:"parent_id"`
}
