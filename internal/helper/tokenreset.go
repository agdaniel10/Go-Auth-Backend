package helper

import (
	"crypto/sha256"
	"encoding/hex"
)

func HashPasswordResetToken(token string) (string, error) {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:]), nil
}
