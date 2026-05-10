package helper

import "golang.org/x/crypto/bcrypt"

func HashPasswordResetToken(token string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	return string(bytes), err
}
