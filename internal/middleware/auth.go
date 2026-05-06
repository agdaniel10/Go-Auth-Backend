package main

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func CreateAccessToken(userID int, secretKey string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"sub":  userID,
			"type": "access",
			"exp":  time.Now().Add(time.Minute * 15).Unix(),
			"iat":  time.Now().Unix(),
		})

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func RefreshAccessToken(username string, secretKey string) (string, error) {

}
