package tokens

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken  = errors.New("invalid token")
	ErrExpiredToken  = errors.New("token has expired")
	ErrTokenNotFound = errors.New("token not found")
)

type TokenServiceRepository interface {
	Insert(ctx context.Context, token Token) error
	GetByHash(ctx context.Context, hash string) (*Token, error)
	DeleteByUserID(ctx context.Context, userID int) error
	DeleteExpired(ctx context.Context) error
	InvalidateAllTokens(ctx context.Context, userID int) error
	MarkAsUsed(ctx context.Context, hash string) error
}

type UserId struct {
	UserId Token
}

type TokenService struct {
	repo      TokenServiceRepository
	secretKey string
}

func NewTokenService(repo TokenServiceRepository, secretKey string) *TokenService {
	return &TokenService{repo: repo, secretKey: secretKey}
}

// CreateAccessToken generates a signed JWT access token
func (s *TokenService) CreateAccessToken(userID int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"sub":  userID,
			"type": "access",
			"exp":  time.Now().Add(time.Minute * 15).Unix(),
			"iat":  time.Now().Unix(),
		})

	tokenString, err := token.SignedString([]byte(s.secretKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return tokenString, nil
}

// CreateRefreshToken generates a refresh token, stores it in DB, returns raw token to caller
func (s *TokenService) CreateRefreshToken(ctx context.Context, userID int) (string, error) {
	token, raw, err := NewRefreshToken(userID)
	if err != nil {
		return "", err
	}

	if err = s.repo.Insert(ctx, *token); err != nil {
		return "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	return raw, nil
}

// GenerateTokenPair issues both tokens at once — call this on login and register
func (s *TokenService) GenerateTokenPair(ctx context.Context, userID int) (accessToken string, refreshToken string, err error) {
	accessToken, err = s.CreateAccessToken(userID)
	if err != nil {
		return "", "", err
	}

	refreshToken, err = s.CreateRefreshToken(ctx, userID)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// ValidateAccessToken parses and validates a JWT, returns the userID from claims
func (s *TokenService) ValidateAccessToken(tokenString string) (int, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(s.secretKey), nil
	})

	if err != nil {
		return 0, ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return 0, ErrInvalidToken
	}

	// make sure it is an access token not a refresh token
	if claims["type"] != "access" {
		return 0, ErrInvalidToken
	}

	// extract userID from sub claim
	sub, ok := claims["sub"].(float64)
	if !ok {
		return 0, ErrInvalidToken
	}

	return int(sub), nil
}

// RefreshTokens validates incoming refresh token, rotates it, issues new token pair
func (s *TokenService) RefreshTokens(ctx context.Context, rawToken string) (accessToken string, refreshToken string, err error) {
	// hash the incoming token and look it up in DB
	hash := HashToken(rawToken)

	stored, err := s.repo.GetByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", ErrTokenNotFound
		}
		return "", "", fmt.Errorf("failed to get refresh token: %w", err)
	}

	// check expiry first
	if time.Now().After(stored.ExpiresAt) {
		return "", "", ErrExpiredToken
	}

	//Reuse detection
	if stored.Used {
		s.repo.InvalidateAllTokens(ctx, stored.UserID)
		return "", "", ErrExpiredToken
	}

	// Mark current token as used
	err = s.repo.MarkAsUsed(ctx, stored.Hash)
	if err != nil {
		return "", "", fmt.Errorf("failed to mark token as used: %w", err)
	}

	// issue a brand new token pair
	return s.GenerateTokenPair(ctx, stored.UserID)
}

func (s *TokenService) InvalidateAllTokens(ctx context.Context, userID int) error {
	err := s.repo.InvalidateAllTokens(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to invalidate tokens for user %d: %w", userID, err)
	}
	return nil
}

// Logout deletes all refresh tokens for a user
func (s *TokenService) Logout(ctx context.Context, userID int) error {
	if err := s.repo.DeleteByUserID(ctx, userID); err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}
	return nil
}
