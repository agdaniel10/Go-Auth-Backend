package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"go-auth-backend/internal/tokens"
	"go-auth-backend/internal/users"
)

// Service interfaces the auth handler depends on
type AuthUserService interface {
	CreateUser(ctx context.Context, user *users.User) error
	GetByEmail(ctx context.Context, email string) (*users.User, error)
}

type AuthTokenService interface {
	GenerateTokenPair(ctx context.Context, userID int) (accessToken string, refreshToken string, err error)
	RefreshTokens(ctx context.Context, rawToken string) (accessToken string, refreshToken string, err error)
	Logout(ctx context.Context, userID int) error
}

// AuthHandler
type AuthHandler struct {
	userService  AuthUserService
	tokenService AuthTokenService
	errorLog     *log.Logger
	infoLog      *log.Logger
}

func NewAuthHandler(
	userService AuthUserService,
	tokenService AuthTokenService,
	errorLog *log.Logger,
	infoLog *log.Logger,
) *AuthHandler {
	return &AuthHandler{
		userService:  userService,
		tokenService: tokenService,
		errorLog:     errorLog,
		infoLog:      infoLog,
	}
}

// Request and response structs
type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type LogoutRequest struct {
	UserID int `json:"user_id"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Register handler
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid input", http.StatusBadRequest)
		return
	}

	user := &users.User{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	}

	if err := h.userService.CreateUser(r.Context(), user); err != nil {
		switch {
		case errors.Is(err, users.ErrEmailAlreadyExists):
			http.Error(w, "email already exists", http.StatusConflict)
		case errors.Is(err, users.ErrNameRequired),
			errors.Is(err, users.ErrEmailRequired),
			errors.Is(err, users.ErrPasswordRequired),
			errors.Is(err, users.ErrInvalidEmail),
			errors.Is(err, users.ErrPasswordTooShort):
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			h.errorLog.Println("register error:", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	// user.ID is now populated from the RETURNING clause in the repository
	accessToken, refreshToken, err := h.tokenService.GenerateTokenPair(r.Context(), user.ID)
	if err != nil {
		h.errorLog.Println("generate token pair error:", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.infoLog.Printf("user registered: %s", user.Email)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// Login handler
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid input", http.StatusBadRequest)
		return
	}

	// fetch user by email
	user, err := h.userService.GetByEmail(r.Context(), req.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// don't reveal whether email exists or not
			http.Error(w, "invalid email or password", http.StatusUnauthorized)
			return
		}
		h.errorLog.Println("login fetch user error:", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// verify password
	if err := users.VerifyPassword(user.Password, req.Password); err != nil {
		http.Error(w, "invalid email or password", http.StatusUnauthorized)
		return
	}

	// generate token pair
	accessToken, refreshToken, err := h.tokenService.GenerateTokenPair(r.Context(), user.ID)
	if err != nil {
		h.errorLog.Println("generate token pair error:", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.infoLog.Printf("user logged in: %s", user.Email)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// Refresh handler
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid input", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		http.Error(w, "refresh token is required", http.StatusBadRequest)
		return
	}

	accessToken, refreshToken, err := h.tokenService.RefreshTokens(r.Context(), req.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, tokens.ErrTokenNotFound):
			http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		case errors.Is(err, tokens.ErrExpiredToken):
			http.Error(w, "refresh token has expired", http.StatusUnauthorized)
		default:
			h.errorLog.Println("refresh token error:", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// Logout handler
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req LogoutRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid input", http.StatusBadRequest)
		return
	}

	if err := h.tokenService.Logout(r.Context(), req.UserID); err != nil {
		h.errorLog.Println("logout error:", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "logged out successfully",
	})
}
