package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"go-auth-backend/internal/users"
)

type UserHandlerService interface {
	CreateUser(ctx context.Context, user *users.User) error
}

type UserHandler struct {
	service  UserHandlerService
	errorLog *log.Logger
	infoLog  *log.Logger
}

func NewUserHandler(service UserHandlerService, errorLog *log.Logger, infoLog *log.Logger) *UserHandler {
	return &UserHandler{
		service:  service,
		errorLog: errorLog,
		infoLog:  infoLog,
	}
}

type CreateUserResponse struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var user users.User

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "invalid input", http.StatusBadRequest)
		return
	}

	if err := h.service.CreateUser(r.Context(), &user); err != nil {
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
			h.errorLog.Println("create user error:", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	response := CreateUserResponse{
		ID:        user.ID,
		Name:      user.Name,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}
