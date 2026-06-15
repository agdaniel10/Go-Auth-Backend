package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
)

type PasswordServiceHandler interface {
	ForgotPassword(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	ResetPasswordAuthenticatedUsers(ctx context.Context, password, token, newPassword string) error
}

type PasswordHandler struct {
	service  PasswordServiceHandler
	errorLog *log.Logger
	infoLog  *log.Logger
}

func NewPasswordHandler(service PasswordServiceHandler, errorLog *log.Logger, infoLog *log.Logger) *PasswordHandler {
	return &PasswordHandler{
		service:  service,
		errorLog: errorLog,
		infoLog:  infoLog,
	}
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

type ResetPasswordAuthRequest struct {
	Token       string `json:"token"`
	Password    string `json:"Password"`
	NewPassword string `json:"newPassword"`
}

type ForgotPasswordResponse struct {
	Message string `json:"message"`
}

type ResetPasswordResponse struct {
	Message string `json:"message"`
}

func (h *PasswordHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid input", http.StatusBadRequest)
		return
	}

	if err := h.service.ForgotPassword(r.Context(), req.Email); err != nil {
		http.Error(w, "error sending reset token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(ForgotPasswordResponse{
		Message: "Reset token sent successfully",
	})

}

func (h *PasswordHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid input", http.StatusBadRequest)
		return
	}

	if len(req.NewPassword) < 8 {
		http.Error(w, "invalid password, password not long enough", http.StatusBadRequest)
		return
	}

	if req.Token == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	err := h.service.ResetPassword(r.Context(), req.Token, req.NewPassword)
	if err != nil {
		http.Error(w, "error resetting user password", http.StatusInternalServerError)
		h.errorLog.Println(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(ResetPasswordResponse{
		Message: "Password reset successful",
	})

}

func (h *PasswordHandler) ResetPasswordAuthenticatedUsers(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordAuthRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
	}

	if len(req.Password) < 8 || len(req.NewPassword) < 8 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if req.Token == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	err := h.service.ResetPasswordAuthenticatedUsers(r.Context(), req.Password, req.Token, req.NewPassword)
	if err != nil {
		http.Error(w, "error resetting user password", http.StatusInternalServerError)
		h.errorLog.Println(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(ResetPasswordResponse{
		Message: "Password reset successful",
	})

}
