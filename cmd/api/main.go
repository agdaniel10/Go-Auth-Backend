package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"go-auth-backend/config"
	"go-auth-backend/internal/emailverificationtoken"
	"go-auth-backend/internal/handlers"
	"go-auth-backend/internal/limiter"
	"go-auth-backend/internal/middleware"
	"go-auth-backend/internal/passwordreset"
	"go-auth-backend/internal/tokens"
	"go-auth-backend/internal/users"

	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("no .env file found, reading from environment")
	}

	secretKey := os.Getenv("JWT_SECRET")

	// Loggers
	infoLog := log.New(os.Stdout, "INFO\t", log.Ltime)
	errorLog := log.New(os.Stderr, "ERROR\t", log.Ltime|log.Lshortfile)

	// Database
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		errorLog.Fatal("DATABASE_URL is not set")
	}

	if secretKey == "" {
		errorLog.Fatal("JWT_SECRET is not set")
	}

	if len(secretKey) < 30 {
		errorLog.Fatal("JWT_SECRET is too short")
	}

	db, err := config.ConnectDB(dsn)
	if err != nil {
		errorLog.Fatal("failed to connect to database:", err)
	}
	defer db.Close()
	infoLog.Println("database connected")

	// Repositories
	userRepo := users.NewSQLUserRepository(db)
	tokenRepo := tokens.NewSQLTokenRepository(db)
	passwordresetRepo := passwordreset.NewPasswordResetRepository(db)
	emailverificationtokenrepo := emailverificationtoken.NewSQLEmailVerificationTokenRepo(db)

	// Services
	emailService := emailverificationtoken.NewEmailVerificationService(emailverificationtokenrepo, userRepo)
	userService := users.NewUserService(userRepo, *emailService)
	tokenService := tokens.NewTokenService(tokenRepo, secretKey)
	passwordresetService := passwordreset.NewPasswordService(passwordresetRepo, *userService, tokenService)

	// Handlers
	userHandler := handlers.NewUserHandler(userService, infoLog, errorLog)
	authHandler := handlers.NewAuthHandler(userService, tokenService, emailService, errorLog, infoLog)
	passwordResetHandler := handlers.NewPasswordHandler(passwordresetService, errorLog, infoLog)

	// Clean up for old refresh and password reset tokens
	go func() {
		for {
			time.Sleep(24 * time.Hour)
			tokenRepo.DeleteExpired(context.Background())
			passwordresetRepo.DeleteExpiredPasswordTokens(context.Background())
		}
	}()

	// Routes
	mux := http.NewServeMux()
	auth := middleware.RequireAuth(tokenService)

	// Public routes — no middleware
	mux.Handle("POST /auth/register", limiter.RateLimiterMiddleware(
		http.HandlerFunc(authHandler.Register), 2, 4,
	))
	mux.Handle("POST /auth/login", limiter.RateLimiterMiddleware(
		http.HandlerFunc(authHandler.Login), 2, 4,
	))

	mux.Handle("POST /auth/refresh", limiter.RateLimiterMiddleware(
		http.HandlerFunc(authHandler.Refresh), 2, 4,
	))

	mux.Handle("POST /auth/logout", limiter.RateLimiterMiddleware(
		http.HandlerFunc(authHandler.Logout), 2, 4,
	))

	mux.Handle("POST /users/forgot-password", limiter.RateLimiterMiddleware(
		http.HandlerFunc(passwordResetHandler.ForgotPassword), 2, 4,
	))

	mux.Handle("POST /users/reset-password", limiter.RateLimiterMiddleware(
		http.HandlerFunc(passwordResetHandler.ResetPassword), 2, 4,
	))

	mux.Handle("GET /verify-email", limiter.RateLimiterMiddleware(
		http.HandlerFunc(authHandler.VerifyEmail), 2, 5,
	))

	// Protected routes — wrapped with auth middleware
	mux.Handle("GET /users/me", auth(http.HandlerFunc(userHandler.GetMe)))
	mux.Handle("POST /users/logout", auth(http.HandlerFunc(authHandler.Logout)))
	mux.Handle("POST /users/logout-all", auth(http.HandlerFunc(authHandler.LogoutAll)))

	// Server
	port := os.Getenv("PORT")
	if port == "" {
		port = "4040"
	}

	infoLog.Printf("server starting on port %s", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), mux); err != nil {
		errorLog.Fatal("server failed:", err)
	}
}
