package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"go-auth-backend/config"
	"go-auth-backend/internal/handlers"
	"go-auth-backend/internal/users"

	"github.com/joho/godotenv"

	"go-auth-backend/internal/tokens"
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

	db, err := config.ConnectDB(dsn)
	if err != nil {
		errorLog.Fatal("failed to connect to database:", err)
	}
	defer db.Close()
	infoLog.Println("database connected")

	// Repositories
	userRepo := users.NewSQLUserRepository(db)

	// Services
	userService := users.NewUserService(userRepo)

	// Handlers
	userHandler := handlers.NewUserHandler(userService, infoLog, errorLog)

	tokenRepo := tokens.NewSQLTokenRepository(db)
	tokenService := tokens.NewTokenService(tokenRepo, secretKey)

	// Routes
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", userHandler.CreateUser)

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
