package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Arup3201/gokit/auth"
	"github.com/Arup3201/gokit/examples/session-auth-app/handlers"
	"github.com/Arup3201/gokit/middlewares"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	Host = "localhost"
	Port = "8080"
)

func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	var err error
	var db *gorm.DB

	db, err = gorm.Open(sqlite.Open("examples.db"), &gorm.Config{
		TranslateError: true,
	})
	if err != nil {
		log.Fatalf("gorm open failed with error: %s\n", err)
	}

	db.AutoMigrate(&auth.User{})
	db.AutoMigrate(&auth.EmailVerification{})
	db.AutoMigrate(&auth.PasswordResetToken{})
	db.AutoMigrate(&auth.Session{})

	RESEND_API_KEY := os.Getenv("RESEND_API_KEY")
	if RESEND_API_KEY == "" {
		log.Fatal("Missing RESEND_API_KEY\n")
	}

	registerService := auth.NewRegisterService(db)
	authService := auth.NewAuthWithSession(db)
	passwordService := auth.NewPasswordService(RESEND_API_KEY, db)
	emailService := auth.NewEmailService(RESEND_API_KEY, db)
	middleware := middlewares.NewSessionAuthenticator(authService)

	controller := handlers.NewAuthController(registerService,
		emailService,
		passwordService,
		authService)

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/register", controller.Register)
	mux.HandleFunc("GET /api/verify-email", controller.VerifyEmail)
	mux.HandleFunc("POST /api/login", controller.Login)
	mux.HandleFunc("POST /api/password-reset-link", controller.PasswordResetEmail)
	mux.HandleFunc("POST /api/reset-password", controller.ResetPassword)

	mux.Handle("POST /api/logout", middleware.WithSession(http.HandlerFunc(controller.Logout)))
	mux.Handle("GET /api/message", middleware.WithSession(http.HandlerFunc(controller.Welcome)))

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", Host, Port),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
		Handler:      CorsMiddleware(mux),
	}

	log.Printf("[INFO] Server starting at %s:%s\n", Host, Port)
	log.Fatal(server.ListenAndServe())
}
