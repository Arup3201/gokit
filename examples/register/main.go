package main

import (
	"context"
	"fmt"
	"log"

	"github.com/Arup3201/gokit/auth"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email         string `gorm:"unique;not null"`
	FullName      string
	Password      string
	EmailVerified bool
}

type repo struct {
	db *gorm.DB
}

func (r *repo) Create(ctx context.Context,
	email, fullName, hashedPassword string) (any, error) {
	user := User{
		Email:         email,
		FullName:      fullName,
		Password:      hashedPassword,
		EmailVerified: false,
	}
	err := gorm.G[User](r.db).Create(ctx, &user)
	if err != nil {
		return nil, fmt.Errorf("gorm user create: %w", err)
	}

	return user.ID, nil
}

func main() {
	var err error
	var db *gorm.DB

	db, err = gorm.Open(sqlite.Open("test.db"), &gorm.Config{
		TranslateError: true,
	})
	if err != nil {
		log.Fatalf("gorm open failed with error: %s\n", err)
	}

	db.AutoMigrate(&User{})

	ctx := context.Background()

	var id any
	registerer := auth.NewRegisterService(14, &repo{db: db})
	id, err = registerer.Register(ctx, "arupjana@example.com", "Arup Jana", "1234")
	if err != nil {
		log.Fatalf("register failed: %s\n", err)
	}

	log.Printf("Registered user with ID: %d\n", id.(uint))
}
