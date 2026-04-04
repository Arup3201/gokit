package main

import (
	"context"
	"log"

	"github.com/Arup3201/gokit/auth"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	var err error
	var db *gorm.DB

	db, err = gorm.Open(sqlite.Open("test.db"), &gorm.Config{
		TranslateError: true,
	})
	if err != nil {
		log.Fatalf("gorm open failed with error: %s\n", err)
	}

	db.AutoMigrate(&auth.User{})
	db.AutoMigrate(&auth.Session{})

	ctx := context.Background()

	var id any
	registerer := auth.NewRegisterService(db)
	id, err = registerer.Register(ctx, "arupjana@example.com", "Arup Jana", "1234")
	if err != nil {
		log.Fatalf("register failed: %s\n", err)
	}

	log.Printf("Registered user with ID: %d\n", id)
}
