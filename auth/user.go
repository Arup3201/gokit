package auth

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Email         string `gorm:"unique;not null"`
	FullName      string
	Password      string
	EmailVerified bool
}
