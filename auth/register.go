package auth

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var emailRegex, _ = regexp.Compile(
	`^[a-zA-Z0-9]+([._-][0-9a-zA-Z]+)*@[a-zA-Z0-9]+([.-][0-9a-zA-Z]+)*\.[a-zA-Z]{2,}$`,
)

type registerService struct {
	bcryptPasswordCost int
	db                 *gorm.DB
}

func NewRegisterService(bcryptPasswordCost int,
	db *gorm.DB) *registerService {
	return &registerService{
		bcryptPasswordCost: bcryptPasswordCost,
		db:                 db,
	}
}

/*
Function to register user

User needs to follow the rules.
1. Email should be valid.
2. Full name should not be empty.

Password is hashed using bcrypt before saving.
The function returns the ID of the user created. The type is any.
You need to convert the type to the correct one based on the implementation
of the Create function of the UserCreator interface type.

In case of any problem, it returns non-nil error.
*/
func (s *registerService) Register(ctx context.Context,
	email, fullName, password string) (uint, error) {
	var err error

	if match := emailRegex.Find([]byte(email)); match == nil {
		return 0, fmt.Errorf("email address is invalid")
	}

	if strings.Trim(fullName, " ") == "" {
		return 0, fmt.Errorf("full name cannot be empty")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password),
		s.bcryptPasswordCost)
	if err != nil {
		return 0, fmt.Errorf("bcrypt generate from password: %w", err)
	}

	user := User{
		Email:         email,
		FullName:      fullName,
		Password:      string(hashedPassword),
		EmailVerified: false,
	}

	err = gorm.G[User](s.db).Create(ctx, &user)
	if err != nil {
		return 0, fmt.Errorf("create user: %w", err)
	}

	return user.ID, nil
}
