package auth

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var emailRegex, _ = regexp.Compile(
	`^[a-zA-Z0-9]+([._-][0-9a-zA-Z]+)*@[a-zA-Z0-9]+([.-][0-9a-zA-Z]+)*\.[a-zA-Z]{2,}$`,
)

type UserCreator interface {
	/*
		Create user with email, full name and hashed password

		Ideally, the function will save the user with email, full name and hashed password in the database.

		It returns the ID of the user created.
		The type of the ID is any.

		In case of a problem, it should return non-nil error.
	*/
	Create(context.Context, string, string, string) (any, error)
}

type registerService struct {
	bcryptPasswordCost int
	userCreator        UserCreator
}

func NewRegisterService(bcryptPasswordCost int,
	creator UserCreator) *registerService {
	return &registerService{
		bcryptPasswordCost: bcryptPasswordCost,
		userCreator:        creator,
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
	email, fullName, password string) (any, error) {
	var err error

	if match := emailRegex.Find([]byte(email)); match == nil {
		return nil, fmt.Errorf("email address is invalid")
	}

	if strings.Trim(fullName, " ") == "" {
		return nil, fmt.Errorf("full name cannot be empty")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password),
		s.bcryptPasswordCost)
	if err != nil {
		return nil, fmt.Errorf("bcrypt generate from password: %w", err)
	}

	var id any
	id, err = s.userCreator.Create(ctx, email, fullName, string(hashedPassword))
	if err != nil {
		return nil, fmt.Errorf("user create: %w", err)
	}

	return id, nil
}
