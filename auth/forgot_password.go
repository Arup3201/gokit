package auth

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Arup3201/gokit"
	"github.com/resend/resend-go/v3"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	VERIFICATION_TOKEN_DURATION_DEFAULT = 15 * time.Minute
)

var (
	VerificationTokenDuration = VERIFICATION_TOKEN_DURATION_DEFAULT
)

type PasswordResetToken struct {
	UserId      uint
	HashedToken string `gorm:"primaryKey"`
	ExpiresAt   time.Time
	UsedAt      *time.Time
	CreatedAt   time.Time
}

type passwordService struct {
	client *resend.Client
	db     *gorm.DB
}

/*
Password Service to manage passwords for the registered users.

It can - send email for email address verification and forgot password, and
reset password (session and JWT both compatible).

It takes:

apiKey: Resend client API key

db: gorm db connection
*/
func NewPasswordService(apiKey string, db *gorm.DB) *passwordService {

	client := resend.NewClient(apiKey)

	return &passwordService{
		client: client,
		db:     db,
	}
}

/*
Send reset password email using Resend API client.

The function takes the destination page URL. This URL is the UI where
user can submit the new password. This function attaches an URL query
token at the end.

The UI page will send the new password along with this token to
reset the password.
*/
func (s *passwordService) SendPasswordResetEmail(ctx context.Context,
	destinationPageUrl string,
	email string) error {

	user, err := gorm.G[User](s.db).Where("email = ?", email).First(ctx)
	if err != nil {
		return fmt.Errorf("gorm find user with id: %w", err)
	}

	/* Invalidate active password reset tokens */
	resetTokens, err := gorm.G[PasswordResetToken](s.db).Where("user_id = ?", user.ID).Find(ctx)
	if err != nil {
		return fmt.Errorf("find previous active password reset tokens with user_id: %w", err)
	}
	for _, t := range resetTokens {
		t.ExpiresAt = time.Unix(0, 0)
		if err := s.db.Save(&t).Error; err != nil {
			return fmt.Errorf("expire password reset token: %w", err)
		}
	}

	token, err := gokit.GetRandomToken(32)
	if err != nil {
		return fmt.Errorf("generate hashed token: %w", err)
	}

	tokenSHA := gokit.GetTokenSHA(token)
	resetToken := PasswordResetToken{
		UserId:      user.ID,
		HashedToken: tokenSHA,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	err = gorm.G[PasswordResetToken](s.db).Create(ctx, &resetToken)
	if err != nil {
		return fmt.Errorf("password reset token create: %w", err)
	}

	resetLink := fmt.Sprintf("%s?token=%s", destinationPageUrl, token)
	html := fmt.Sprintf("Hello %s, Here is your password reset link: \n<a href='%s'>Click to reset password</a>\n", user.FullName, resetLink)

	params := &resend.SendEmailRequest{
		From:    "Arup <hello@contact.itsdeployedbyme.dpdns.org>",
		To:      []string{email},
		Html:    html,
		Subject: "Email verification",
		ReplyTo: "hello@contact.itsdeployedbyme.dpdns.org",
	}

	sent, err := s.client.Emails.Send(params)
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}

	log.Printf("[INFO] Reset password email sent: %s\n", sent.Id)

	return nil
}

/*
Function to reset password. Takes forgot password token and new password.

This service should be called when the user tries to submit new password.
*/
func (s *passwordService) ResetPassword(ctx context.Context,
	token, password string) error {

	tokenSHA := gokit.GetTokenSHA(token)
	now := time.Now().UTC()

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		rt, err := gorm.G[PasswordResetToken](tx).
			Where("hashed_token = ? AND used_at IS NULL AND expires_at >= ?",
				tokenSHA, now).
			First(ctx)
		if err != nil {
			return fmt.Errorf("find password reset token with token hash: %w", err)
		}

		rt.UsedAt = &now
		if err := tx.Save(&rt).Error; err != nil {
			return fmt.Errorf("mark password reset token as used: %w", err)
		}

		user, err := gorm.G[User](tx).Where("id = ?", rt.UserId).First(ctx)
		if err != nil {
			return fmt.Errorf("find user with id: %w", err)
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), PasswordCost)
		if err != nil {
			return fmt.Errorf("bcrypt generate from password: %w", err)
		}

		user.Password = string(hashedPassword)
		if err := tx.Save(&user).Error; err != nil {
			return fmt.Errorf("user password update: %w", err)
		}

		// revoke active refresh tokens

		var tokens []RefreshToken
		tokens, err = gorm.G[RefreshToken](s.db).Where("user_id = ? AND revoked = ?",
			user.ID, false).Find(ctx)
		if err := tx.Save(&user).Error; err != nil {
			return fmt.Errorf("get active refresh tokens: %w", err)
		}

		for _, t := range tokens {
			t.Revoked = true
			if err := tx.Save(&t).Error; err != nil {
				return fmt.Errorf("revoke refresh token: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("gorm transaction: %w", err)
	}

	return nil
}
