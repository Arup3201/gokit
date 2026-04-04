package auth

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Arup3201/gokit"
	"github.com/resend/resend-go/v3"
	"gorm.io/gorm"
)

type EmailVerification struct {
	UserId      string
	HashedToken string `gorm:"primaryKey"`
	ExpiresAt   time.Time
	UsedAt      *time.Time
	CreatedAt   time.Time
}

type emailService struct {
	client *resend.Client
	db     *gorm.DB
}

/*
Email Service to manage email address verification after registration.

It will send email for email address verification and verify user email address.

It takes:

apiKey: Resend client API key

db: gorm db connection
*/
func NewEmailService(apiKey string, db *gorm.DB) *emailService {

	client := resend.NewClient(apiKey)

	return &emailService{
		client: client,
		db:     db,
	}
}

/*
Send the verification email to the email address used during registration.

Email contains a link that has token which has duration equal to
VERIFICATION_TOKEN_DURATION_DEFAULT. If you want to change it, set the
VerificationTokenDuration value.

The email is sent with Resend API client.

serverUrl: root URL for API
e.g. http://localhost:8080, http://localhost:8080/api, http://localhost:8080/api/v1
*/
func (s *emailService) SendVerificationEmail(ctx context.Context,
	serverUrl string,
	userId, email, fullName string) error {

	token, err := gokit.GetRandomToken(32)
	if err != nil {
		return fmt.Errorf("get hashed token: %w", err)
	}

	tokenSHA := gokit.GetTokenSHA(token)
	ev := EmailVerification{
		UserId:      userId,
		HashedToken: tokenSHA,
		ExpiresAt:   time.Now().Add(VerificationTokenDuration),
	}
	err = gorm.G[EmailVerification](s.db).Create(ctx, &ev)
	if err != nil {
		return fmt.Errorf("gorm create: %w", err)
	}

	verificationLink := fmt.Sprintf("%s/verify-email?token=%s", serverUrl, token)
	html := fmt.Sprintf("Hello %s, Here is your email verification link: \n<a href='%s'>Click to verify</a>\n", fullName, verificationLink)

	params := &resend.SendEmailRequest{
		From:    "Arup <hello@contact.itsdeployedbyme.dpdns.org>",
		To:      []string{email},
		Html:    html,
		Subject: "Email verification",
		ReplyTo: "hello@contact.itsdeployedbyme.dpdns.org",
	}

	sent, err := s.client.Emails.Send(params)
	if err != nil {
		return fmt.Errorf("email client send: %w", err)
	}

	log.Printf("[INFO] Email sent: %s\n", sent.Id)

	return nil
}

/*
Function to verify registered user email address when user clicks
on the link in verification email.

It takes the token from verification email link.

The function will mark the user as verified.
*/
func (s *emailService) VerifyEmail(ctx context.Context, token string) error {

	tokenSHA := gokit.GetTokenSHA(token)
	now := time.Now().UTC()

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		ev, err := gorm.G[EmailVerification](tx).
			Where("hashed_token = ? AND used_at IS NULL AND expires_at >= ?",
				tokenSHA, now).
			First(ctx)
		if err != nil {
			return fmt.Errorf("gorm find hashed token: %w", err)
		}

		ev.UsedAt = &now
		if err := tx.Save(&ev).Error; err != nil {
			return fmt.Errorf("email verification used at update: %w", err)
		}

		user, err := gorm.G[User](tx).Where("id = ?", ev.UserId).First(ctx)
		if err != nil {
			return fmt.Errorf("gorm find user with id: %w", err)
		}

		user.EmailVerified = true
		if err := tx.Save(&user).Error; err != nil {
			return fmt.Errorf("user mark email verified update: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("gorm transaction: %w", err)
	}

	return nil
}
