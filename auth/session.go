package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	SESSION_DURATION_DEFAULT = 15 * time.Minute
)

var (
	SessionDuration = SESSION_DURATION_DEFAULT
)

type Session struct {
	ID        string `gorm:"primaryKey"`
	UserId    uint   `gorm:"index"`
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

type sessionService struct {
	db *gorm.DB
}

func NewSessionService(db *gorm.DB) *sessionService {
	return &sessionService{
		db: db,
	}
}

type shortSessionDetail struct {
	ID        string
	ExpiresAt time.Time
}

func (s *sessionService) Login(ctx context.Context,
	email, password string) (*shortSessionDetail, error) {

	user, err := gorm.G[User](s.db).Where("email = ?", email).First(ctx)
	if err != nil {
		switch err {
		case gorm.ErrRecordNotFound:
			return nil, fmt.Errorf("email not found")
		default:
			return nil, fmt.Errorf("sql where first: %w", err)
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, fmt.Errorf("password mismatch")
	}

	if !user.EmailVerified {
		return nil, fmt.Errorf("email verification pending")
	}

	var sessionId string
	sessionId = uuid.NewString()

	session := Session{
		ID:        sessionId,
		UserId:    user.ID,
		ExpiresAt: time.Now().Add(SessionDuration).UTC(),
	}

	err = gorm.G[Session](s.db).Create(ctx, &session)
	if err != nil {
		return nil, fmt.Errorf("session create: %w", err)
	}

	return &shortSessionDetail{
		ID:        sessionId,
		ExpiresAt: session.ExpiresAt,
	}, nil
}

func (s *sessionService) Logout(ctx context.Context,
	sessionId string) error {

	session, err := gorm.G[Session](s.db).
		Where("id = ? AND revoked_at IS NULL AND expires_at >= ?",
			sessionId, time.Now().UTC()).
		First(ctx)
	if err != nil {
		switch err {
		case gorm.ErrRecordNotFound:
			return fmt.Errorf("session not found")
		default:
			return fmt.Errorf("gorm session where clause: %w", err)
		}
	}

	now := time.Now().UTC()
	session.RevokedAt = &now
	s.db.Save(&session)

	return nil
}

func (s *sessionService) GetUserIdFromSession(ctx context.Context, id string) (uint, error) {
	var err error
	var session Session

	session, err = gorm.G[Session](s.db).
		Where("id = ? AND revoked_at IS NULL AND expires_at >= ?",
			id, time.Now().UTC()).
		First(ctx)
	if err != nil {
		switch err {
		case gorm.ErrRecordNotFound:
			return 0, fmt.Errorf("session not found")
		default:
			return 0, fmt.Errorf("gorm session where clause: %w", err)
		}
	}

	return session.UserId, nil
}
