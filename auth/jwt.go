package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strconv"
	"time"

	"github.com/Arup3201/gokit"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	ACCESS_TOKEN_DURATION_DEFAULT  = 15 * time.Minute   // 15 minutes
	REFRESH_TOKEN_DURATION_DEFAULT = 7 * 24 * time.Hour // 7 days
)

var (
	AccessTokenDuration  = ACCESS_TOKEN_DURATION_DEFAULT
	RefreshTokenDuration = REFRESH_TOKEN_DURATION_DEFAULT
)

type RefreshToken struct {
	Jti       string `gorm:"primaryKey"`
	UserId    uint
	Revoked   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

type authWithJWT struct {
	db         *gorm.DB
	privateKey *rsa.PrivateKey
}

type accessAndRefreshToken struct {
	AccessToken, RefreshToken                   string
	AccessTokenExpiresAt, RefreshTokenExpiresAt time.Time
}

func (a *authWithJWT) Login(ctx context.Context,
	email, password string,
	tokenIssuer string) (*accessAndRefreshToken, error) {

	user, err := gorm.G[User](a.db).Where("email = ?", email).First(ctx)
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

	var subject, userId string
	var accessToken, refreshToken string
	var accessExpiry, refreshExpiry time.Time
	var jwt *gokit.JWT

	userId = strconv.Itoa(int(user.ID))
	subject = userId

	accessExpiry = time.Now().Add(AccessTokenDuration)
	accessClaims := gokit.NewClaims(tokenIssuer, subject, userId, accessExpiry)
	jwt, err = gokit.JWTFromClaims(accessClaims, gokit.JWT_ALG_RSA)
	if err != nil {
		return nil, fmt.Errorf("jwt from claims: %w", err)
	}

	accessToken, err = jwt.Sign(a.privateKey)
	if err != nil {
		return nil, fmt.Errorf("jwt sign: %w", err)
	}

	refreshExpiry = time.Now().Add(RefreshTokenDuration)
	refreshClaims := gokit.NewClaims(tokenIssuer, subject, userId, refreshExpiry)
	jwt, err = gokit.JWTFromClaims(refreshClaims, gokit.JWT_ALG_RSA)
	if err != nil {
		return nil, fmt.Errorf("jwt from claims: %w", err)
	}

	dbToken := RefreshToken{
		Jti:       refreshClaims.Jti,
		UserId:    user.ID,
		Revoked:   false,
		CreatedAt: refreshClaims.IssuedAt,
		UpdatedAt: refreshClaims.IssuedAt,
	}
	err = gorm.G[RefreshToken](a.db).Create(ctx, &dbToken)
	if err != nil {
		return nil, fmt.Errorf("db refresh token create: %w", err)
	}

	refreshToken, err = jwt.Sign(a.privateKey)
	if err != nil {
		return nil, fmt.Errorf("jwt sign: %w", err)
	}

	return &accessAndRefreshToken{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessExpiry,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshExpiry,
	}, nil
}

func (a *authWithJWT) Refresh(ctx context.Context,
	token, tokenIssuer string) (*accessAndRefreshToken, error) {

	var err error
	var claims *gokit.JWTClaims
	var dbToken RefreshToken

	claims, err = gokit.ClaimsFromToken(token, &a.privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("utils claims from token: %w", err)
	}

	dbToken, err = gorm.G[RefreshToken](a.db).Where("jti = ?",
		claims.Jti, false).First(ctx)

	if dbToken.Revoked {
		return nil, fmt.Errorf("token has been revoked")
	}

	var subject, userId string
	var accessToken, refreshToken string
	var accessExpiry, refreshExpiry time.Time
	var jwt *gokit.JWT

	subject = userId

	accessExpiry = time.Now().Add(AccessTokenDuration)
	accessClaims := gokit.NewClaims(tokenIssuer, subject, claims.UserId, accessExpiry)
	jwt, err = gokit.JWTFromClaims(accessClaims, gokit.JWT_ALG_RSA)
	if err != nil {
		return nil, fmt.Errorf("utils jwt from claims: %w", err)
	}

	accessToken, err = jwt.Sign(a.privateKey)
	if err != nil {
		return nil, fmt.Errorf("jwt sign: %w", err)
	}

	refreshExpiry = time.Now().Add(RefreshTokenDuration)
	refreshClaims := gokit.NewClaims(tokenIssuer, subject, claims.UserId, refreshExpiry)
	jwt, err = gokit.JWTFromClaims(refreshClaims, gokit.JWT_ALG_RSA)
	if err != nil {
		return nil, fmt.Errorf("utils jwt from claims: %w", err)
	}

	err = a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {

		dbToken.Revoked = true
		if err := tx.Save(&dbToken).Error; err != nil {
			return fmt.Errorf("revoke refresh token: %w", err)
		}

		userIdInt, _ := strconv.Atoi(claims.UserId)
		dbToken = RefreshToken{
			Jti:       refreshClaims.Jti,
			UserId:    uint(userIdInt),
			Revoked:   false,
			CreatedAt: refreshClaims.IssuedAt,
			UpdatedAt: refreshClaims.IssuedAt,
		}
		err = gorm.G[RefreshToken](tx).Create(ctx, &dbToken)
		if err != nil {
			return fmt.Errorf("refresh token create: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("token refresh transaction: %w", err)
	}

	refreshToken, err = jwt.Sign(a.privateKey)
	if err != nil {
		return nil, fmt.Errorf("jwt sign: %w", err)
	}

	return &accessAndRefreshToken{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessExpiry,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshExpiry,
	}, nil
}

func (a *authWithJWT) Logout(ctx context.Context, token string) error {

	var err error
	var claims *gokit.JWTClaims
	var dbToken RefreshToken

	claims, err = gokit.ClaimsFromToken(token, &a.privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("claims from token: %w", err)
	}

	dbToken, err = gorm.G[RefreshToken](a.db).Where("jti = ?",
		claims.Jti, false).First(ctx)

	if dbToken.Revoked {
		return fmt.Errorf("token has been revoked")
	}

	dbToken.Revoked = true
	a.db.Save(&dbToken)

	return nil
}
