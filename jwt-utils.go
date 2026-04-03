package gokit

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	JWT_ALG_ECDSA   = "ECDSA"
	JWT_ALG_ED25519 = "ED25519"
	JWT_ALG_HMAC    = "HMAC"
	JWT_ALG_RSA     = "RSA"
)

type JWTClaims struct {
	Jti       string    `json:"jti"`
	Issuer    string    `json:"iss"`
	UserId    string    `json:"user_id"`
	Subject   string    `json:"sub"`
	NotBefore time.Time `json:"nbf"`
	IssuedAt  time.Time `json:"iat"`
	Expiry    time.Time `json:"exp"`
}

func NewClaims(iss, sub, userId string, exp time.Time) *JWTClaims {
	now := time.Now().UTC()
	jti := uuid.NewString()

	return &JWTClaims{
		Jti:       jti,
		Issuer:    iss,
		Subject:   sub,
		UserId:    userId,
		IssuedAt:  now,
		NotBefore: now,
		Expiry:    exp,
	}
}

func ClaimsFromToken(tokenString string, key any) (*JWTClaims, error) {

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (any, error) {
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("jwt parse with claims: %w", err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("token claims is of invalid type, need &CustomClaims")
	}

	jwtClaims := JWTClaims{
		Jti:       claims.Jti,
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		UserId:    claims.UserId,
		IssuedAt:  claims.IssuedAt.Time,
		NotBefore: claims.NotBefore.Time,
		Expiry:    claims.ExpiresAt.Time,
	}

	return &jwtClaims, nil
}

type CustomClaims struct {
	Jti    string `json:"jti"`
	UserId string `json:"user_id"`
	jwt.RegisteredClaims
}

type JWT struct {
	Claims *JWTClaims
	Alg    jwt.SigningMethod
}

func JWTFromClaims(claims *JWTClaims,
	alg string) (*JWT, error) {

	obj := JWT{
		Claims: claims,
	}

	switch alg {
	case JWT_ALG_ECDSA:
		obj.Alg = jwt.SigningMethodES256
	case JWT_ALG_ED25519:
		obj.Alg = jwt.SigningMethodEdDSA
	case JWT_ALG_HMAC:
		obj.Alg = jwt.SigningMethodHS256
	case JWT_ALG_RSA:
		obj.Alg = jwt.SigningMethodRS256
	default:
		return nil, errors.New("invalid jwt algorithm")
	}

	return &obj, nil
}

func (t *JWT) Sign(key any) (string, error) {

	claims := CustomClaims{
		Jti:    t.Claims.Jti,
		UserId: t.Claims.UserId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(t.Claims.Expiry),
			IssuedAt:  jwt.NewNumericDate(t.Claims.IssuedAt),
			NotBefore: jwt.NewNumericDate(t.Claims.NotBefore),
			Issuer:    t.Claims.Issuer,
			Subject:   t.Claims.Subject,
		},
	}
	token := jwt.NewWithClaims(t.Alg, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("jwt signed string: %w", err)
	}

	return signed, nil
}
