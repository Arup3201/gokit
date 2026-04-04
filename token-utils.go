package gokit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func GetRandomToken(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("rand read: %w", err)
	}

	token := base64.URLEncoding.EncodeToString(b)

	return token, nil
}

func GetTokenSHA(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	tokenSHA := hex.EncodeToString(h.Sum(nil))

	return tokenSHA
}
