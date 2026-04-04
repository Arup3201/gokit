package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/Arup3201/gokit/auth"
	"github.com/Arup3201/gokit/middlewares"
)

var (
	ApiUrl               = "http://localhost:8080/api"
	ResetPasswordPageUrl = "http://localhost:5173/reset-password"
)

type Registerer interface {
	Register(ctx context.Context,
		email, fullName, password string) (uint, error)
}

type Emailer interface {
	SendVerificationEmail(ctx context.Context,
		serverUrl string,
		userId, email, fullName string) error
	VerifyEmail(ctx context.Context, token string) error
}

type PasswordResetter interface {
	SendPasswordResetEmail(ctx context.Context,
		destinationPageUrl string,
		email string) error
	ResetPassword(ctx context.Context,
		token, password string) error
}

type Authenticator interface {
	Login(ctx context.Context,
		email, password string) (*auth.ShortSessionDetail, error)
	Logout(ctx context.Context,
		sessionId string) error
}

type authController struct {
	registerer       Registerer
	emailer          Emailer
	passwordResetter PasswordResetter
	authenticator    Authenticator
}

func NewAuthController(registerer Registerer,
	emailer Emailer,
	resetter PasswordResetter,
	auth Authenticator) *authController {
	return &authController{
		registerer:       registerer,
		emailer:          emailer,
		passwordResetter: resetter,
		authenticator:    auth,
	}
}

func (c *authController) Register(w http.ResponseWriter, r *http.Request) {

	type registerData struct {
		Email    string `json:"email"`
		FullName string `json:"full_name"`
		Password string `json:"password"`
	}

	var data registerData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		log.Printf("[ERROR] json decode payload: %s\n", err)

		http.Error(w,
			"Error while parsing payload. Payload accepts email, full_name and password",
			http.StatusBadRequest)
		return
	}

	id, err := c.registerer.Register(r.Context(), data.Email, data.FullName, data.Password)
	if err != nil {
		log.Printf("[ERROR] authentication service register: %s\n", err)

		http.Error(w,
			"Registration failed. Make sure email is valid, full name and password is not empty",
			http.StatusInternalServerError)
		return
	}

	err = c.emailer.SendVerificationEmail(r.Context(),
		ApiUrl,
		strconv.Itoa(int(id)),
		data.Email,
		data.FullName)
	if err != nil {
		log.Printf("[ERROR] email service send verification email: %s\n", err)

		http.Error(w,
			"Failed to send verification email to the email",
			http.StatusInternalServerError)
		return
	}

	responseBody := map[string]any{
		"id":      id,
		"message": "User has registered successfully",
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(responseBody)
}

func (c *authController) VerifyEmail(w http.ResponseWriter, r *http.Request) {

	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w,
			"Empty token not allowed",
			http.StatusBadRequest)
		return
	}

	err := c.emailer.VerifyEmail(r.Context(), token)
	if err != nil {
		log.Printf("[ERROR] verify email: %s\n", err)

		http.Error(w,
			"Failed to verify email",
			http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "http://localhost:5173", http.StatusSeeOther)
}

func (c *authController) Login(w http.ResponseWriter, r *http.Request) {

	type loginData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var data loginData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		log.Printf("[ERROR] json decode payload: %s\n", err)

		http.Error(w,
			"Error while parsing payload. Payload accepts email and password",
			http.StatusBadRequest)
		return
	}

	session, err := c.authenticator.Login(r.Context(), data.Email, data.Password)
	if err != nil {
		log.Printf("[ERROR] auth service login: %s\n", err)

		http.Error(w,
			"Encountered error while logging in. Please try again with correct credentials.",
			http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name:     middlewares.SessionCookieName,
		Value:    session.ID,
		Expires:  session.ExpiresAt,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)

	responseBody := map[string]any{
		"message": "Logged in successfully",
	}
	json.NewEncoder(w).Encode(responseBody)
}

func (c *authController) PasswordResetEmail(w http.ResponseWriter, r *http.Request) {

	type forgotPasswordReq struct {
		Email string `json:"email"`
	}

	var data forgotPasswordReq
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		log.Printf("[ERROR] json decode payload: %s\n", err)

		http.Error(w,
			"Error while parsing payload. Payload accepts only email",
			http.StatusBadRequest)
		return
	}

	err := c.passwordResetter.SendPasswordResetEmail(r.Context(), ResetPasswordPageUrl, data.Email)
	if err != nil {
		log.Printf("[ERROR] auth service login: %s\n", err)

		http.Error(w,
			"Encountered error while sending password reset email. Please try again with valid email.",
			http.StatusInternalServerError)
		return
	}

	responseBody := map[string]any{
		"message": "Reset password email has been sent to the email address",
	}
	json.NewEncoder(w).Encode(responseBody)
}

func (c *authController) ResetPassword(w http.ResponseWriter, r *http.Request) {

	type resetPasswordReq struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}

	var data resetPasswordReq
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		log.Printf("[ERROR] json decode payload: %s\n", err)

		http.Error(w,
			"Error while parsing payload. Payload accepts token and password",
			http.StatusBadRequest)
		return
	}

	err := c.passwordResetter.ResetPassword(r.Context(), data.Token, data.Password)
	if err != nil {
		log.Printf("[ERROR] auth service reset password: %s\n", err)

		http.Error(w,
			"Encountered error while resetting password.",
			http.StatusInternalServerError)
		return
	}

	responseBody := map[string]any{
		"message": "Password reset successful",
	}
	json.NewEncoder(w).Encode(responseBody)
}

func (c *authController) Logout(w http.ResponseWriter, r *http.Request) {

	var cookies = r.Cookies()

	sInd := slices.IndexFunc(cookies, func(c *http.Cookie) bool {
		return c.Name == middlewares.SessionCookieName
	})
	if sInd == -1 {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	sessionId := cookies[sInd].Value
	err := c.authenticator.Logout(r.Context(), sessionId)
	if err != nil {
		log.Printf("[ERROR] auth service logout: %s\n", err)

		http.Error(w,
			"Encountered error while logout.",
			http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name:     middlewares.SessionCookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)

	responseBody := map[string]any{
		"message": "Logged out successfully",
	}
	json.NewEncoder(w).Encode(responseBody)

}

func (c *authController) Welcome(w http.ResponseWriter, r *http.Request) {

	_, ok := middlewares.FromContext(r.Context())
	if !ok {
		http.Error(w, "Error extracting user data", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Welcome to the site",
	})
}
