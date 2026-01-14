package dto

import "github.com/google/uuid"

// Token

type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// Register
type RegisterRequest struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type UserIdentity struct {
	Id    uuid.UUID `json:"id"`
	Name  string    `json:"name"`
	Email string    `json:"email"`
}

type RegisterResponse struct {
	User  UserIdentity `json:"user"`
	Token Token        `json:"token"`
}

// Login
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	User  UserIdentity `json:"user"`
	Token Token        `json:"token"`
}

// Logout
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token validate:"required"`
}
