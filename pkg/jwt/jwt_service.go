package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTService interface {
	GenerateToken(userID uuid.UUID, nameUser string, emailUser string, roles []string, permissions []string, tokenType string) (string, error)
	ValidateToken(tokenString string) (*jwt.Token, error)
}

type jwtService struct {
	secretKey     string
	issuer        string
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

// Custom Claims
type JWTCustomClaims struct {
	UserID     uuid.UUID `json:"user_id"`
	Name       string
	Email      string
	Role       []string
	Permission []string
	Type       string `json:"type"` // "access" atau "refresh"
	jwt.RegisteredClaims
}

func NewJWTService(secret, issuer string) JWTService {
	return &jwtService{
		secretKey:     secret,
		issuer:        issuer,
		accessExpiry:  15 * time.Minute, // Sesuai alurmu: 900 detik
		refreshExpiry: 7 * 24 * time.Hour,
	}
}

func (s *jwtService) GenerateToken(userID uuid.UUID, nameUser string, emailUser string, roles []string, permissions []string, tokenType string) (string, error) {
	expiry := s.accessExpiry
	if tokenType == "refresh" {
		expiry = s.refreshExpiry
	}

	claims := &JWTCustomClaims{
		UserID:     userID,
		Name:       nameUser,
		Email:      emailUser,
		Role:       roles,
		Permission: permissions,
		Type:       tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.secretKey))
}

func (s *jwtService) ValidateToken(tokenString string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, &JWTCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.secretKey), nil
	})
}
