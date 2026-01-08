package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"template-golang-2025/internal/dto"
	"template-golang-2025/internal/pkg/serverutils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func (m *MockAuthService) Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.LoginResponse), args.Error(1)
}

func TestAuthController_Login(t *testing.T) {
	// Helper untuk setup router bisa disesuaikan dengan codebase Anda
	setup := func() (*MockAuthService, *gin.Engine) {
		mockService := new(MockAuthService)
		r := setupRouter(mockService) // Pastikan ini mengarah ke c.Login
		return mockService, r
	}

	t.Run("1. Success Login", func(t *testing.T) {
		mockService, r := setup()

		userID := uuid.New()
		expectedRes := &dto.LoginResponse{
			User: dto.UserIdentity{
				Id:    userID,
				Name:  "John Doe",
				Email: "john@test.com",
			},
			Token: dto.Token{
				AccessToken:  "valid-access-token",
				RefreshToken: "valid-refresh-token",
				ExpiresIn:    900,
			},
		}

		mockService.On("Login", mock.Anything, mock.MatchedBy(func(req *dto.LoginRequest) bool {
			return req.Email == "john@test.com" && req.Password == "password123"
		})).Return(expectedRes, nil)

		body := dto.LoginRequest{
			Email:    "john@test.com",
			Password: "password123",
		}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "Success Registration") // Sesuai label di Controller Anda
		assert.Contains(t, w.Body.String(), "valid-access-token")
	})

	t.Run("2. Validation Error - Invalid Email Format", func(t *testing.T) {
		mockService, r := setup()

		body := dto.LoginRequest{
			Email:    "bukan-email",
			Password: "password123",
		}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertNotCalled(t, "Login", mock.Anything, mock.Anything)
	})

	t.Run("3. Unauthorized - Wrong Credentials", func(t *testing.T) {
		mockService, r := setup()

		// Simulasi email/password salah
		mockService.On("Login", mock.Anything, mock.Anything).
			Return(nil, serverutils.ErrInvalidCredentials)

		body := dto.LoginRequest{
			Email:    "wrong@test.com",
			Password: "wrongpassword",
		}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
		r.ServeHTTP(w, req)

		// Pastikan status code sesuai (biasanya 401 Unauthorized)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("4. Bad JSON Body", func(t *testing.T) {
		_, r := setup()

		badJson := []byte(`{"email": "test@test.com", "password": "missing-bracket"`)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(badJson))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("5. Internal Server Error", func(t *testing.T) {
		mockService, r := setup()

		mockService.On("Login", mock.Anything, mock.Anything).
			Return(nil, errors.New("unexpected database error"))

		body := dto.LoginRequest{
			Email:    "admin@test.com",
			Password: "password123",
		}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
