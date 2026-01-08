package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"template-golang-2025/internal/auth"
	"template-golang-2025/internal/dto"
	"template-golang-2025/internal/pkg/serverutils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// --- MOCK SERVICE ---
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(ctx context.Context, req *dto.RegisterRequest) (*dto.RegisterResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.RegisterResponse), args.Error(1)
}

// Helper untuk setup router agar tidak redundan
func setupRouter(s auth.IAuthService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// Wajib pasang middleware agar ctx.Error(err) diproses
	r.Use(serverutils.ErrorHandlerMiddlewareGin())

	controller := auth.NewAuthController(s)
	// Kita gunakan group yang sama dengan main.go agar path-nya konsisten
	api := r.Group("/api")
	controller.RegisterRoutes(api)
	return r
}

func TestAuthController_Register_Comprehensive(t *testing.T) {

	t.Run("1. Success Registration", func(t *testing.T) {
		mockService := new(MockAuthService)
		r := setupRouter(mockService)

		userID := uuid.New()
		expectedRes := &dto.RegisterResponse{
			User:  dto.UserIdentity{Id: userID, Name: "John Doe", Email: "john@test.com"},
			Token: dto.Token{AccessToken: "at", RefreshToken: "rt"},
		}

		mockService.On("Register", mock.Anything, mock.Anything).Return(expectedRes, nil)

		body := dto.RegisterRequest{Name: "John Doe", Email: "john@test.com", Password: "password123"}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(jsonBody))
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "Success Registration")
	})

	t.Run("2. Validation Error - Invalid Email Format", func(t *testing.T) {
		mockService := new(MockAuthService)
		r := setupRouter(mockService)

		body := dto.RegisterRequest{Name: "John", Email: "bukan-email", Password: "password123"}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(jsonBody))
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertNotCalled(t, "Register", mock.Anything, mock.Anything)
	})

	t.Run("3. Validation Error - Missing Field", func(t *testing.T) {
		mockService := new(MockAuthService)
		r := setupRouter(mockService)

		// Password kosong
		body := dto.RegisterRequest{Name: "John", Email: "john@test.com", Password: ""}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(jsonBody))
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("4. Bad JSON Body", func(t *testing.T) {
		mockService := new(MockAuthService)
		r := setupRouter(mockService)

		// JSON rusak (kurang tutup kurung)
		badJson := []byte(`{"name": "john", "email": "test@test.com"`)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(badJson))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("5. Service Error - Email Already Exists", func(t *testing.T) {
		mockService := new(MockAuthService)
		r := setupRouter(mockService)

		mockService.On("Register", mock.Anything, mock.Anything).
			Return(nil, serverutils.ErrEmailAlreadyExists)

		body := dto.RegisterRequest{Name: "John", Email: "exists@test.com", Password: "password123"}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(jsonBody))
		r.ServeHTTP(w, req)

		// Ini akan sesuai dengan mapping di ErrorHandlerMiddlewareGin Anda
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "email already registered")
	})

	t.Run("6. Service Error - Unexpected Internal Error", func(t *testing.T) {
		mockService := new(MockAuthService)
		r := setupRouter(mockService)

		// Simulasi database down atau error lainnya
		mockService.On("Register", mock.Anything, mock.Anything).
			Return(nil, errors.New("database connection failed"))

		body := dto.RegisterRequest{Name: "John", Email: "error@test.com", Password: "password123"}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(jsonBody))
		r.ServeHTTP(w, req)

		// Biasanya error yang tidak terdefinisi masuk ke 500 Internal Server Error
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
