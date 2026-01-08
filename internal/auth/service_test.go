package auth

import (
	"context"
	"errors"
	"template-golang-2025/internal/dto"
	"template-golang-2025/internal/entity"
	"template-golang-2025/internal/pkg/serverutils"
	user "template-golang-2025/internal/users"
	"template-golang-2025/pkg/database"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

type MockUserRepository struct {
	mock.Mock
}

type MockJWTService struct {
	mock.Mock
}

func TestAuthService_Register(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockJWT := new(MockJWTService) // Mock JWT yang kita buat sebelumnya

	// Kita panggil SERVICE ASLI, bukan mock
	service := NewAuthService(mockRepo, mockJWT)

	t.Run("1. Error Email Already Exists", func(t *testing.T) {
		email := "duplicate@example.com"
		req := &dto.RegisterRequest{
			Email:    email,
			Name:     "Test",
			Password: "password123",
		}

		// Simulasi: Repository menemukan user dengan email tersebut
		mockRepo.On("FindUserByEmail", mock.Anything, email).Return(&entity.Users{Id: uuid.New(), Email: email}, nil)

		res, err := service.Register(context.Background(), req)

		// ASSERTION: Di sini test akan FAIL jika Anda mengubah
		// logic return di service menjadi ErrInvalidCredentials
		assert.Nil(t, res)
		assert.ErrorIs(t, err, serverutils.ErrEmailAlreadyExists)

		mockRepo.AssertExpectations(t)
	})

	t.Run("2. Success Register & Hashing Check", func(t *testing.T) {
		mockRepo := new(MockUserRepository)
		mockJWT := new(MockJWTService)
		service := NewAuthService(mockRepo, mockJWT)

		req := &dto.RegisterRequest{
			Email:    "new@example.com",
			Name:     "New User",
			Password: "password123",
		}

		mockRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(nil, nil)
		mockRepo.On("CreateUser", mock.Anything, mock.Anything).Return(nil)

		// PERBAIKAN DI SINI:
		// Setup untuk pemanggilan ACCESS TOKEN
		mockJWT.On("GenerateToken",
			mock.AnythingOfType("uuid.UUID"), // Gunakan matcher tipe yang benar
			req.Name,
			req.Email,
			[]string{"user"},
			mock.Anything, // Gunakan mock.Anything untuk permissions agar tidak sensitif terhadap []string{""} atau []string{}
			"access",
		).Return("fake-access-token", nil)

		// Setup untuk pemanggilan REFRESH TOKEN
		mockJWT.On("GenerateToken",
			mock.AnythingOfType("uuid.UUID"),
			req.Name,
			req.Email,
			[]string{"user"},
			mock.Anything,
			"refresh",
		).Return("fake-refresh-token", nil)

		res, err := service.Register(context.Background(), req)

		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.Equal(t, "fake-access-token", res.Token.AccessToken)

		mockRepo.AssertExpectations(t)
		mockJWT.AssertExpectations(t)
	})

	t.Run("3. Error Database - Failed to Create User", func(t *testing.T) {
		mockRepo := new(MockUserRepository)
		mockJWT := new(MockJWTService)
		service := NewAuthService(mockRepo, mockJWT)

		req := &dto.RegisterRequest{
			Email:    "db-error@example.com",
			Name:     "DB Error User",
			Password: "password123",
		}

		// Simulasi email belum ada
		mockRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(nil, nil)

		// Simulasi database gagal menyimpan data (misal: koneksi terputus)
		mockRepo.On("CreateUser", mock.Anything, mock.Anything).
			Return(errors.New("database connection failed"))

		res, err := service.Register(context.Background(), req)

		// Assertion
		assert.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, "database connection failed", err.Error())

		mockRepo.AssertExpectations(t)
	})

	t.Run("4. Error JWT - Failed to Generate Access Token", func(t *testing.T) {
		mockRepo := new(MockUserRepository)
		mockJWT := new(MockJWTService)
		service := NewAuthService(mockRepo, mockJWT)

		req := &dto.RegisterRequest{
			Email:    "jwt-error@example.com",
			Name:     "JWT Error User",
			Password: "password123",
		}

		mockRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(nil, nil)
		mockRepo.On("CreateUser", mock.Anything, mock.Anything).Return(nil)

		// Simulasi library JWT gagal menandatangani token (misal: secret key bermasalah)
		mockJWT.On("GenerateToken", mock.Anything, req.Name, req.Email,
			[]string{"user"}, mock.Anything, "access").
			Return("", errors.New("jwt signing error"))

		res, err := service.Register(context.Background(), req)

		// Assertion
		assert.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "jwt signing error")

		mockRepo.AssertExpectations(t)
		mockJWT.AssertExpectations(t)
	})
}

func TestAuthService_Login(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockJWT := new(MockJWTService)
	service := NewAuthService(mockRepo, mockJWT)

	passwordPlain := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(passwordPlain), bcrypt.DefaultCost)
	userID := uuid.New()

	userInDB := &entity.Users{
		Id:         userID,
		Name:       "John Doe",
		Email:      "john@example.com",
		Password:   string(hashedPassword),
		IsVerified: true,
	}

	t.Run("1. Success Login", func(t *testing.T) {
		req := &dto.LoginRequest{
			Email:    "john@example.com",
			Password: passwordPlain,
		}

		roles := []string{"admin"}
		perms := []string{"user:read", "user:write"}

		// 1. Mock Find User
		mockRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(userInDB, nil).Once()

		// 2. Mock Get Roles & Perms
		mockRepo.On("GetUserRolesAndPermissions", mock.Anything, userID).Return(roles, perms, nil).Once()

		// 3. Mock JWT Generate (Access & Refresh)
		mockJWT.On("GenerateToken", userID, userInDB.Name, userInDB.Email, roles, perms, "access").
			Return("fake-access-token", nil).Once()
		mockJWT.On("GenerateToken", userID, userInDB.Name, userInDB.Email, roles, perms, "refresh").
			Return("fake-refresh-token", nil).Once()

		res, err := service.Login(context.Background(), req)

		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.Equal(t, "fake-access-token", res.Token.AccessToken)
		assert.Equal(t, userInDB.Email, res.User.Email)

		mockRepo.AssertExpectations(t)
		mockJWT.AssertExpectations(t)
	})

	t.Run("2. Error - User Not Found", func(t *testing.T) {
		mockRepo := new(MockUserRepository) // Reset mock
		service := NewAuthService(mockRepo, mockJWT)

		req := &dto.LoginRequest{Email: "notfound@example.com", Password: "any"}

		mockRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(nil, nil).Once()

		res, err := service.Login(context.Background(), req)

		assert.ErrorIs(t, err, serverutils.ErrInvalidCredentials)
		assert.Nil(t, res)
	})

	t.Run("3. Error - Wrong Password", func(t *testing.T) {
		mockRepo := new(MockUserRepository)
		service := NewAuthService(mockRepo, mockJWT)

		req := &dto.LoginRequest{Email: "john@example.com", Password: "wrong-password"}

		mockRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(userInDB, nil).Once()

		res, err := service.Login(context.Background(), req)

		assert.ErrorIs(t, err, serverutils.ErrInvalidCredentials)
		assert.Nil(t, res)
	})

	t.Run("4. Error - Database Error on FindUser", func(t *testing.T) {
		mockRepo := new(MockUserRepository)
		service := NewAuthService(mockRepo, mockJWT)

		mockRepo.On("FindUserByEmail", mock.Anything, mock.Anything).
			Return(nil, errors.New("db connection lost")).Once()

		res, err := service.Login(context.Background(), &dto.LoginRequest{Email: "error@test.com"})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "db connection lost")
		assert.Nil(t, res)
	})

	t.Run("5. Error - Failed to Get Roles & Permissions", func(t *testing.T) {
		mockRepo := new(MockUserRepository)
		service := NewAuthService(mockRepo, mockJWT)

		req := &dto.LoginRequest{Email: "john@example.com", Password: passwordPlain}

		mockRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(userInDB, nil).Once()
		mockRepo.On("GetUserRolesAndPermissions", mock.Anything, userID).
			Return(nil, nil, errors.New("failed to fetch roles")).Once()

		res, err := service.Login(context.Background(), req)

		assert.Error(t, err)
		assert.Equal(t, "failed to fetch roles", err.Error())
		assert.Nil(t, res)
	})

	t.Run("6. Error - JWT Generation Failed", func(t *testing.T) {
		mockRepo := new(MockUserRepository)
		mockJWT := new(MockJWTService)
		service := NewAuthService(mockRepo, mockJWT)

		req := &dto.LoginRequest{Email: "john@example.com", Password: passwordPlain}

		mockRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(userInDB, nil).Once()
		mockRepo.On("GetUserRolesAndPermissions", mock.Anything, userID).Return([]string{"user"}, []string{}, nil).Once()

		// Simulasi error di GenerateToken pertama
		mockJWT.On("GenerateToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, "access").
			Return("", errors.New("jwt signing error")).Once()

		res, err := service.Login(context.Background(), req)

		assert.Error(t, err)
		assert.Nil(t, res)
	})
}

func (m *MockUserRepository) UsingTx(ctx context.Context, tx database.DatabaseQueryer) user.IUserRepository {
	// Kita panggil Called supaya kita bisa melakukan tracking apakah UsingTx dipanggil
	args := m.Called(ctx, tx)

	// Biasanya kita ingin mengembalikan dirinya sendiri (m)
	// agar chain method tetap berjalan menggunakan mock yang sama
	if args.Get(0) == nil {
		return m
	}

	return args.Get(0).(user.IUserRepository)
}

func (m *MockUserRepository) FindUserByEmail(ctx context.Context, email string) (*entity.Users, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Users), args.Error(1)
}

func (m *MockUserRepository) CreateUser(ctx context.Context, user *entity.Users) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserRolesAndPermissions(ctx context.Context, userID uuid.UUID) ([]string, []string, error) {
	args := m.Called(ctx, userID)

	var roles []string
	if args.Get(0) != nil {
		roles = args.Get(0).([]string)
	}

	var permissions []string
	if args.Get(1) != nil {
		permissions = args.Get(1).([]string)
	}

	return roles, permissions, args.Error(2)
}

func (m *MockJWTService) GenerateToken(userID uuid.UUID, nameUser string, emailUser string, roles []string, permissions []string, tokenType string) (string, error) {
	// Menangkap argumen yang dilewatkan saat pemanggilan
	args := m.Called(userID, nameUser, emailUser, roles, permissions, tokenType)

	// Mengembalikan nilai string (token) dan error
	return args.String(0), args.Error(1)
}

func (m *MockJWTService) ValidateToken(tokenString string) (*jwt.Token, error) {
	args := m.Called(tokenString)

	// Jika return value pertama tidak nil, cast ke *jwt.Token
	if args.Get(0) != nil {
		return args.Get(0).(*jwt.Token), args.Error(1)
	}

	return nil, args.Error(1)
}
