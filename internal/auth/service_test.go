package auth

import (
	"context"
	"errors"
	"template-golang-2025/internal/dto"
	"template-golang-2025/internal/entity"
	"template-golang-2025/internal/pkg/serverutils"
	token "template-golang-2025/internal/refresh-token"
	user "template-golang-2025/internal/users"
	"template-golang-2025/pkg/database"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

type MockDB struct {
	mock.Mock
}

type MockUserRepository struct {
	mock.Mock
}

type MockJWTService struct {
	mock.Mock
}

type MockTransaction struct {
	mock.Mock
}

type MockRefreshTokenRepository struct {
	mock.Mock
}

func TestAuthService_Register(t *testing.T) {
	mockPool, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mockPool.Close()

	mockUserRepo := new(MockUserRepository)
	mockJWT := new(MockJWTService)
	mockTokenRepo := new(MockRefreshTokenRepository)

	// Kita panggil SERVICE ASLI, bukan mock
	service := NewAuthService(mockUserRepo, mockTokenRepo, mockJWT, mockPool)

	t.Run("1. Error Email Already Exists", func(t *testing.T) {
		email := "duplicate@example.com"
		req := &dto.RegisterRequest{
			Email:    email,
			Name:     "Test",
			Password: "password123",
		}

		// Simulasi: Repository menemukan user dengan email tersebut
		mockUserRepo.On("FindUserByEmail", mock.Anything, email).Return(&entity.Users{Id: uuid.New(), Email: email}, nil)

		res, err := service.Register(context.Background(), req)

		// ASSERTION: Di sini test akan FAIL jika Anda mengubah
		// logic return di service menjadi ErrInvalidCredentials
		assert.Nil(t, res)
		assert.ErrorIs(t, err, serverutils.ErrEmailAlreadyExists)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("2. Success Register & Transaction Check", func(t *testing.T) {
		// 1. Inisialisasi pgxmock
		mockPool, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mockPool.Close()

		mockUserRepo := new(MockUserRepository)
		mockJWT := new(MockJWTService)
		mockTokenRepo := new(MockRefreshTokenRepository)

		// 2. Inisialisasi Service (Sekarang mockPool bisa masuk karena parameternya Interface)
		service := NewAuthService(mockUserRepo, mockTokenRepo, mockJWT, mockPool)

		req := &dto.RegisterRequest{
			Email:    "new@example.com",
			Name:     "New User",
			Password: "password123",
		}

		// --- SETUP EXPECTATIONS (DB) ---
		// Kita beritahu mock bahwa transaksi akan dimulai dan diakhiri dengan Commit
		mockPool.ExpectBegin()
		mockPool.ExpectCommit()

		// --- SETUP MOCK (REPOSITORIES) ---
		mockUserRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(nil, nil)
		mockUserRepo.On("CreateUser", mock.Anything, mock.Anything).Return(nil)

		// Penting: Mock UsingTx harus mengembalikan repository itu sendiri
		mockTokenRepo.On("UsingTx", mock.Anything, mock.Anything).Return(mockTokenRepo)
		mockTokenRepo.On("DeleteRefreshTokenByUserId", mock.Anything, mock.Anything).Return(nil)
		mockTokenRepo.On("CreateRefreshToken", mock.Anything, mock.Anything).Return(nil)

		// --- SETUP MOCK (JWT) ---
		mockJWT.On("GenerateToken", mock.Anything, req.Name, req.Email,
			[]string{"user"}, mock.Anything, "access").Return("fake-access", nil)
		mockJWT.On("GenerateToken", mock.Anything, req.Name, req.Email,
			[]string{"user"}, mock.Anything, "refresh").Return("fake-refresh", nil)

		// --- EXECUTION ---
		res, err := service.Register(context.Background(), req)

		// --- ASSERTION ---
		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.Equal(t, "fake-access", res.Token.AccessToken)

		// Pastikan semua ekspektasi (termasuk DB transaksi) terpenuhi
		assert.NoError(t, mockPool.ExpectationsWereMet())
		mockUserRepo.AssertExpectations(t)
		mockJWT.AssertExpectations(t)
	})

	t.Run("3. Error Database - Failed to Create User", func(t *testing.T) {
		// 1. Inisialisasi pgxmock
		mockPool, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mockPool.Close()

		mockUserRepo := new(MockUserRepository)
		mockJWT := new(MockJWTService)
		mockTokenRepo := new(MockRefreshTokenRepository)

		// 2. Inisialisasi Service (Sekarang mockPool bisa masuk karena parameternya Interface)
		service := NewAuthService(mockUserRepo, mockTokenRepo, mockJWT, mockPool)

		req := &dto.RegisterRequest{
			Email:    "db-error@example.com",
			Name:     "DB Error User",
			Password: "password123",
		}

		// Simulasi email belum ada
		mockUserRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(nil, nil)

		// Simulasi database gagal menyimpan data (misal: koneksi terputus)
		mockUserRepo.On("CreateUser", mock.Anything, mock.Anything).
			Return(errors.New("database connection failed"))

		res, err := service.Register(context.Background(), req)

		// Assertion
		assert.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, "database connection failed", err.Error())

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("4. Error JWT - Failed to Generate Access Token", func(t *testing.T) {
		mockPool, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mockPool.Close()

		mockUserRepo := new(MockUserRepository)
		mockJWT := new(MockJWTService)
		mockTokenRepo := new(MockRefreshTokenRepository)
		service := NewAuthService(mockUserRepo, mockTokenRepo, mockJWT, mockPool)

		req := &dto.RegisterRequest{
			Email:    "jwt-error@example.com",
			Name:     "JWT Error User",
			Password: "password123",
		}

		// --- SETUP EXPECTATIONS ---

		// 1. Logic pengecekan user & create user (sebelum transaksi)
		mockUserRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(nil, nil)
		mockUserRepo.On("CreateUser", mock.Anything, mock.Anything).Return(nil)

		// 2. Setup Database Transaction
		mockPool.ExpectBegin()

		// 3. PENTING: Karena s.tokenRepository.UsingTx dipanggil tepat setelah Begin,
		// mock ini WAJIB ada meskipun JWT nantinya gagal.
		mockTokenRepo.On("UsingTx", mock.Anything, mock.Anything).Return(mockTokenRepo)

		// 4. Karena JWT error, tx.Commit tidak dipanggil, sehingga defer tx.Rollback akan jalan
		mockPool.ExpectRollback()

		// 5. Setup JWT Error
		mockJWT.On("GenerateToken", mock.Anything, req.Name, req.Email,
			[]string{"user"}, mock.Anything, "access").
			Return("", errors.New("jwt signing error"))

		// --- EXECUTION ---
		res, err := service.Register(context.Background(), req)

		// --- ASSERTION ---
		assert.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "jwt signing error")

		// Pastikan semua mock terpanggil sesuai rencana
		mockUserRepo.AssertExpectations(t)
		mockJWT.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t) // Pastikan UsingTx diverifikasi
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})
}

func TestAuthService_Login(t *testing.T) {
	mockPool, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mockPool.Close()

	mockUserRepo := new(MockUserRepository)
	mockJWT := new(MockJWTService)
	mockTokenRepo := new(MockRefreshTokenRepository)

	// Kita panggil SERVICE ASLI, bukan mock
	service := NewAuthService(mockUserRepo, mockTokenRepo, mockJWT, mockPool)

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
			Password: "password123",
		}

		// --- SETUP DB EXPECTATIONS ---
		// WAJIB ADA: Karena fungsi Login memanggil s.db.Begin()
		mockPool.ExpectBegin()

		// WAJIB ADA: Karena setelah Begin, s.tokenRepository.UsingTx() dipanggil
		mockTokenRepo.On("UsingTx", mock.Anything, mock.Anything).Return(mockTokenRepo)

		// WAJIB ADA: Karena di akhir fungsi Login ada Commit
		mockPool.ExpectCommit()

		// --- SETUP REPO & JWT MOCKS ---
		mockUserRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(userInDB, nil)

		// Setup Roles & Permissions
		mockUserRepo.On("GetUserRolesAndPermissions", mock.Anything, userInDB.Id).
			Return([]string{"user"}, []string{""}, nil)

		// Mock Delete & Create Token
		mockTokenRepo.On("DeleteRefreshTokenByUserId", mock.Anything, userInDB.Id).Return(nil)
		mockTokenRepo.On("CreateRefreshToken", mock.Anything, mock.Anything).Return(nil)

		// Mock JWT
		mockJWT.On("GenerateToken", mock.Anything, mock.Anything, mock.Anything,
			mock.Anything, mock.Anything, "access").Return("access-token", nil)
		mockJWT.On("GenerateToken", mock.Anything, mock.Anything, mock.Anything,
			mock.Anything, mock.Anything, "refresh").Return("refresh-token", nil)

		// --- EXECUTION ---
		res, err := service.Login(context.Background(), req)

		// --- ASSERTIONS ---
		assert.NoError(t, err)
		assert.NotNil(t, res) // Mencegah panic di baris berikutnya
		if res != nil {
			assert.Equal(t, "access-token", res.Token.AccessToken)
		}

		// Verifikasi semua ekspektasi
		assert.NoError(t, mockPool.ExpectationsWereMet())
		mockUserRepo.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t)
		mockJWT.AssertExpectations(t)
	})

	t.Run("2. Error - User Not Found", func(t *testing.T) {
		// 1. Inisialisasi pgxmock
		mockPool, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mockPool.Close()

		mockUserRepo := new(MockUserRepository)
		mockJWT := new(MockJWTService)
		mockTokenRepo := new(MockRefreshTokenRepository)

		// 2. Inisialisasi Service (Sekarang mockPool bisa masuk karena parameternya Interface)
		service := NewAuthService(mockUserRepo, mockTokenRepo, mockJWT, mockPool)

		req := &dto.LoginRequest{Email: "notfound@example.com", Password: "any"}

		mockUserRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(nil, nil).Once()

		res, err := service.Login(context.Background(), req)

		assert.ErrorIs(t, err, serverutils.ErrInvalidCredentials)
		assert.Nil(t, res)
	})

	t.Run("3. Error - Wrong Password", func(t *testing.T) {
		// 1. Inisialisasi pgxmock
		mockPool, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mockPool.Close()

		mockUserRepo := new(MockUserRepository)
		mockJWT := new(MockJWTService)
		mockTokenRepo := new(MockRefreshTokenRepository)

		// 2. Inisialisasi Service (Sekarang mockPool bisa masuk karena parameternya Interface)
		service := NewAuthService(mockUserRepo, mockTokenRepo, mockJWT, mockPool)

		req := &dto.LoginRequest{Email: "john@example.com", Password: "wrong-password"}

		mockUserRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(userInDB, nil).Once()

		res, err := service.Login(context.Background(), req)

		assert.ErrorIs(t, err, serverutils.ErrInvalidCredentials)
		assert.Nil(t, res)
	})

	t.Run("4. Error - Database Error on FindUser", func(t *testing.T) {
		// 1. Inisialisasi pgxmock
		mockPool, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mockPool.Close()

		mockUserRepo := new(MockUserRepository)
		mockJWT := new(MockJWTService)
		mockTokenRepo := new(MockRefreshTokenRepository)

		// 2. Inisialisasi Service (Sekarang mockPool bisa masuk karena parameternya Interface)
		service := NewAuthService(mockUserRepo, mockTokenRepo, mockJWT, mockPool)

		mockUserRepo.On("FindUserByEmail", mock.Anything, mock.Anything).
			Return(nil, errors.New("db connection lost")).Once()

		res, err := service.Login(context.Background(), &dto.LoginRequest{Email: "error@test.com"})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "db connection lost")
		assert.Nil(t, res)
	})

	t.Run("5. Error - Failed to Get Roles & Permissions", func(t *testing.T) {
		// 1. Inisialisasi pgxmock
		mockPool, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mockPool.Close()

		mockUserRepo := new(MockUserRepository)
		mockJWT := new(MockJWTService)
		mockTokenRepo := new(MockRefreshTokenRepository)

		// 2. Inisialisasi Service (Sekarang mockPool bisa masuk karena parameternya Interface)
		service := NewAuthService(mockUserRepo, mockTokenRepo, mockJWT, mockPool)

		req := &dto.LoginRequest{Email: "john@example.com", Password: passwordPlain}

		mockUserRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(userInDB, nil).Once()
		mockUserRepo.On("GetUserRolesAndPermissions", mock.Anything, userID).
			Return(nil, nil, errors.New("failed to fetch roles")).Once()

		res, err := service.Login(context.Background(), req)

		assert.Error(t, err)
		assert.Equal(t, "failed to fetch roles", err.Error())
		assert.Nil(t, res)
	})

	t.Run("6. Error - JWT Generation Failed", func(t *testing.T) {
		// 1. Inisialisasi pgxmock
		mockPool, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mockPool.Close()

		mockUserRepo := new(MockUserRepository)
		mockJWT := new(MockJWTService)
		mockTokenRepo := new(MockRefreshTokenRepository)

		// 2. Inisialisasi Service (Sekarang mockPool bisa masuk karena parameternya Interface)
		service := NewAuthService(mockUserRepo, mockTokenRepo, mockJWT, mockPool)

		req := &dto.LoginRequest{Email: "john@example.com", Password: passwordPlain}

		mockUserRepo.On("FindUserByEmail", mock.Anything, req.Email).Return(userInDB, nil).Once()
		mockUserRepo.On("GetUserRolesAndPermissions", mock.Anything, userID).Return([]string{"user"}, []string{}, nil).Once()

		// Simulasi error di GenerateToken pertama
		mockJWT.On("GenerateToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, "access").
			Return("", errors.New("jwt signing error")).Once()

		res, err := service.Login(context.Background(), req)

		assert.Error(t, err)
		assert.Nil(t, res)
	})
}

func (m *MockRefreshTokenRepository) UsingTx(ctx context.Context, tx database.DatabaseQueryer) token.IRefreshTokenRepository {
	args := m.Called(ctx, tx)
	return args.Get(0).(token.IRefreshTokenRepository)
}

func (m *MockTransaction) Rollback(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

func (m *MockTransaction) Commit(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

func (m *MockUserRepository) FindUserByEmail(ctx context.Context, email string) (*entity.Users, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Users), args.Error(1)
}

func (m *MockUserRepository) UsingTx(ctx context.Context, tx database.DatabaseQueryer) user.IUserRepository {
	// 1. Masukkan semua argumen ke Called agar bisa di-verify oleh testify
	args := m.Called(ctx, tx)

	// 2. Pastikan return value di-cast ke interface Repository
	// Kita asumsikan return value pertama (index 0) adalah IUserRepository
	if args.Get(0) == nil {
		return nil
	}

	return args.Get(0).(user.IUserRepository)
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

func (m *MockDB) Begin(ctx context.Context) (any, error) {
	args := m.Called(ctx)
	return args.Get(0), args.Error(1)
}

func (m *MockRefreshTokenRepository) DeleteRefreshTokenByUserId(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockRefreshTokenRepository) CreateRefreshToken(ctx context.Context, t *entity.RefereshTokens) error {
	return m.Called(ctx, t).Error(0)
}
