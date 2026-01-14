package auth

import (
	"context"
	"errors"
	"log"
	"time"

	"template-golang-2025/internal/constant"
	"template-golang-2025/internal/dto"
	"template-golang-2025/internal/entity"
	"template-golang-2025/internal/pkg/serverutils"
	token "template-golang-2025/internal/refresh-token"
	user "template-golang-2025/internal/users"
	"template-golang-2025/pkg/jwt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

type IAuthService interface {
	Register(ctx context.Context, req *dto.RegisterRequest) (*dto.RegisterResponse, error)
	Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error)
	Logout(ctx context.Context, req *dto.LogoutRequest) error
}

type DBTransactioner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

type authService struct {
	usersRepository user.IUserRepository
	tokenRepository token.IRefreshTokenRepository
	jwtService      jwt.JWTService
	db              DBTransactioner
}

func NewAuthService(usersRepository user.IUserRepository, tokenRepository token.IRefreshTokenRepository, jwtService jwt.JWTService, db DBTransactioner) IAuthService {
	return &authService{usersRepository: usersRepository, tokenRepository: tokenRepository, jwtService: jwtService, db: db}
}

func (s *authService) Register(ctx context.Context, req *dto.RegisterRequest) (*dto.RegisterResponse, error) {
	// 1. Validasi awal (diluar transaksi untuk menghemat resource)
	existingUser, err := s.usersRepository.FindUserByEmail(ctx, req.Email)
	if err != nil {
		log.Printf("[Register] DB Error checking email %s: %v", req.Email, err)
		return nil, serverutils.ErrInternalServer
	}
	if existingUser != nil {
		return nil, serverutils.ErrEmailAlreadyExists
	}

	existingRole, err := s.usersRepository.GetRole(ctx, "user")
	if err != nil {
		log.Printf("[Register] Role 'user' not found in DB: %v", err)
		return nil, serverutils.ErrInternalServer
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("[Register] Failed to hash password: %v", err)
		return nil, serverutils.ErrInternalServer
	}

	// 2. Mulai Transaksi Tunggal
	tx, err := s.db.Begin(ctx)
	if err != nil {
		log.Printf("[Register] Transaction Begin Error: %v", err)
		return nil, serverutils.ErrInternalServer
	}
	// Pastikan rollback jika terjadi error atau panic
	defer tx.Rollback(ctx)

	// Gunakan repository yang sudah dibungkus transaksi
	userRepoTx := s.usersRepository.UsingTx(ctx, tx)
	tokenRepoTx := s.tokenRepository.UsingTx(ctx, tx)

	now := time.Now()
	user := &entity.Users{
		Id:         uuid.New(),
		Name:       req.Name,
		Email:      req.Email,
		Password:   string(hashedPassword),
		IsVerified: false,
		CreatedAt:  now,
		UpdatedAt:  &now,
	}

	// SIMPAN USER (Gunakan userRepoTx)
	if err := userRepoTx.CreateUser(ctx, user); err != nil {
		log.Printf("[Register] Failed to create user entity: %v", err)
		return nil, serverutils.ErrInternalServer
	}

	userRoles := &entity.UserRoles{
		Id:        uuid.New(),
		UserId:    user.Id,
		RoleId:    existingRole.Id,
		CreatedAt: now,
		UpdatedAt: &now,
	}

	// SIMPAN ROLE (Gunakan userRepoTx)
	if err := userRepoTx.CreateUserRole(ctx, userRoles); err != nil {
		log.Printf("[Register] Failed to assign role to user %s: %v", user.Id, err)
		return nil, serverutils.ErrInternalServer
	}

	// 3. Generate Token
	defaultRoles := []string{constant.USER}
	defaultPerm := []string{""}

	accessToken, err := s.jwtService.GenerateToken(user.Id, user.Name, user.Email, defaultRoles, defaultPerm, "access")
	if err != nil {
		log.Printf("[Register] Failed to create access token: %v", err)
		return nil, serverutils.ErrInternalServer
	}
	refreshToken, err := s.jwtService.GenerateToken(user.Id, user.Name, user.Email, defaultRoles, defaultPerm, "refresh")
	if err != nil {
		log.Printf("[Register] Failed to create refresh token: %v", err)
		return nil, serverutils.ErrInternalServer
	}

	refreshDuration := s.jwtService.GetRefreshExpiry()
	expiredAt := now.Add(refreshDuration)

	// SIMPAN REFRESH TOKEN (Gunakan tokenRepoTx)
	tokenRefresh := &entity.RefereshTokens{
		Id:        uuid.New(),
		UserId:    user.Id,
		Token:     refreshToken,
		ExpiredAt: &expiredAt, // Menggunakan pointer ke time.Time
		RevokedAt: nil,        // Nil karena token baru aktif dan belum dicabut
		CreatedAt: now,
	}

	if err := tokenRepoTx.CreateRefreshToken(ctx, tokenRefresh); err != nil {
		log.Printf("[Auth] Failed to insert refresh token to db: %v", err)
		return nil, serverutils.ErrInternalServer
	}

	// 4. Commit Transaksi
	if err := tx.Commit(ctx); err != nil {
		log.Printf("[Register] Transaction Commit Error: %v", err)
		return nil, serverutils.ErrInternalServer
	}

	return &dto.RegisterResponse{
		User: dto.UserIdentity{
			Id:    user.Id,
			Name:  user.Name,
			Email: user.Email,
		},
		Token: dto.Token{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    900,
		},
	}, nil
}

func (s *authService) Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error) {
	// 1. Cari User berdasarkan Email
	user, err := s.usersRepository.FindUserByEmail(ctx, req.Email)
	if err != nil {
		log.Printf("[Login] Database error for email %s: %v", req.Email, err)
		return nil, serverutils.ErrInternalServer
	}

	// 2. Validasi Keberadaan User & Password (Security Best Practice: Error yang sama)
	if user == nil {
		log.Printf("[Login] User not found: %s", req.Email)
		return nil, serverutils.ErrInvalidCredentials
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		log.Printf("[Login] Invalid password attempt for email: %s", req.Email)
		return nil, serverutils.ErrInvalidCredentials
	}

	// 3. Ambil Roles dan Permissions
	roles, permissions, err := s.usersRepository.GetUserRolesAndPermissions(ctx, user.Id)
	if err != nil {
		log.Printf("[Login] Failed to fetch roles/perms for user %s: %v", user.Id, err)
		return nil, serverutils.ErrInternalServer
	}

	// 4. Generate Token (diluar transaksi untuk efisiensi)
	accessToken, err := s.jwtService.GenerateToken(user.Id, user.Name, user.Email, roles, permissions, "access")
	if err != nil {
		log.Printf("[Login] Error generating access token for user %s: %v", user.Id, err)
		return nil, err
	}

	refreshToken, err := s.jwtService.GenerateToken(user.Id, user.Name, user.Email, roles, permissions, "refresh")
	if err != nil {
		log.Printf("[Login] Error generating refresh token for user %s: %v", user.Id, err)
		return nil, err
	}

	// 5. Mulai Transaksi Database
	tx, err := s.db.Begin(ctx)
	if err != nil {
		log.Printf("[Login] Failed to start transaction: %v", err)
		return nil, serverutils.ErrInternalServer
	}
	defer tx.Rollback(ctx)

	tokenRepoTx := s.tokenRepository.UsingTx(ctx, tx)

	// 6. Kelola Refresh Token (Hapus yang lama, simpan yang baru)
	if err := tokenRepoTx.DeleteRefreshTokenByUserId(ctx, user.Id); err != nil {
		log.Printf("[Login] Failed to delete old refresh tokens for user %s: %v", user.Id, err)
		return nil, serverutils.ErrInternalServer
	}

	now := time.Now()
	// Ambil durasi expiry dari service agar sinkron
	refreshExpiryDuration := s.jwtService.GetRefreshExpiry()
	expiredAt := now.Add(refreshExpiryDuration)

	tokenRefresh := &entity.RefereshTokens{
		Id:        uuid.New(),
		UserId:    user.Id,
		Token:     refreshToken,
		ExpiredAt: &expiredAt, // Sekarang sudah terisi
		RevokedAt: nil,
		CreatedAt: now,
	}

	log.Printf("Refresh Token: %v", tokenRefresh)

	if err := tokenRepoTx.CreateRefreshToken(ctx, tokenRefresh); err != nil {
		log.Printf("[Login] Failed to save new refresh token for user %s: %v", user.Id, err)
		return nil, serverutils.ErrInternalServer
	}

	// 7. Commit Transaksi
	if err := tx.Commit(ctx); err != nil {
		log.Printf("[Login] Failed to commit transaction for user %s: %v", user.Id, err)
		return nil, serverutils.ErrInternalServer
	}

	log.Printf("[Login] Success: User %s logged in", user.Email)

	return &dto.LoginResponse{
		User: dto.UserIdentity{
			Id:    user.Id,
			Name:  user.Name,
			Email: user.Email,
		},
		Token: dto.Token{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    900,
		},
	}, nil
}

func (s *authService) Logout(ctx context.Context, req *dto.LogoutRequest) error {
	// 1. Validasi token (hanya perlu panggil sekali)
	token, err := s.jwtService.ValidateToken(req.RefreshToken)
	if err != nil || !token.Valid {
		return errors.New("invalid or expired refresh token")
	}

	// 2. Ambil claims untuk mendapatkan UserID dan Tipe Token
	claims, err := s.jwtService.GetClaims(token)
	if err != nil {
		return err
	}

	// 3. Keamanan Tambahan: Pastikan yang mau di-logout memang Refresh Token
	if claims.Type != "refresh" {
		return errors.New("invalid token type for logout")
	}

	// 4. Panggil repository untuk menghapus data (Hard Delete)
	// Kirim claims.UserID (uuid.UUID) sesuai permintaan fungsi repository sebelumnya
	err = s.tokenRepository.RevokeRefreshToken(ctx, claims.UserID)
	if err != nil {
		return err
	}

	return nil
}
