package auth

import (
	"context"
	"time"

	"template-golang-2025/internal/constant"
	"template-golang-2025/internal/dto"
	"template-golang-2025/internal/entity"
	"template-golang-2025/internal/pkg/serverutils"
	user "template-golang-2025/internal/users"
	"template-golang-2025/pkg/jwt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type IAuthService interface {
	Register(ctx context.Context, req *dto.RegisterRequest) (*dto.RegisterResponse, error)
	Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error)
}

type authService struct {
	usersRepository user.IUserRepository
	jwtService      jwt.JWTService
}

func NewAuthService(usersRepository user.IUserRepository, jwtService jwt.JWTService) IAuthService {
	return &authService{usersRepository: usersRepository, jwtService: jwtService}
}

func (s *authService) Register(ctx context.Context, req *dto.RegisterRequest) (*dto.RegisterResponse, error) {
	// 1. Cek User Exist
	existingUser, err := s.usersRepository.FindUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, serverutils.ErrEmailAlreadyExists
	}

	// 2. Hash Password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// 3. Simpan User
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

	err = s.usersRepository.CreateUser(ctx, user)
	if err != nil {
		return nil, err
	}

	defaultRoles := []string{constant.USER}
	defaultPerm := []string{""}

	// 5. Generate Tokens (Kirim data lengkap: ID, Name, Email, Roles)
	accessToken, err := s.jwtService.GenerateToken(user.Id, user.Name, user.Email, defaultRoles, defaultPerm, "access")
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.jwtService.GenerateToken(user.Id, user.Name, user.Email, defaultRoles, defaultPerm, "refresh")
	if err != nil {
		return nil, err
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
			ExpiresIn:    900, // 15 menit
		},
	}, nil
}

func (s *authService) Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error) {
	// 1. Cari User berdasarkan Email
	user, err := s.usersRepository.FindUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}

	// Keamanan: Jika user tidak ada, gunakan error generic "Invalid Credentials"
	if user == nil {
		return nil, serverutils.ErrInvalidCredentials
	}

	// 2. Verifikasi Password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		return nil, serverutils.ErrInvalidCredentials
	}

	// 3. Ambil Roles & Permissions dari DB (Sesuai method baru kita di repository)
	roles, permissions, err := s.usersRepository.GetUserRolesAndPermissions(ctx, user.Id)
	if err != nil {
		return nil, err
	}

	// 4. Generate Tokens dengan data asli dari Database
	accessToken, err := s.jwtService.GenerateToken(user.Id, user.Name, user.Email, roles, permissions, "access")
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.jwtService.GenerateToken(user.Id, user.Name, user.Email, roles, permissions, "refresh")
	if err != nil {
		return nil, err
	}

	// 5. Response (Gunakan dto.LoginResponse)
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
