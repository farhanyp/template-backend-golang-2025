package auth

import (
	"context"
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

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}

	defer tx.Rollback(ctx)

	tokenRepository := s.tokenRepository.UsingTx(ctx, tx)

	// 5. Generate Tokens (Kirim data lengkap: ID, Name, Email, Roles)
	accessToken, err := s.jwtService.GenerateToken(user.Id, user.Name, user.Email, defaultRoles, defaultPerm, "access")
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.jwtService.GenerateToken(user.Id, user.Name, user.Email, defaultRoles, defaultPerm, "refresh")
	if err != nil {
		return nil, err
	}

	err = tokenRepository.DeleteRefreshTokenByUserId(ctx, user.Id)
	if err != nil {
		return nil, err
	}

	tokenRefresh := &entity.RefereshTokens{
		Id:        uuid.New(),
		UserId:    &user.Id,
		Token:     refreshToken,
		ExpiredAt: nil,
		RevokedAt: nil,
		CreatedAt: time.Now(),
	}

	err = tokenRepository.CreateRefreshToken(ctx, tokenRefresh)
	if err != nil {
		return nil, err
	}

	err = tx.Commit(ctx)
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
			ExpiresIn:    900,
		},
	}, nil
}

func (s *authService) Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error) {
	user, err := s.usersRepository.FindUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, serverutils.ErrInvalidCredentials
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		return nil, serverutils.ErrInvalidCredentials
	}

	roles, permissions, err := s.usersRepository.GetUserRolesAndPermissions(ctx, user.Id)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.jwtService.GenerateToken(user.Id, user.Name, user.Email, roles, permissions, "access")
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.jwtService.GenerateToken(user.Id, user.Name, user.Email, roles, permissions, "refresh")
	if err != nil {
		return nil, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}

	defer tx.Rollback(ctx)

	tokenRepository := s.tokenRepository.UsingTx(ctx, tx)

	err = tokenRepository.DeleteRefreshTokenByUserId(ctx, user.Id)
	if err != nil {
		return nil, err
	}

	tokenRefresh := &entity.RefereshTokens{
		Id:        uuid.New(),
		UserId:    &user.Id,
		Token:     refreshToken,
		ExpiredAt: nil,
		RevokedAt: nil,
		CreatedAt: time.Now(),
	}

	err = tokenRepository.CreateRefreshToken(ctx, tokenRefresh)
	if err != nil {
		return nil, err
	}

	err = tx.Commit(ctx)
	if err != nil {
		return nil, err
	}

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
