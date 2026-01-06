package auth

import (
	"context"
	"time"

	"template-golang-2025/internal/dto"
	"template-golang-2025/internal/entity"
	"template-golang-2025/internal/pkg/serverutils"
	"template-golang-2025/pkg/jwt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type IAuthService interface {
	Register(ctx context.Context, req *dto.RegisterRequest) (*dto.RegisterResponse, error)
}

type authService struct {
	usersRepository IUsersRepository
	jwtService      jwt.JWTService
}

func NewAuthService(usersRepository IUsersRepository, jwtService jwt.JWTService) IAuthService {
	return &authService{usersRepository: usersRepository, jwtService: jwtService}
}

func (s *authService) Register(ctx context.Context, req *dto.RegisterRequest) (*dto.RegisterResponse, error) {
	existingUser, err := s.usersRepository.FindUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}

	if existingUser != nil {
		return nil, serverutils.ErrEmailAlreadyExists
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &entity.Users{
		Id:              uuid.New(),
		Name:            req.Name,
		Email:           req.Email,
		Password:        string(hashedPassword),
		IsActive:        false,
		EmailVerifiedAt: nil,
		CreatedAt:       time.Now(),
		UpdatedAt:       nil,
	}

	err = s.usersRepository.CreateUser(ctx, user)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.jwtService.GenerateToken(user.Id, "access")
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.jwtService.GenerateToken(user.Id, "refresh")
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
		},
	}, nil
}
