package example

import (
	"context"
	"time"

	"template-golang-2025/internal/dto"
	"template-golang-2025/internal/entity"

	"github.com/google/uuid"
)

type IAuthService interface {
	Register(ctx context.Context, req *dto.RegisterRequest) (*dto.RegisterResponse, error)
}

type authService struct {
	usersRepository IUsersRepository
}

func NewAuthService(usersRepository IUsersRepository) IAuthService {
	return &authService{usersRepository: usersRepository}
}

func (s *authService) Register(ctx context.Context, req *dto.RegisterRequest) (*dto.RegisterResponse, error) {

	userExist, err := s.usersRepository.FindUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}

	user := &entity.Users{
		Id:              uuid.New(),
		Name:            req.Name,
		Email:           userExist.Email,
		Password:        "",
		IsActive:        false,
		EmailVerifiedAt: nil,
		CreatedAt:       time.Now(),
		UpdatedAt:       nil,
	}

	err = s.usersRepository.CreateUser(ctx, user)
	if err != nil {
		return nil, err
	}

	return nil, nil
}
