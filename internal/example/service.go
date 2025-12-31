package example

import (
	"context"
	"fmt"

	"template-golang-2025/internal/dto"
)

type IExampleService interface {
	HelloWorld(ctx context.Context, req *dto.HelloWorldRequest) (*dto.HelloWorldResponse, error)
}

type exampleService struct {
	exampleRepository IExampleRepository
}

func NewExampleService(exampleRepository IExampleRepository) IExampleService {
	return &exampleService{
		exampleRepository: exampleRepository,
	}
}

func (s *exampleService) HelloWorld(
	ctx context.Context,
	req *dto.HelloWorldRequest,
) (*dto.HelloWorldResponse, error) {

	_, err := s.exampleRepository.Ping(ctx)
	if err != nil {
		return nil, err
	}

	return &dto.HelloWorldResponse{
		Message: fmt.Sprintf("Hello %s", req.Name),
	}, nil
}
