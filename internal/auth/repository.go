package auth

import (
	"context"
	"fmt"

	"template-golang-2025/internal/entity"
	"template-golang-2025/pkg/database"

	"github.com/jackc/pgx/v5/pgxpool"
)

type IUsersRepository interface {
	UsingTx(ctx context.Context, tx database.DatabaseQueryer) IUsersRepository
	CreateUser(ctx context.Context, user *entity.Users) error
	FindUserByEmail(ctx context.Context, email string) (*entity.Users, error)
}

type usersRepository struct {
	db database.DatabaseQueryer
}

func NewUserRepository(db *pgxpool.Pool) IUsersRepository {
	return &usersRepository{
		db: db,
	}
}

func (r *usersRepository) UsingTx(ctx context.Context, tx database.DatabaseQueryer) IUsersRepository {
	return &usersRepository{
		db: tx,
	}
}

func (r *usersRepository) CreateUser(ctx context.Context, user *entity.Users) error {
	query := `
        INSERT INTO users (id, name, email, password, is_active, email_verified_at, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `

	Tag, err := r.db.Exec(
		ctx,
		query,
		user.Id,
		user.Name,
		user.Email,
		user.Password,
		user.IsActive,
		user.EmailVerifiedAt,
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		return err
	}

	if Tag.RowsAffected() == 0 {
		return fmt.Errorf("no rows were inserted")
	}

	return nil
}

func (r *usersRepository) FindUserByEmail(ctx context.Context, email string) (*entity.Users, error) {
	query := `
        SELECT name, email FROM users  WHERE email = $1
    `

	var user entity.Users
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.Name,
		&user.Email,
	)

	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}
