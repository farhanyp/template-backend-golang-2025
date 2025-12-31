package example

import (
	"context"

	"template-golang-2025/pkg/database"

	"github.com/jackc/pgx/v5/pgxpool"
)

type IExampleRepository interface {
	UsingTx(ctx context.Context, tx database.DatabaseQueryer) IExampleRepository
	Ping(ctx context.Context) (*Example, error)
}

type exampleRepository struct {
	db database.DatabaseQueryer
}

func NewExampleRepository(db *pgxpool.Pool) IExampleRepository {
	return &exampleRepository{
		db: db,
	}
}

func (r *exampleRepository) UsingTx(ctx context.Context, tx database.DatabaseQueryer) IExampleRepository {
	return &exampleRepository{
		db: tx,
	}
}

func (r *exampleRepository) Ping(ctx context.Context) (*Example, error) {
	row := r.db.QueryRow(
		ctx,
		`SELECT 'hello' AS "message"`,
	)

	var example Example
	if err := row.Scan(&example.Message); err != nil {
		return nil, err
	}

	return &example, nil
}
