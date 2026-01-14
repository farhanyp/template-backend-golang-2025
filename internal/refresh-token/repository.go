package token

import (
	"context"
	"fmt"

	"template-golang-2025/internal/entity"
	"template-golang-2025/pkg/database"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type IRefreshTokenRepository interface {
	UsingTx(ctx context.Context, tx database.DatabaseQueryer) IRefreshTokenRepository
	CreateRefreshToken(ctx context.Context, token *entity.RefereshTokens) error
	DeleteRefreshTokenByUserId(ctx context.Context, userID uuid.UUID) error
	RevokeRefreshToken(ctx context.Context, userID uuid.UUID) error
}

type refreshTokenRepository struct {
	db database.DatabaseQueryer
}

func NewUserRepository(db *pgxpool.Pool) IRefreshTokenRepository {
	return &refreshTokenRepository{
		db: db,
	}
}

func (r *refreshTokenRepository) UsingTx(ctx context.Context, tx database.DatabaseQueryer) IRefreshTokenRepository {
	return &refreshTokenRepository{
		db: tx,
	}
}

func (r *refreshTokenRepository) CreateRefreshToken(ctx context.Context, token *entity.RefereshTokens) error {
	query := `
        INSERT INTO refresh_tokens (id, user_id, token, expired_at, revoked_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
    `

	Tag, err := r.db.Exec(
		ctx,
		query,
		token.Id,
		token.UserId,
		token.Token,
		token.ExpiredAt,
		token.RevokedAt,
		token.CreatedAt,
	)

	if err != nil {
		return err
	}

	if Tag.RowsAffected() == 0 {
		return fmt.Errorf("no rows were inserted")
	}

	return nil
}

func (r *refreshTokenRepository) DeleteRefreshTokenByUserId(ctx context.Context, userID uuid.UUID) error {
	// 1. Perbaiki Query: Gunakan DELETE dan arahkan ke tabel yang benar
	query := `DELETE FROM refresh_tokens WHERE user_id = $1`

	// 2. Jalankan Exec
	tag, err := r.db.Exec(ctx, query, userID)

	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	// 3. Opsional: Cek apakah ada data yang dihapus
	// Biasanya untuk Delete by User ID, jika tidak ada data yang dihapus (0 rows)
	// tidak dianggap error, karena mungkin user memang belum punya token.
	_ = tag.RowsAffected()

	return nil
}

func (r *refreshTokenRepository) RevokeRefreshToken(ctx context.Context, userID uuid.UUID) error {
	// Menghapus data token secara permanen dari database
	query := `DELETE FROM refresh_tokens WHERE user_id = $1`

	tag, err := r.db.Exec(
		ctx,
		query,
		userID,
	)

	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	// Tag.RowsAffected() memberitahu kita berapa banyak baris yang dihapus.
	// Jika 0, berarti user memang tidak memiliki session aktif.
	if tag.RowsAffected() == 0 {
		// Ini opsional, bisa dianggap sukses atau error tergantung kebutuhan bisnis Anda
		return fmt.Errorf("no active session found for this user")
	}

	return nil
}
