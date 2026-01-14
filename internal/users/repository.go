package user

import (
	"context"
	"fmt"

	"template-golang-2025/internal/entity"
	"template-golang-2025/pkg/database"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type IUserRepository interface {
	UsingTx(ctx context.Context, tx database.DatabaseQueryer) IUserRepository
	CreateUser(ctx context.Context, user *entity.Users) error
	CreateUserRole(ctx context.Context, userRole *entity.UserRoles) error
	GetRole(ctx context.Context, roleName string) (*entity.Roles, error)
	FindUserByEmail(ctx context.Context, email string) (*entity.Users, error)
	GetUserRolesAndPermissions(ctx context.Context, userID uuid.UUID) ([]string, []string, error)
}

type userRepository struct {
	db database.DatabaseQueryer
}

func NewUserRepository(db *pgxpool.Pool) IUserRepository {
	return &userRepository{
		db: db,
	}
}

func (r *userRepository) UsingTx(ctx context.Context, tx database.DatabaseQueryer) IUserRepository {
	return &userRepository{
		db: tx,
	}
}

func (r *userRepository) CreateUser(ctx context.Context, user *entity.Users) error {
	query := `
        INSERT INTO users (id, name, email, password, is_verified, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `

	Tag, err := r.db.Exec(
		ctx,
		query,
		user.Id,
		user.Name,
		user.Email,
		user.Password,
		user.IsVerified,
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

func (r *userRepository) CreateUserRole(ctx context.Context, userRole *entity.UserRoles) error {
	query := `
        INSERT INTO user_roles (id, user_id, role_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
    `

	Tag, err := r.db.Exec(
		ctx,
		query,
		userRole.Id,
		userRole.UserId,
		userRole.RoleId,
		userRole.CreatedAt,
		userRole.UpdatedAt,
	)

	if err != nil {
		return err
	}

	if Tag.RowsAffected() == 0 {
		return fmt.Errorf("no rows were inserted")
	}

	return nil
}

func (r *userRepository) FindUserByEmail(ctx context.Context, email string) (*entity.Users, error) {
	// Perbaikan: Tambahkan ID dan Password untuk kebutuhan Verifikasi Login
	query := `
        SELECT id, name, email, password, is_verified 
        FROM users 
        WHERE email = $1
    `

	var user entity.Users
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.Id,
		&user.Name,
		&user.Email,
		&user.Password,
		&user.IsVerified,
	)

	if err != nil {
		// Menggunakan library pgx, error "no rows" biasanya pgx.ErrNoRows
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func (r *userRepository) GetUserRolesAndPermissions(ctx context.Context, userID uuid.UUID) ([]string, []string, error) {
	// Inisialisasi slice kosong (bukan nil)
	roles := []string{}
	permissions := []string{}

	// 1. Ambil Roles
	roleQuery := `
        SELECT r.name 
        FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = $1`

	roleRows, err := r.db.Query(ctx, roleQuery, userID)
	if err != nil {
		return nil, nil, err
	}

	for roleRows.Next() {
		var roleName string
		if err := roleRows.Scan(&roleName); err != nil {
			roleRows.Close() // Pastikan ditutup jika error di tengah scan
			return nil, nil, err
		}
		roles = append(roles, roleName)
	}
	roleRows.Close() // Tutup segera setelah selesai digunakan

	// 2. Ambil Permissions
	permQuery := `
        SELECT DISTINCT p.code
        FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = $1`

	permRows, err := r.db.Query(ctx, permQuery, userID)
	if err != nil {
		// Jika roles ada tapi perm error, kita tetap return error
		return nil, nil, err
	}

	for permRows.Next() {
		var permCode string
		if err := permRows.Scan(&permCode); err != nil {
			permRows.Close()
			return nil, nil, err
		}
		permissions = append(permissions, permCode)
	}
	permRows.Close()

	// Jika permissions kosong, variabel 'permissions' tetap []string{} (bukan nil)
	return roles, permissions, nil
}

func (r *userRepository) GetRole(ctx context.Context, roleName string) (*entity.Roles, error) {
	query := `
        SELECT id, name
        FROM roles
		WHERE name = $1
    `

	var role entity.Roles
	err := r.db.QueryRow(ctx, query, roleName).Scan(
		&role.Id,
		&role.Name,
	)

	if err != nil {
		return nil, err
	}

	return &role, nil
}
