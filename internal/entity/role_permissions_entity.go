package entity

import (
	"time"

	"github.com/google/uuid"
)

type RolePermissions struct {
	Id            uuid.UUID
	Role_id       uuid.UUID
	Permission_id uuid.UUID
	CreatedAt     time.Time
	UpdatedAt     *time.Time
}
