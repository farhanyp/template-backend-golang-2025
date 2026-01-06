package entity

import (
	"time"

	"github.com/google/uuid"
)

type Role struct {
	Id          uuid.UUID
	Code        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   *time.Time
}
