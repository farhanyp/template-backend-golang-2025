package entity

import (
	"time"

	"github.com/google/uuid"
)

type Roles struct {
	Id        uuid.UUID
	Name      string
	Password  string
	CreatedAt time.Time
	UpdatedAt *time.Time
}
