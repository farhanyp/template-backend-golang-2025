package entity

import (
	"time"

	"github.com/google/uuid"
)

type Users struct {
	Id         uuid.UUID
	Name       string
	Password   string
	Email      string
	IsVerified bool
	CreatedAt  time.Time
	UpdatedAt  *time.Time
}
