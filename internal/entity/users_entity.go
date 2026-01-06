package entity

import (
	"time"

	"github.com/google/uuid"
)

type Users struct {
	Id              uuid.UUID
	Name            string
	Password        string
	Email           string
	IsActive        bool
	EmailVerifiedAt *time.Time
	CreatedAt       time.Time
	UpdatedAt       *time.Time
}
