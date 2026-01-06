package entity

import (
	"time"

	"github.com/google/uuid"
)

type PasswordResets struct {
	Id         uuid.UUID
	UserId     *uuid.UUID
	Token      string
	ExpiredAt  *time.Time
	UsedAt     *time.Time
	VerifiedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  *time.Time
}
