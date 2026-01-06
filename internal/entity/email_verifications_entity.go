package entity

import (
	"time"

	"github.com/google/uuid"
)

type EmailVerifications struct {
	Id              uuid.UUID
	UserId          *uuid.UUID
	OtpCode         string
	ExpiredAt       *time.Time
	EmailVerifiedAt *time.Time
	Attempts        int
	CreatedAt       time.Time
	UpdatedAt       *time.Time
}
