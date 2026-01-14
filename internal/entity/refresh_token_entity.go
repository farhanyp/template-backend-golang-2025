package entity

import (
	"time"

	"github.com/google/uuid"
)

type RefereshTokens struct {
	Id        uuid.UUID
	UserId    uuid.UUID
	Token     string
	ExpiredAt *time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}
