package serverutils

import "errors"

var (
	ErrNotFound            = errors.New("not found")
	ErrEmailAlreadyExists  = errors.New("email already registered")
	ErrInvalidCredentials  = errors.New("credentials is invalid")
	ErrInternalServer      = errors.New("something went wrong, please try again later")
	ErrInvalidRefreshToken = errors.New("credentials is invalid")
)
