package serverutils

import "errors"

var (
	ErrNotFound           = errors.New("not found")
	ErrEmailAlreadyExists = errors.New("email already registered")
	ErrInternalServer     = errors.New("something went wrong, please try again later")
)
