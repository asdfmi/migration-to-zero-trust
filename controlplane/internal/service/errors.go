package service

import (
	"errors"

	"migration-to-zero-trust/controlplane/internal/repository"
)

type ValidationError struct {
	Msg string
}

func (e ValidationError) Error() string {
	return e.Msg
}

type AuthError struct {
	Msg string
}

func (e AuthError) Error() string {
	return e.Msg
}

func IsNotFound(err error) bool {
	return errors.Is(err, repository.ErrNotFound)
}

func IsValidation(err error) bool {
	var v ValidationError
	return errors.As(err, &v)
}

func IsAuth(err error) bool {
	var a AuthError
	return errors.As(err, &a)
}
