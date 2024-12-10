package storage_errors

import "errors"

var errAlreadyExists = errors.New("already exists")

func NewErrAlreadyExists() error {
	return errAlreadyExists
}

var errNotExists = errors.New("not exists")

func NewErrNotExists() error {
	return errNotExists
}
