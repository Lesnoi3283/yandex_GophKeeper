package storageerrors

import "errors"

var errAlreadyExists = errors.New("already exists")

func NewErrAlreadyExists() error {
	return errAlreadyExists
}
