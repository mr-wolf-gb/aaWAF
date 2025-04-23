package conf

import (
	"php-parser/pkg/errors"
	"php-parser/pkg/version"
)

type Config struct {
	Version          *version.Version
	ErrorHandlerFunc func(e *errors.Error)
}
