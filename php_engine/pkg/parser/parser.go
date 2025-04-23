package parser

import (
	"errors"
	"php-parser/internal/php7"
	"php-parser/internal/scanner"
	"php-parser/pkg/ast"
	"php-parser/pkg/conf"
	"php-parser/pkg/version"
)

var (
	// ErrVersionOutOfRange is returned if the version is not supported
	ErrVersionOutOfRange = errors.New("the version is out of supported range")

	php7RangeStart = &version.Version{Major: 7}
	php7RangeEnd   = &version.Version{Major: 7, Minor: 4}
)

// Parser interface
type Parser interface {
	Parse() int
	GetRootNode() ast.Vertex
	GetFraction() int
}

func Parse(src []byte, config conf.Config) (int, error) {
	var parser Parser

	if config.Version == nil {
		config.Version = php7RangeEnd
	}

	if config.Version.InRange(php7RangeStart, php7RangeEnd) {
		lexer := scanner.NewLexer(src, config)
		parser = php7.NewParser(lexer, config)
		parser.Parse()
		return parser.GetFraction(), nil
	}

	return 0, ErrVersionOutOfRange
}
