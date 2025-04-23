package php7

import (
	"php-parser/internal/position"
	"php-parser/internal/scanner"
	"php-parser/pkg/ast"
	"php-parser/pkg/conf"
	"php-parser/pkg/errors"
	"php-parser/pkg/token"
)

// Parser structure
type Parser struct {
	Lexer          *scanner.Lexer
	currentToken   *token.Token
	rootNode       ast.Vertex
	errHandlerFunc func(*errors.Error)
	builder        *position.Builder
	fraction       int
}

// NewParser creates and returns new Parser
func NewParser(lexer *scanner.Lexer, config conf.Config) *Parser {
	return &Parser{
		Lexer:          lexer,
		errHandlerFunc: config.ErrorHandlerFunc,
		builder:        position.NewBuilder(),
	}
}

func (p *Parser) GetFraction() int {
	return p.fraction
}

func (p *Parser) AddFraction(fraction int) {
	p.fraction += fraction
	return
}

func (p *Parser) Lex(lval *yySymType) int {
	t := p.Lexer.Lex()

	p.currentToken = t
	lval.token = t

	return int(t.ID)
}

func (p *Parser) Error(msg string) {
	if p.errHandlerFunc == nil {
		return
	}
	p.errHandlerFunc(errors.NewError(msg, p.currentToken.Position))
}

// Parse the php7 Parser entrypoint
func (p *Parser) Parse() int {
	p.rootNode = nil
	return yyParse(p)
}

// GetRootNode returns root node
func (p *Parser) GetRootNode() ast.Vertex {
	return p.rootNode
}

func lastNode(nn []ast.Vertex) ast.Vertex {
	if len(nn) == 0 {
		return nil
	}
	return nn[len(nn)-1]
}
