package php7_test

import (
	"io/ioutil"
	"testing"

	"php-parser/internal/php7"
	"php-parser/internal/scanner"
	"php-parser/pkg/conf"
	"php-parser/pkg/version"
)

func BenchmarkPhp7(b *testing.B) {
	src, err := ioutil.ReadFile("test.php")

	if err != nil {
		b.Fatal("can not read test.php: " + err.Error())
	}

	for n := 0; n < b.N; n++ {
		config := conf.Config{
			Version: &version.Version{
				Major: 7,
				Minor: 4,
			},
		}
		lexer := scanner.NewLexer(src, config)
		php7parser := php7.NewParser(lexer, config)
		php7parser.Parse()
	}
}
