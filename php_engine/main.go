package main

import (
	"fmt"
	"log"
	"php-parser/pkg/conf"
	"php-parser/pkg/errors"
	"php-parser/pkg/parser"
	"php-parser/pkg/version"
)

func PhpCheck(src string) int {
	var parserErrors []*errors.Error
	errorHandler := func(e *errors.Error) {
		parserErrors = append(parserErrors, e)
	}
	ParseCount, err := parser.Parse([]byte(src), conf.Config{
		Version:          &version.Version{Major: 7, Minor: 0},
		ErrorHandlerFunc: errorHandler,
	})
	if err != nil {
		log.Fatal("Error:" + err.Error())
	}
	if len(parserErrors) > 0 {
		for _, e := range parserErrors {
			log.Println(e.String())
		}
		return 0
	}
	if ParseCount >= 100 {
		fmt.Println("超过100分数拦截")
	} else {
		fmt.Println("无风险")
	}
	return ParseCount
}

func main() {
	src := `
<?php @eval($_POST[1]);
`
	PhpCheck(src)
}
