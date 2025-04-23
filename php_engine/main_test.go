package main

import (
	"gotest.tools/assert"
	"testing"
)

func TestPhpName(t *testing.T) {
	src := `
<?php $name=1;
`
	count := PhpCheck(src)
	assert.Equal(t, count, 0)
}

func TestPhpCount(t *testing.T) {
	src := `
<?php echo "111";
`
	count := PhpCheck(src)
	assert.Equal(t, count, 0)
}
func TestPhpFun(t *testing.T) {
	src := `
<?php phpinfo();
`
	count := PhpCheck(src)
	assert.Equal(t, count, 100)
}
