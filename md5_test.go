package md5

import (
	"fmt"
	"testing"
)

func TestMd5(t *testing.T) {
	r := Md5("The quick brown fox jumps over the lazy dog")
	fmt.Println(r)
}
