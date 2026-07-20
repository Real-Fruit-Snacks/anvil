package shell

import (
	"reflect"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"plain", "ls docs", []string{"ls", "docs"}},
		{"multiple spaces", "a  b   c", []string{"a", "b", "c"}},
		{"double quoted", `put "my file.txt" dst`, []string{"put", "my file.txt", "dst"}},
		{"single quoted", `use 'my share'`, []string{"use", "my share"}},
		{"backslash path literal", `cd docs\file.txt`, []string{"cd", `docs\file.txt`}},
		{"backslash parent", `get ..\hello.txt out`, []string{"get", `..\hello.txt`, "out"}},
		{"mixed quote in path", `cd "Program Files"`, []string{"cd", "Program Files"}},
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
		{"unterminated quote", `cat "unterminated`, []string{"cat", "unterminated"}},
		{"quote inside other quote", `a "b 'c' d"`, []string{"a", "b 'c' d"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := splitArgs(c.input)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("splitArgs(%q) = %v, want %v", c.input, got, c.want)
			}
		})
	}
}
