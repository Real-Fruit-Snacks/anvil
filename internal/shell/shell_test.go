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

func TestParseRegQueryArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		keyPath string
		value   string
		hasV    bool
		surplus string
	}{
		{"plain key", []string{`HKLM\SOFTWARE\Foo`}, `HKLM\SOFTWARE\Foo`, "", false, ""},
		{"key with /v", []string{`HKLM\SOFTWARE\Foo`, "/v", "Bar"}, `HKLM\SOFTWARE\Foo`, "Bar", true, ""},
		{"quoted path with space", []string{`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`}, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "", false, ""},
		{"unquoted path with space flags surplus", []string{`HKLM\SOFTWARE\Microsoft\Windows`, `NT\CurrentVersion`}, `HKLM\SOFTWARE\Microsoft\Windows`, "", false, `NT\CurrentVersion`},
		{"dangling /v is surplus", []string{`HKLM\Foo`, "/v"}, `HKLM\Foo`, "", false, "/v"},
		{"empty args", nil, "", "", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keyPath, value, hasV, surplus := parseRegQueryArgs(c.args)
			if keyPath != c.keyPath || value != c.value || hasV != c.hasV || surplus != c.surplus {
				t.Errorf("parseRegQueryArgs(%v) = (%q, %q, %v, %q), want (%q, %q, %v, %q)",
					c.args, keyPath, value, hasV, surplus, c.keyPath, c.value, c.hasV, c.surplus)
			}
		})
	}
}
