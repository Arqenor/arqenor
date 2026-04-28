package util

import "testing"

func TestRedactURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no query", "https://host/path", "https://host/path"},
		{"plain token", "https://host/api?token=abc123", "https://host/api?token=***"},
		{"api_key mixed case", "https://h/?Api_Key=xyz&safe=1", "https://h/?Api_Key=***&safe=1"},
		{"multiple secrets", "https://h/?token=a&password=b&q=ok", "https://h/?token=***&password=***&q=ok"},
		{"bare query string", "token=abc&user=joe", "token=***&user=joe"},
		{"flagless pair", "abc&def", "abc&def"},
		{"refresh_token", "https://h/?refresh_token=r", "https://h/?refresh_token=***"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RedactURL(c.in); got != c.want {
				t.Errorf("RedactURL(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestRedactCmdline(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no flags", "/usr/bin/echo hello", "/usr/bin/echo hello"},
		{"long flag space", "myapp --password hunter2 --verbose", "myapp --password *** --verbose"},
		{"long flag equals", "myapp --token=abc123 --verbose", "myapp --token=*** --verbose"},
		{"short -p flag", "psql -p mypass -h localhost", "psql -p *** -h localhost"},
		{"api-key", "tool --api-key=KEEP-PRIVATE", "tool --api-key=***"},
		{"url with token", "curl https://api.example.com/?token=secret", "curl https://api.example.com/?token=***"},
		{"flag at end without value", "foo --password", "foo --password"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RedactCmdline(c.in); got != c.want {
				t.Errorf("RedactCmdline(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestRedactHeader(t *testing.T) {
	cases := []struct {
		name, h, v, want string
	}{
		{"authorization", "Authorization", "Bearer abc.def.ghi", "***"},
		{"cookie", "Cookie", "session=xyz", "***"},
		{"x-api-key", "X-API-Key", "k", "***"},
		{"non-sensitive", "User-Agent", "curl/8", "curl/8"},
		{"empty value", "Authorization", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RedactHeader(c.h, c.v); got != c.want {
				t.Errorf("RedactHeader(%q,%q) = %q, want %q", c.h, c.v, got, c.want)
			}
		})
	}
}
