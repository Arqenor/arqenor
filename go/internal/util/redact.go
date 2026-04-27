// Package util provides small cross-package helpers.
//
// redact.go masks credential-like material (CLI flags, query strings,
// HTTP headers) before that material reaches a structured logger.
// Defense-in-depth: even if upstream code accidentally logs a request
// URL or a process command line, the secret should already be replaced
// by "***".
package util

import (
	"net/url"
	"strings"
)

const placeholder = "***"

// sensitiveQueryKeys lists query-string parameter names whose values
// must be redacted. Match is case-insensitive.
var sensitiveQueryKeys = map[string]struct{}{
	"token":         {},
	"access_token":  {},
	"refresh_token": {},
	"key":           {},
	"api_key":       {},
	"apikey":        {},
	"secret":        {},
	"password":      {},
	"passwd":        {},
	"auth":          {},
	"authorization": {},
	"sig":           {},
	"signature":     {},
}

// sensitiveCmdFlags lists CLI flags whose *next* argv element must be
// redacted (long form: --password VALUE / short form: -p VALUE).
// Long forms also recognised in their `--flag=value` shape.
var sensitiveCmdFlags = []string{
	"--password",
	"--passwd",
	"--token",
	"--access-token",
	"--refresh-token",
	"--api-key",
	"--apikey",
	"--secret",
	"--key",
	"--auth",
	"--authorization",
	"-p",
}

// RedactURL masks sensitive query-string values in a URL.
//
// Accepts either a full URL ("https://host/path?token=abc") or a bare
// query string ("token=abc&key=xyz"). The path/scheme/host are returned
// untouched. Unparseable inputs are returned as-is — this function is
// best-effort and never returns an error, by design (it sits in the log
// path and must not panic / fail).
func RedactURL(raw string) string {
	if raw == "" {
		return raw
	}

	// If it parses as a URL with a scheme, redact only the RawQuery.
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" {
		if u.RawQuery == "" {
			return raw
		}
		u.RawQuery = redactQuery(u.RawQuery)
		return u.String()
	}

	// Otherwise treat the whole input as a query string.
	return redactQuery(raw)
}

// redactQuery walks a `k=v&k2=v2` query string and replaces values whose
// keys appear in sensitiveQueryKeys.
//
// Hand-rolled rather than using url.Values to preserve original key
// ordering and the original separator characters (logs are easier to
// diff that way).
func redactQuery(q string) string {
	if q == "" {
		return q
	}

	var b strings.Builder
	b.Grow(len(q))

	first := true
	for _, pair := range strings.Split(q, "&") {
		if !first {
			b.WriteByte('&')
		}
		first = false

		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			b.WriteString(pair)
			continue
		}
		key := pair[:eq]
		if _, sensitive := sensitiveQueryKeys[strings.ToLower(key)]; sensitive {
			b.WriteString(key)
			b.WriteByte('=')
			b.WriteString(placeholder)
			continue
		}
		b.WriteString(pair)
	}

	return b.String()
}

// RedactCmdline masks the values of credential-like flags inside a
// process command line.
//
// Handles:
//   - "--password value"     → "--password ***"
//   - "--password=value"     → "--password=***"
//   - "-p value"             → "-p ***"
//   - URL-shaped tokens via RedactURL on each token containing a "?"
//
// Splitting is done on whitespace; we do not attempt full POSIX shell
// parsing — that's overkill for a logger and would mask hide bugs. If
// the input was already shell-quoted, the quoting is preserved as-is.
func RedactCmdline(cmd string) string {
	if cmd == "" {
		return cmd
	}

	tokens := strings.Fields(cmd)
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]

		// --flag=value form.
		if eq := strings.IndexByte(tok, '='); eq > 0 {
			flag := tok[:eq]
			if isSensitiveFlag(flag) {
				tokens[i] = flag + "=" + placeholder
				continue
			}
		}

		// --flag value / -p value form.
		if isSensitiveFlag(tok) && i+1 < len(tokens) {
			tokens[i+1] = placeholder
			i++ // skip the value we just redacted
			continue
		}

		// URLs embedded in the cmdline (e.g. curl ... https://api/?token=x).
		if strings.Contains(tok, "?") && (strings.HasPrefix(tok, "http://") || strings.HasPrefix(tok, "https://")) {
			tokens[i] = RedactURL(tok)
			continue
		}
	}

	return strings.Join(tokens, " ")
}

// RedactHeader returns the placeholder for sensitive header names,
// otherwise returns the value unchanged. Header name match is
// case-insensitive (HTTP headers are case-insensitive per RFC 9110).
func RedactHeader(name, value string) string {
	switch strings.ToLower(name) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token":
		if value == "" {
			return value
		}
		return placeholder
	}
	return value
}

func isSensitiveFlag(flag string) bool {
	for _, f := range sensitiveCmdFlags {
		if flag == f {
			return true
		}
	}
	return false
}
