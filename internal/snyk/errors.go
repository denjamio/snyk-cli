package snyk

import (
	"fmt"
	"net/http"
)

// Kind classifies a client failure. Machine consumers branch on it — via
// the envelope's error.kind — instead of matching message strings.
type Kind string

const (
	KindAuth      Kind = "auth"       // 401/403: token missing, revoked or unauthorized
	KindNotFound  Kind = "not_found"  // 404: unknown org, project or issue id
	KindRateLimit Kind = "rate_limit" // 429: rate limited past the retry budget
	KindTransient Kind = "transient"  // 502/503/504: upstream down past the retry budget
	KindNetwork   Kind = "network"    // transport failure: refused/reset connection, timeout, TLS
	KindAPI       Kind = "api"        // any other non-200 HTTP status
	KindDecode    Kind = "decode"     // a 200 response whose body is not the expected JSON
)

// Error is the typed failure the client returns for HTTP and decode
// errors; transport failures are wrapped too, so network classification
// survives the call stack. Error() renders the wrapped message unchanged.
type Error struct {
	Kind   Kind
	Status int // HTTP status for HTTP kinds, 0 otherwise
	err    error
}

func (e *Error) Error() string { return e.err.Error() }
func (e *Error) Unwrap() error { return e.err }

// kindForStatus maps an HTTP status to its failure kind.
func kindForStatus(code int) Kind {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden:
		return KindAuth
	case http.StatusNotFound:
		return KindNotFound
	case http.StatusTooManyRequests:
		return KindRateLimit
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return KindTransient
	default:
		return KindAPI
	}
}

// apiError builds the typed error for a non-200 response.
func apiError(code int, format string, args ...any) *Error {
	return &Error{Kind: kindForStatus(code), Status: code, err: fmt.Errorf(format, args...)}
}

// decodeError builds the typed error for a 200 response the client cannot
// parse.
func decodeError(format string, args ...any) *Error {
	return &Error{Kind: KindDecode, err: fmt.Errorf(format, args...)}
}
