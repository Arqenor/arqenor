// Package middleware contains the orchestrator-side Gin middlewares.
//
// ratelimit.go implements a per-IP token-bucket rate limiter backed by
// golang.org/x/time/rate. Limiters are kept in a map keyed by client IP
// and garbage-collected after a quiet period to bound memory under
// scan-storm conditions.
package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// idleTTL — limiters with no traffic for this long are evicted.
const idleTTL = 5 * time.Minute

// gcInterval — how often the eviction goroutine wakes up.
const gcInterval = 1 * time.Minute

// ipLimiter wraps a rate.Limiter with the timestamp of the last request
// it served, so the GC can decide whether to evict it.
type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// IPRateLimiter is a process-wide registry of per-IP token buckets.
//
// Safe for concurrent use. The zero value is *not* usable — construct via
// NewIPRateLimiter.
type IPRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*ipLimiter
	rps      rate.Limit
	burst    int

	stop chan struct{}
}

// NewIPRateLimiter builds a rate limiter with the given steady-state rate
// (requests/sec) and burst size. The garbage-collection goroutine starts
// immediately and runs until Stop is called.
func NewIPRateLimiter(rps, burst int) *IPRateLimiter {
	if rps <= 0 {
		rps = 1
	}
	if burst <= 0 {
		burst = rps * 2
	}

	rl := &IPRateLimiter{
		limiters: make(map[string]*ipLimiter),
		rps:      rate.Limit(rps),
		burst:    burst,
		stop:     make(chan struct{}),
	}

	go rl.gcLoop()
	return rl
}

// Stop terminates the GC goroutine. Idempotent.
func (rl *IPRateLimiter) Stop() {
	select {
	case <-rl.stop:
		// already closed
	default:
		close(rl.stop)
	}
}

// Allow consumes one token for the given IP. Returns false if the bucket
// is empty (caller should respond with 429).
func (rl *IPRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	entry, ok := rl.limiters[ip]
	if !ok {
		entry = &ipLimiter{
			limiter:  rate.NewLimiter(rl.rps, rl.burst),
			lastSeen: time.Now(),
		}
		rl.limiters[ip] = entry
	} else {
		entry.lastSeen = time.Now()
	}
	rl.mu.Unlock()
	return entry.limiter.Allow()
}

func (rl *IPRateLimiter) gcLoop() {
	ticker := time.NewTicker(gcInterval)
	defer ticker.Stop()
	for {
		select {
		case <-rl.stop:
			return
		case <-ticker.C:
			rl.evictIdle()
		}
	}
}

func (rl *IPRateLimiter) evictIdle() {
	cutoff := time.Now().Add(-idleTTL)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for ip, entry := range rl.limiters {
		if entry.lastSeen.Before(cutoff) {
			delete(rl.limiters, ip)
		}
	}
}

// retryAfterSeconds — the value advertised in the Retry-After header when
// a request is throttled. We expose the wait time the caller would need
// to recover one full token (1 / rps), rounded up to the next second.
func (rl *IPRateLimiter) retryAfterSeconds() int {
	if rl.rps <= 0 {
		return 1
	}
	secs := int(1.0/float64(rl.rps) + 0.999)
	if secs < 1 {
		secs = 1
	}
	return secs
}

// RateLimit returns a Gin middleware that throttles requests by source IP.
//
// The IP is derived from the request's RemoteAddr; deployments behind a
// reverse proxy must front the orchestrator with something that strips
// X-Forwarded-For (or extend this middleware to consume it). On throttle,
// responds 429 with a Retry-After header.
func RateLimit(rl *IPRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := clientIP(c.Request.RemoteAddr)
		if !rl.Allow(ip) {
			retry := rl.retryAfterSeconds()
			c.Header("Retry-After", strconv.Itoa(retry))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "rate limit exceeded",
				"retry_after": fmt.Sprintf("%ds", retry),
			})
			return
		}
		c.Next()
	}
}

// clientIP extracts the host portion of a "host:port" string. Falls back
// to the input verbatim if SplitHostPort fails (covers IPv6 brackets and
// odd corner cases) — over-approximating the key just makes the limit
// stricter, which is acceptable.
func clientIP(remoteAddr string) string {
	if remoteAddr == "" {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	// Try stripping a leading bracketed IPv6 form just in case.
	if i := strings.LastIndexByte(remoteAddr, ':'); i > 0 {
		return remoteAddr[:i]
	}
	return remoteAddr
}
