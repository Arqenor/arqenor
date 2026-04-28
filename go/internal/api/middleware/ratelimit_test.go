package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func newTestRouter(rl *IPRateLimiter) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RateLimit(rl))
	r.GET("/probe", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

// TestRateLimit_AllowsBurstThenBlocks fires (burst+1) requests rapidly and
// expects the last one to be 429. Uses a tiny rps so the second-tick
// refill cannot mask the throttle.
func TestRateLimit_AllowsBurstThenBlocks(t *testing.T) {
	rl := NewIPRateLimiter(1, 2) // 1 rps, burst 2
	defer rl.Stop()

	r := newTestRouter(rl)

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		req.RemoteAddr = "1.2.3.4:5555"
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("burst request %d: status = %d, want 200", i, w.Code)
		}
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("post-burst request: status = %d, want 429", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got == "" {
		t.Errorf("Retry-After header missing on 429")
	}
}

func TestRateLimit_PerIPIsolation(t *testing.T) {
	rl := NewIPRateLimiter(1, 1)
	defer rl.Stop()
	r := newTestRouter(rl)

	// Exhaust client A.
	wA := httptest.NewRecorder()
	reqA := httptest.NewRequest(http.MethodGet, "/probe", nil)
	reqA.RemoteAddr = "1.1.1.1:1"
	r.ServeHTTP(wA, reqA)
	wA = httptest.NewRecorder()
	r.ServeHTTP(wA, reqA)
	if wA.Code != http.StatusTooManyRequests {
		t.Fatalf("A second request: status = %d, want 429", wA.Code)
	}

	// Different IP must still pass.
	wB := httptest.NewRecorder()
	reqB := httptest.NewRequest(http.MethodGet, "/probe", nil)
	reqB.RemoteAddr = "2.2.2.2:2"
	r.ServeHTTP(wB, reqB)
	if wB.Code != http.StatusOK {
		t.Fatalf("B first request: status = %d, want 200", wB.Code)
	}
}

func TestClientIP(t *testing.T) {
	cases := map[string]string{
		"":                "unknown",
		"1.2.3.4:80":      "1.2.3.4",
		"[::1]:8080":      "::1",
		"weird":           "weird",
		"127.0.0.1:12345": "127.0.0.1",
	}
	for in, want := range cases {
		if got := clientIP(in); got != want {
			t.Errorf("clientIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRateLimit_GCEvictsIdle(t *testing.T) {
	rl := NewIPRateLimiter(10, 10)
	defer rl.Stop()
	rl.Allow("9.9.9.9")
	rl.mu.Lock()
	if _, ok := rl.limiters["9.9.9.9"]; !ok {
		rl.mu.Unlock()
		t.Fatal("limiter for 9.9.9.9 not registered")
	}
	// Force the entry's lastSeen into the past so evictIdle removes it.
	rl.limiters["9.9.9.9"].lastSeen = time.Now().Add(-2 * idleTTL)
	rl.mu.Unlock()

	rl.evictIdle()

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if _, ok := rl.limiters["9.9.9.9"]; ok {
		t.Error("idle limiter was not evicted")
	}
}
