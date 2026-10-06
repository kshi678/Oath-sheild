package middleware

import (
	"context"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/yourname/goauth-shield/internal/httpx"
)

type client struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter is a per-IP token bucket. State is in memory, so with several
// instances each enforces its own limit (use a shared store such as Redis or
// an edge limiter if you need a global limit).
type RateLimiter struct {
	mu         sync.Mutex
	clients    map[string]*client
	rps        rate.Limit
	burst      int
	trustProxy bool
	retryAfter string
}

func NewRateLimiter(ctx context.Context, rps float64, burst int, trustProxy bool) *RateLimiter {
	rl := &RateLimiter{
		clients:    make(map[string]*client),
		rps:        rate.Limit(rps),
		burst:      burst,
		trustProxy: trustProxy,
		retryAfter: strconv.Itoa(int(math.Max(1, math.Ceil(1/rps)))),
	}
	go rl.cleanup(ctx)
	return rl
}

func (rl *RateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	c, ok := rl.clients[ip]
	if !ok {
		c = &client{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.clients[ip] = c
	}
	c.lastSeen = time.Now()
	return c.limiter.Allow()
}

func (rl *RateLimiter) cleanup(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rl.mu.Lock()
			for ip, c := range rl.clients {
				if time.Since(c.lastSeen) > 10*time.Minute {
					delete(rl.clients, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(ClientIP(r, rl.trustProxy)) {
			w.Header().Set("Retry-After", rl.retryAfter)
			httpx.WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many requests, slow down")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ClientIP returns the caller's IP. X-Forwarded-For is honoured only when
// trustProxy is set, because clients can otherwise spoof it to dodge limits.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if ip := strings.TrimSpace(first); net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
