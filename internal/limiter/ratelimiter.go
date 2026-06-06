package limiter

import (
	"net"
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

type IPLimiter struct {
	mu      sync.Mutex
	clients map[string]*rate.Limiter
}

func (i *IPLimiter) getLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter, exists := i.clients[ip]
	if !exists {
		limiter = rate.NewLimiter(2, 5)
		i.clients[ip] = limiter
	}

	return limiter
}

func rateLimiterMiddleware(next http.Handler, ipStore *IPLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		limiter := ipStore.getLimiter(ip)

		if !limiter.Allow() {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
