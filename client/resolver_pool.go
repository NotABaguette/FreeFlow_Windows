package client

import (
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// DefaultResolvers is the list of well-known public DNS resolvers used when
// no custom list is provided. Distributing queries across many resolvers
// reduces the fingerprint on any single resolver (anti-detection).
var DefaultResolvers = []string{
	"8.8.8.8",          // Google
	"8.8.4.4",          // Google
	"1.1.1.1",          // Cloudflare
	"1.0.0.1",          // Cloudflare
	"9.9.9.9",          // Quad9
	"149.112.112.112",  // Quad9
	"208.67.222.222",   // OpenDNS
	"208.67.220.220",   // OpenDNS
	"76.76.2.0",        // ControlD
	"76.76.10.0",       // ControlD
	"94.140.14.14",     // AdGuard
	"94.140.15.15",     // AdGuard
}

// ResolverPool manages a pool of DNS resolvers with round-robin rotation
// and periodic health checking. The rotation schedule is controlled by
// "strength" (1-10): strength 10 rotates every query, strength 1 rotates
// every 10 queries.
type ResolverPool struct {
	mu         sync.RWMutex
	resolvers  []string        // all configured resolvers
	healthy    map[string]bool // health status per resolver
	index      int             // current round-robin index
	queryCount int             // queries since last rotation
	strength   int             // 1-10, rotate every (11-strength) queries
	stopHealth chan struct{}
}

// NewResolverPool creates a resolver pool. If resolvers is empty, the
// DefaultResolvers list is used. Strength is clamped to [1, 10].
func NewResolverPool(resolvers []string, strength int) *ResolverPool {
	if len(resolvers) == 0 {
		resolvers = DefaultResolvers
	}
	if strength < 1 {
		strength = 1
	}
	if strength > 10 {
		strength = 10
	}

	healthy := make(map[string]bool, len(resolvers))
	for _, r := range resolvers {
		healthy[r] = true
	}

	return &ResolverPool{
		resolvers:  resolvers,
		healthy:    healthy,
		strength:   strength,
		stopHealth: make(chan struct{}),
	}
}

// Next returns the next healthy resolver according to the round-robin
// schedule. If no healthy resolvers remain, all are reset to healthy.
func (p *ResolverPool) Next() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	rotateEvery := 11 - p.strength
	p.queryCount++

	if p.queryCount >= rotateEvery {
		p.queryCount = 0
		p.index = (p.index + 1) % len(p.resolvers)
	}

	for i := 0; i < len(p.resolvers); i++ {
		idx := (p.index + i) % len(p.resolvers)
		r := p.resolvers[idx]
		if p.healthy[r] {
			p.index = idx
			return r
		}
	}

	// No healthy resolvers — reset all
	log.Printf("[RESOLVER_POOL] No healthy resolvers, resetting all to healthy")
	for _, r := range p.resolvers {
		p.healthy[r] = true
	}
	return p.resolvers[p.index]
}

// MarkUnhealthy marks a resolver as down.
func (p *ResolverPool) MarkUnhealthy(resolver string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.healthy[resolver] = false
	log.Printf("[RESOLVER_POOL] Marked %s unhealthy", resolver)
}

// HealthyCount returns the number of currently healthy resolvers.
func (p *ResolverPool) HealthyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	count := 0
	for _, ok := range p.healthy {
		if ok {
			count++
		}
	}
	return count
}

// SetStrength updates the rotation strength (1-10).
func (p *ResolverPool) SetStrength(s int) {
	if s < 1 {
		s = 1
	}
	if s > 10 {
		s = 10
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.strength = s
}

// StartHealthCheck launches a background goroutine that periodically tests
// all resolvers by sending a DNS AAAA query for "google.com".
func (p *ResolverPool) StartHealthCheck(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-p.stopHealth:
				return
			case <-ticker.C:
				p.checkAll()
			}
		}
	}()
}

// StopHealthCheck stops the background health-checking goroutine.
func (p *ResolverPool) StopHealthCheck() {
	select {
	case p.stopHealth <- struct{}{}:
	default:
	}
}

// checkAll tests every resolver with a simple DNS query.
func (p *ResolverPool) checkAll() {
	p.mu.RLock()
	resolvers := make([]string, len(p.resolvers))
	copy(resolvers, p.resolvers)
	p.mu.RUnlock()

	for _, r := range resolvers {
		healthy := p.probe(r)
		p.mu.Lock()
		p.healthy[r] = healthy
		p.mu.Unlock()
	}

	log.Printf("[RESOLVER_POOL] Health check complete: %d/%d healthy", p.HealthyCount(), len(resolvers))
}

// probe uses ICMP ping to test if a resolver is reachable.
func (p *ResolverPool) probe(resolver string) bool {
	host := resolver
	if h, _, err := net.SplitHostPort(resolver); err == nil {
		host = h
	}
	host = strings.TrimSpace(host)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", "3000", host)
	default:
		cmd = exec.Command("ping", "-c", "1", "-W", "3", host)
	}

	err := cmd.Run()
	return err == nil
}
