package client

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"
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
	Disabled   bool            // if true, bypass pool and use SingleResolver
	SingleResolver string     // resolver to use when Disabled=true
	// ProbeDomain is the FreeFlow domain used for probing.
	// Probes send an AAAA query for a subdomain of this domain through each
	// resolver to test that the full path (resolver → Oracle) works and
	// returns AAAA records. Set this to the Oracle's domain.
	ProbeDomain string
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
// schedule. If disabled, returns SingleResolver. If no healthy resolvers
// remain, all are reset to healthy.
func (p *ResolverPool) Next() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Load balancing disabled — use single resolver
	if p.Disabled && p.SingleResolver != "" {
		return p.SingleResolver
	}

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

	// No healthy resolvers — reset all and return first
	log.Printf("[RESOLVER_POOL] No healthy resolvers, resetting all to healthy")
	for _, r := range p.resolvers {
		p.healthy[r] = true
	}
	return p.resolvers[p.index]
}

// ProbeAll tests all resolvers immediately and updates health status.
// Call this on startup to establish which resolvers are actually working.
func (p *ResolverPool) ProbeAll() {
	log.Printf("[RESOLVER_POOL] Initial probe of %d resolvers...", len(p.resolvers))
	p.checkAll()
	log.Printf("[RESOLVER_POOL] Initial probe done: %d/%d healthy", p.HealthyCount(), len(p.resolvers))
}

// SetDisabled enables or disables load balancing.
func (p *ResolverPool) SetDisabled(disabled bool, singleResolver string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Disabled = disabled
	p.SingleResolver = singleResolver
	if disabled {
		log.Printf("[RESOLVER_POOL] Load balancing DISABLED, using single resolver: %s", singleResolver)
	} else {
		log.Printf("[RESOLVER_POOL] Load balancing ENABLED, pool of %d resolvers", len(p.resolvers))
	}
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
		// Probe all resolvers immediately on startup
		p.checkAll()

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

// probe tests whether a resolver can return AAAA records for the FreeFlow
// domain. Sends an AAAA query for a random subdomain through the resolver
// to the Oracle. If the Oracle responds with AAAA records, the resolver works
// for FreeFlow traffic. This tests the FULL path, not just "is resolver alive."
//
// If ProbeDomain is not set, falls back to a basic DNS A query for dns.google.
func (p *ResolverPool) probe(resolver string) bool {
	host := resolver
	if h, _, err := net.SplitHostPort(resolver); err == nil {
		host = h
	}
	host = strings.TrimSpace(host)

	addr := net.JoinHostPort(host, "53")
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	p.mu.RLock()
	domain := p.ProbeDomain
	p.mu.RUnlock()

	var query []byte
	expectAAAA := false
	if domain != "" {
		query = buildAAAAProbe(domain)
		expectAAAA = true
	} else {
		query = buildAProbe()
	}

	if _, err := conn.Write(query); err != nil {
		return false
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return false
	}

	if expectAAAA {
		// Must have at least 1 AAAA answer — proves the full path works
		answerCount := int(buf[6])<<8 | int(buf[7])
		return answerCount > 0
	}
	return true
}

// buildAAAAProbe builds a DNS AAAA query for "probe-XXXX.domain" where XXXX
// is random hex. Random subdomain ensures no caching and tests the Oracle path.
func buildAAAAProbe(domain string) []byte {
	var txid [2]byte
	rand.Read(txid[:])
	var rnd [4]byte
	rand.Read(rnd[:])
	subdomain := fmt.Sprintf("probe-%x", rnd)

	var pkt []byte
	pkt = append(pkt, txid[0], txid[1])
	pkt = append(pkt, 0x01, 0x00) // flags: recursion desired
	pkt = append(pkt, 0x00, 0x01) // questions: 1
	pkt = append(pkt, 0, 0, 0, 0, 0, 0)

	// Encode: subdomain.domain (e.g. probe-abcd1234.v.gamesoft-dl.fun)
	for _, label := range strings.Split(subdomain+"."+domain, ".") {
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, []byte(label)...)
	}
	pkt = append(pkt, 0)           // root
	pkt = append(pkt, 0x00, 0x1C) // AAAA
	pkt = append(pkt, 0x00, 0x01) // IN
	return pkt
}

// buildAProbe builds a basic DNS A query for dns.google (fallback).
func buildAProbe() []byte {
	var txid [2]byte
	rand.Read(txid[:])
	var pkt []byte
	pkt = append(pkt, txid[0], txid[1])
	pkt = append(pkt, 0x01, 0x00)
	pkt = append(pkt, 0x00, 0x01)
	pkt = append(pkt, 0, 0, 0, 0, 0, 0)
	pkt = append(pkt, 3)
	pkt = append(pkt, []byte("dns")...)
	pkt = append(pkt, 6)
	pkt = append(pkt, []byte("google")...)
	pkt = append(pkt, 0)
	pkt = append(pkt, 0x00, 0x01)
	pkt = append(pkt, 0x00, 0x01)
	return pkt
}
