package server

import (
	"net"
	"time"
)

const (
	newTunnelLimiterSweepInterval = time.Minute
	newTunnelLimiterMaxSources    = 4096
)

// newTunnelLimiter is a per-source-IP token bucket. Engine serializes access
// to it. The source table is capped because UDP source addresses can be
// spoofed; once full, previously unseen sources are denied until idle entries
// are swept rather than allowing limiter bookkeeping itself to exhaust memory.
type newTunnelLimiter struct {
	rate      float64
	burst     float64
	lastSweep time.Time
	buckets   map[string]*newTunnelBucket
}

type newTunnelBucket struct {
	tokens float64
	last   time.Time
}

func newNewTunnelLimiter(ratePerSecond float64, burst int) *newTunnelLimiter {
	return &newTunnelLimiter{rate: ratePerSecond, burst: float64(burst), buckets: make(map[string]*newTunnelBucket)}
}

func (l *newTunnelLimiter) allow(ip string, now time.Time) bool {
	if l.lastSweep.IsZero() || now.Before(l.lastSweep) {
		l.lastSweep = now
	}
	if now.Sub(l.lastSweep) >= newTunnelLimiterSweepInterval {
		l.sweep(now)
		l.lastSweep = now
	}
	bucket := l.buckets[ip]
	if bucket == nil {
		if len(l.buckets) >= newTunnelLimiterMaxSources {
			l.sweep(now)
			if len(l.buckets) >= newTunnelLimiterMaxSources {
				return false
			}
		}
		bucket = &newTunnelBucket{tokens: l.burst, last: now}
		l.buckets[ip] = bucket
	}
	if elapsed := now.Sub(bucket.last).Seconds(); elapsed > 0 {
		bucket.tokens = min(l.burst, bucket.tokens+elapsed*l.rate)
		bucket.last = now
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func (l *newTunnelLimiter) sweep(now time.Time) {
	idleLimit := time.Duration(l.burst/l.rate*float64(time.Second)) * 4
	if idleLimit < newTunnelLimiterSweepInterval {
		idleLimit = newTunnelLimiterSweepInterval
	}
	for ip, bucket := range l.buckets {
		if now.Sub(bucket.last) > idleLimit {
			delete(l.buckets, ip)
		}
	}
}

func sourceIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		return udp.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}
	return addr.String()
}
