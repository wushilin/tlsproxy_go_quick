package main

// Speed limits: max_aggregated_speed (one token bucket per rule and direction,
// shared by all its connections) and max_single_connection_speed (one per
// connection and direction).

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// limiter is a token bucket, kept lock-free as GCRA (the generic cell rate
// algorithm): one atomic number, the theoretical arrival time "tat" until
// which the bucket is spent. Charging n bytes moves tat forward by n/rate;
// the caller waits for whatever exceeds the burst allowance. Many
// connections sharing one rule's limiter charge it with a compare-and-swap,
// never a lock.
type limiter struct {
	rate     float64 // bytes per second
	burst    float64
	perByte  float64      // nanoseconds one byte costs
	burstDur int64        // how far ahead of now tat may run before callers wait
	tat      atomic.Int64 // unix nanoseconds
}

func newLimiter(bytesPerSec float64, bufferSize int) *limiter {
	if bytesPerSec <= 0 {
		return nil
	}
	burst := float64(limitedChunk(bytesPerSec, bufferSize))
	l := &limiter{rate: bytesPerSec, burst: burst, perByte: 1e9 / bytesPerSec}
	l.burstDur = int64(burst * l.perByte)
	l.tat.Store(time.Now().UnixNano()) // starts full: nothing owed
	return l
}

// limitedChunk sizes copies so a limited flow moves about 20 chunks a second,
// which keeps even a few hundred bytes per second smooth.
func limitedChunk(bytesPerSec float64, bufferSize int) int {
	return max(256, min(int(bytesPerSec/20), bufferSize))
}

// reserve charges n bytes and returns how long the caller must wait.
func (l *limiter) reserve(n int64) time.Duration {
	cost := int64(float64(n) * l.perByte)
	for {
		now := time.Now().UnixNano()
		old := l.tat.Load()
		// Idle time refills the bucket, but never beyond the burst: credit is
		// what "now" is ahead of tat, and only burstDur of it can be used.
		next := max(old, now) + cost
		if l.tat.CompareAndSwap(old, next) {
			if wait := next - now - l.burstDur; wait > 0 {
				return time.Duration(wait)
			}
			return 0
		}
	}
}

// waitAll charges n bytes to every non-nil limiter and sleeps until all of
// them allow it. It returns false when cancel closes: the bytes must then not
// be forwarded.
func waitAll(n int64, cancel <-chan struct{}, limiters ...*limiter) bool {
	var d time.Duration
	for _, l := range limiters {
		if l != nil {
			d = max(d, l.reserve(n))
		}
	}
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-cancel:
		return false
	}
}

// parseRate reads a bandwidth such as "100Mbit", "2.5 Gbps", "800KB/s" or
// "64MiB/s" and returns bytes per second. Bit units and KB/MB/GB are decimal;
// KiB/MiB/GiB are binary.
func parseRate(s string) (float64, error) {
	orig := s
	s = strings.TrimSuffix(strings.TrimSpace(s), "/s")
	i := strings.IndexFunc(s, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if i <= 0 {
		return 0, fmt.Errorf("invalid rate %q: want a number and a unit, like 100Mbit or 50MB/s", orig)
	}
	n, err := strconv.ParseFloat(s[:i], 64)
	if err != nil || n <= 0 || math.IsInf(n, 0) {
		return 0, fmt.Errorf("invalid rate %q: the number must be positive", orig)
	}
	unit := strings.TrimSpace(s[i:])
	multipliers := map[string]float64{
		"bit": 1.0 / 8, "bps": 1.0 / 8,
		"kbit": 1e3 / 8, "kbps": 1e3 / 8, "mbit": 1e6 / 8, "mbps": 1e6 / 8,
		"gbit": 1e9 / 8, "gbps": 1e9 / 8,
		"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9,
		"kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30,
	}
	// "B" means bytes and "b" bits only in the short forms; the spelled-out
	// units ignore case.
	key := strings.ToLower(unit)
	if unit == "b" || unit == "Kb" || unit == "Mb" || unit == "Gb" {
		key += "it"
	}
	m, ok := multipliers[key]
	if !ok {
		return 0, fmt.Errorf("invalid rate %q: unknown unit %q (use bit, Kbit, Mbit, Gbit, B, KB, MB, GB, KiB, MiB or GiB, optionally with /s)", orig, unit)
	}
	if n*m < 1 {
		return 0, fmt.Errorf("invalid rate %q: less than one byte per second", orig)
	}
	return n * m, nil
}

// humanRate formats bytes per second with binary units for logs.
func humanRate(bytesPerSec float64) string {
	v := bytesPerSec
	for _, u := range []string{"B/s", "KiB/s", "MiB/s", "GiB/s"} {
		if v < 1024 || u == "GiB/s" {
			return strconv.FormatFloat(math.Round(v*100)/100, 'f', -1, 64) + " " + u
		}
		v /= 1024
	}
	return ""
}

// ruleLimits are a rule's shared buckets, one per direction.
type ruleLimits struct {
	rate float64
	dir  [2]*limiter
}

// newRuleLimits builds the shared buckets for every rule with
// max_aggregated_speed. A rule whose listener, pattern and rate are unchanged keeps the
// buckets of prev, so connections from before and after a reload share them
// and the rule never gets the budget twice.
func newRuleLimits(cfg *Config, prev map[string]*ruleLimits) (map[*Rule]*ruleLimits, map[string]*ruleLimits) {
	byRule, bySource := map[*Rule]*ruleLimits{}, map[string]*ruleLimits{}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.MaxAggregatedSpeed == 0 {
			continue
		}
		l := prev[r.Key()]
		if l == nil || l.rate != r.MaxAggregatedSpeed {
			l = &ruleLimits{rate: r.MaxAggregatedSpeed}
			for d := range l.dir {
				l.dir[d] = newLimiter(r.MaxAggregatedSpeed, cfg.BufferSize)
			}
		}
		byRule[r], bySource[r.Key()] = l, l
	}
	return byRule, bySource
}

// describeLimits is the connected log line's note about speed limits.
func describeLimits(r *Rule) string {
	var parts []string
	if r.MaxSingleConnectionSpeed > 0 {
		parts = append(parts, humanRate(r.MaxSingleConnectionSpeed)+" per connection")
	}
	if r.MaxAggregatedSpeed > 0 {
		parts = append(parts, humanRate(r.MaxAggregatedSpeed)+" for all connections of this rule")
	}
	if len(parts) == 0 {
		return ""
	}
	return "speed limit " + strings.Join(parts, ", ") + ", each direction"
}
