package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// Hop represents a single traceroute hop.
type Hop struct {
	TTL         int
	IP          net.IP         // nil for * hops
	RTT         time.Duration
	Unreachable bool            // true when hop has !H, !N, !X suffix
}

// TraceResult holds the complete traceroute result for one target IP.
type TraceResult struct {
	TargetIP net.IP
	Hops     []Hop
	Complete bool    // true if traceroute reached target or hit max hops
	Error    string  // non-empty if traceroute failed
}

// unreachableSuffixes contains the ICMP unreachable signatures that set
// Unreachable=true on a hop.
var unreachableSuffixes = []string{"!H", "!N", "!X"}

// ParseHopLine parses a single traceroute output line and returns a Hop.
// Returns nil for header lines, blank lines, and timeout lines.
//
// Standard:     " 8  223.120.3.201  39.160 ms" → Hop{TTL:8, IP:223.120.3.201, RTT:39.16ms}
// No response:  " 9  *"                        → nil
// Unreachable:  " 8  1.2.3.4 !H  1.234 ms"     → Hop{IP:1.2.3.4, Unreachable:true}
// Header:       "traceroute to 1.2.3.4 (1.2.3.4), 30 hops max, 60 byte packets" → nil
func ParseHopLine(line string) *Hop {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	// Skip header lines.
	if strings.HasPrefix(line, "traceroute to ") {
		return nil
	}

	// Split on whitespace.
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}

	// First field is TTL.
	ttl, err := parseInt(fields[0])
	if err != nil {
		return nil
	}

	// Second field is either "*" (no response) or an IP address.
	ipField := fields[1]
	if ipField == "*" {
		return nil
	}

	// Check for unreachable suffix: it may be attached to the IP field
	// (e.g. "1.2.3.4!H") or in the next field (e.g. "1.2.3.4 !H").
	ipStr, unreachable := stripUnreachable(ipField)
	if !unreachable && len(fields) > 2 {
		unreachable = hasUnreachableSuffix(fields[2])
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	// Find the "ms" token and parse the RTT from the field before it.
	var rtt time.Duration
	for i, f := range fields {
		if f == "ms" && i > 0 {
			rttStr := fields[i-1]
			// Some locales use comma as decimal separator.
			rttStr = strings.ReplaceAll(rttStr, ",", ".")
			d, err := time.ParseDuration(rttStr + "ms")
			if err == nil {
				rtt = d
			}
			break
		}
	}

	return &Hop{
		TTL:         ttl,
		IP:          ip,
		RTT:         rtt,
		Unreachable: unreachable,
	}
}

// stripUnreachable checks if ipField ends with an unreachable suffix and
// returns the clean IP and whether it was unreachable.
func stripUnreachable(ipField string) (string, bool) {
	for _, suffix := range unreachableSuffixes {
		if strings.HasSuffix(ipField, suffix) {
			return strings.TrimSuffix(ipField, suffix), true
		}
	}
	return ipField, false
}

// parseInt parses an integer from a string. Returns 0 and an error on failure.
func parseInt(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number: %s", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// hasUnreachableSuffix checks if s ends with any ICMP unreachable marker.
func hasUnreachableSuffix(s string) bool {
	for _, suffix := range unreachableSuffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}

// DedupBy24 groups IPs by /24 subnet and returns one IP per subnet.
// For each /24, the IP with the lowest numeric value is kept.
//
// Note: Cloudflare uses anycast BGP — different /32s within the same /24
// may route differently. This is a best-effort optimization only.
func DedupBy24(ips []net.IP) []net.IP {
	type candidate struct {
		ip    net.IP
		order int
	}

	// Group by /24 key (3 bytes for IPv4).
	groups := make(map[[3]byte]candidate)
	for i, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			// Keep IPv6 addresses as-is.
			continue
		}
		var key [3]byte
		copy(key[:], ip4[:3])

		existing, ok := groups[key]
		if !ok {
			groups[key] = candidate{ip: ip, order: i}
			continue
		}
		// Keep the IP with the lower numeric value (compare last byte).
		if ip4[3] < existing.ip.To4()[3] {
			groups[key] = candidate{ip: ip, order: i}
		}
	}

	result := make([]net.IP, 0, len(groups))
	for _, c := range groups {
		result = append(result, c.ip)
	}
	// Sort by original order for determinism.
	sort.Slice(result, func(i, j int) bool {
		return findOrder(result[i], ips) < findOrder(result[j], ips)
	})
	return result
}

// findOrder returns the index of ip in ips, or a large number if not found.
func findOrder(ip net.IP, ips []net.IP) int {
	for i, candidate := range ips {
		if ip.Equal(candidate) {
			return i
		}
	}
	return len(ips)
}

// CheckpointManager persists traceroute progress to a JSON file so the
// process can be resumed after interruption.
type CheckpointManager struct {
	checkpointPath string
	mu             sync.Mutex
}

// CheckpointData is serialized to JSON for resume support.
type CheckpointData struct {
	CompletedIPs []string `json:"completed_ips"`
	CompletedSet map[string]bool `json:"-"`          // in-memory only
	DedupMode    string   `json:"dedup_mode"`
	StartTime    time.Time `json:"start_time"`
}

// NewCheckpointManager creates a CheckpointManager that stores data at
// /tmp/.cmin2-trace-checkpoint.json.
func NewCheckpointManager(dedupMode string) *CheckpointManager {
	if dedupMode == "" {
		dedupMode = "/24"
	}
	return &CheckpointManager{
		checkpointPath: "/tmp/.cmin2-trace-checkpoint.json",
	}
}

// Load reads checkpoint data from disk. Returns nil data without error if
// no checkpoint exists.
func (cm *CheckpointManager) Load() (*CheckpointData, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	data, err := os.ReadFile(cm.checkpointPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read checkpoint: %w", err)
	}

	var cp CheckpointData
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("unmarshal checkpoint: %w", err)
	}

	// Rebuild the in-memory set.
	cp.CompletedSet = make(map[string]bool, len(cp.CompletedIPs))
	for _, ip := range cp.CompletedIPs {
		cp.CompletedSet[ip] = true
	}
	if cp.CompletedSet == nil {
		cp.CompletedSet = make(map[string]bool)
	}

	return &cp, nil
}

// Save atomically writes checkpoint data to disk.
func (cm *CheckpointManager) Save(data *CheckpointData) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Rebuild the serialized slice from the set for consistency.
	data.CompletedIPs = make([]string, 0, len(data.CompletedSet))
	for ip := range data.CompletedSet {
		data.CompletedIPs = append(data.CompletedIPs, ip)
	}
	sort.Strings(data.CompletedIPs)

	tmpPath := cm.checkpointPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create checkpoint tmp: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return fmt.Errorf("encode checkpoint: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close checkpoint tmp: %w", err)
	}
	if err := os.Rename(tmpPath, cm.checkpointPath); err != nil {
		return fmt.Errorf("rename checkpoint: %w", err)
	}
	return nil
}

// MarkCompleted records an IP as completed and persists the checkpoint.
func (cm *CheckpointManager) MarkCompleted(data *CheckpointData, ip string) {
	cm.mu.Lock()
	data.CompletedSet[ip] = true
	cm.mu.Unlock()
}

// IsCompleted checks if an IP has already been traced.
func (cm *CheckpointManager) IsCompleted(data *CheckpointData, ip string) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return data.CompletedSet[ip]
}

// Clear removes the checkpoint file from disk.
func (cm *CheckpointManager) Clear() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if err := os.Remove(cm.checkpointPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove checkpoint: %w", err)
	}
	return nil
}

// ParseTracerouteOutput parses the full stdout output of a traceroute command
// and returns a TraceResult.
func ParseTracerouteOutput(output string, targetIP net.IP) *TraceResult {
	result := &TraceResult{
		TargetIP: targetIP,
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		hop := ParseHopLine(line)
		if hop == nil {
			continue
		}
		result.Hops = append(result.Hops, *hop)
	}

	// Determine completion: last hop IP approximates target (same /24) or
	// all 30 hops were used.
	if len(result.Hops) > 0 {
		last := result.Hops[len(result.Hops)-1]
		if last.IP != nil && last.TTL <= 30 {
			// Check if last hop is in the same /24 as target, or is
			// the exact target.
			if ipsSame24(last.IP, targetIP) {
				result.Complete = true
			}
			// If we used all 30 hops, consider it complete even if
			// target was not reached.
			if last.TTL >= 30 {
				result.Complete = true
			}
		}
	}

	// Also mark complete if any hop exactly matches the target.
	if !result.Complete {
		for _, h := range result.Hops {
			if h.IP != nil && h.IP.Equal(targetIP) {
				result.Complete = true
				break
			}
		}
	}

	return result
}

// ipsSame24 checks if two IPv4 addresses share the same /24 prefix.
func ipsSame24(a, b net.IP) bool {
	a4 := a.To4()
	b4 := b.To4()
	if a4 == nil || b4 == nil {
		return false
	}
	return a4[0] == b4[0] && a4[1] == b4[1] && a4[2] == b4[2]
}

// TracerouteRunner manages concurrent traceroute execution with checkpoint
// resume, CGNAT-safe pacing, and context-based cancellation.
type TracerouteRunner struct {
	Concurrent    int           // worker count (default 20)
	Cooldown      time.Duration // between batches (default 10s)
	PerIPTimeout  time.Duration // per-traceroute timeout (default 30s)
	Checkpoint    *CheckpointManager
}

// NewTracerouteRunner creates a TracerouteRunner with sensible defaults.
func NewTracerouteRunner() *TracerouteRunner {
	return &TracerouteRunner{
		Concurrent:   20,
		Cooldown:     10 * time.Second,
		PerIPTimeout: 30 * time.Second,
		Checkpoint:   NewCheckpointManager("/24"),
	}
}

// Run executes traceroutes against the given IPs. If resume is true and a
// checkpoint exists, already-completed IPs are skipped.
//
// Workers are limited by a semaphore (buffered channel). After each batch
// of Concurrent workers, a cooldown sleep prevents overwhelming CGNAT
// infrastructure. Context cancellation kills all running traceroute
// subprocesses via exec.CommandContext.
func (tr *TracerouteRunner) Run(ctx context.Context, ips []net.IP, resume bool) map[string]*TraceResult {
	results := make(map[string]*TraceResult, len(ips))
	var mu sync.Mutex

	// Load checkpoint state for resume.
	var cp *CheckpointData
	if resume {
		var err error
		cp, err = tr.Checkpoint.Load()
		if err != nil {
			log.Printf("warning: failed to load checkpoint: %v", err)
		}
		if cp == nil {
			cp = &CheckpointData{
				CompletedSet: make(map[string]bool),
				DedupMode:    "/24",
				StartTime:    time.Now(),
			}
		}
	}

	// Semaphore for concurrency control.
	sem := make(chan struct{}, tr.Concurrent)

	total := len(ips)
	completed := 0
	batchCount := 0

	for i, ip := range ips {
		ipStr := ip.String()

		// Resume check.
		if resume && cp != nil && tr.Checkpoint.IsCompleted(cp, ipStr) {
			mu.Lock()
			results[ipStr] = &TraceResult{
				TargetIP: ip,
				Hops:     []Hop{},
				Complete: true,
			}
			completed++
			mu.Unlock()
			log.Printf("skipped IP %s (already completed, %d/%d)", ipStr, completed, total)
			continue
		}

		// Acquire semaphore slot (respects context cancellation).
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			mu.Lock()
			results[ipStr] = &TraceResult{
				TargetIP: ip,
				Error:    ctx.Err().Error(),
			}
			mu.Unlock()
			return results
		}

		batchCount++

		// CGNAT cooldown: after each batch, sleep before starting the next.
		// The first batch starts immediately.
		if batchCount > tr.Concurrent && (i%tr.Concurrent) == 0 {
			log.Printf("CGNAT cooldown: sleeping %v before next batch", tr.Cooldown)
			select {
			case <-time.After(tr.Cooldown):
			case <-ctx.Done():
				return results
			}
		}

		go func(ip net.IP, ipStr string) {
			defer func() { <-sem }()

			traceCtx, cancel := context.WithTimeout(ctx, tr.PerIPTimeout)
			defer cancel()

			result := tr.runSingle(traceCtx, ip)
			mu.Lock()
			results[ipStr] = result
			completed++
			mu.Unlock()

			log.Printf("traced IP %s (%d/%d)", ipStr, completed, total)

			// Save checkpoint.
			if resume && cp != nil {
				tr.Checkpoint.MarkCompleted(cp, ipStr)
				if err := tr.Checkpoint.Save(cp); err != nil {
					log.Printf("warning: checkpoint save failed for %s: %v", ipStr, err)
				}
			}
		}(ip, ipStr)
	}

	// Wait for all workers to finish.
	for i := 0; i < tr.Concurrent; i++ {
		sem <- struct{}{}
	}

	return results
}

// runSingle executes traceroute against one IP and parses the output.
func (tr *TracerouteRunner) runSingle(ctx context.Context, ip net.IP) *TraceResult {
	ipStr := ip.String()

	cmd := exec.CommandContext(ctx, "traceroute", "-n", "-m", "30", "-q", "1", ipStr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// exec.CommandContext kills the process on context cancel, which
		// produces an exit error even on successful partial output.
		// Still parse whatever we got.
		if len(output) == 0 {
			return &TraceResult{
				TargetIP: ip,
				Error:    fmt.Sprintf("traceroute failed: %v", err),
			}
		}
	}

	result := ParseTracerouteOutput(string(output), ip)
	if err != nil && result.Error == "" {
		// Only set error if we have no output at all.
		if len(result.Hops) == 0 {
			result.Error = fmt.Sprintf("traceroute failed: %v", err)
		}
	}

	return result
}

// ipToNetIP converts a netip.Addr to net.IP.
func ipToNetIP(addr netip.Addr) net.IP {
	return net.IP(addr.AsSlice())
}

// netIPsFromAddrs converts a slice of netip.Addr to a slice of net.IP.
func netIPsFromAddrs(addrs []netip.Addr) []net.IP {
	ips := make([]net.IP, len(addrs))
	for i, a := range addrs {
		ips[i] = ipToNetIP(a)
	}
	return ips
}


