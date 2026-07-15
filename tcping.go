package main

import (
	"log"
	"math/rand"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// TCPSpeedResult holds the TCP handshake latency result for one IP (best port).
type TCPSpeedResult struct {
	IP       netip.Addr
	Port     int             // The best (lowest-latency) port for this IP
	AvgRTT   time.Duration   // Average of successful round RTTs
	LossRate float64         // 0.0 to 1.0 (e.g., 0.25 = 1 out of 4 failed)
	RawRTTs  []time.Duration // Per-round RTTs
}

// PortRTT holds per-port TCP latency data for a single IP.
type PortRTT struct {
	Port      int
	RTTs      []time.Duration
	AvgRTT    time.Duration
	LossRate  float64
	Successes int
	Total     int
}

// TCPingSingle performs one TCP dial to addr and returns the handshake RTT.
// addr format is "ip:port" (e.g., "23.249.17.25:443").
// The connection is closed immediately after measuring.
func TCPingSingle(addr string, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	conn, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", addr)
	if err != nil {
		return 0, err
	}
	rtt := time.Since(start)
	conn.Close()
	return rtt, nil
}

// TCPingPort runs rounds TCP handshake attempts on a single IP:port
// with random jitter before each dial. Returns a PortRTT with per-round RTTs,
// or nil if all rounds failed.
func TCPingPort(ip netip.Addr, port int, rounds int, timeout time.Duration) *PortRTT {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	pr := &PortRTT{
		Port:  port,
		Total: rounds,
	}
	addr := net.JoinHostPort(ip.String(), itoa(port))

	for range rounds {
		// Random jitter before each dial to avoid triggering rate limiting.
		jitter := time.Duration(rng.Intn(500)) * time.Millisecond
		time.Sleep(jitter)

		rtt, err := TCPingSingle(addr, timeout)
		if err != nil {
			continue
		}
		pr.RTTs = append(pr.RTTs, rtt)
		pr.Successes++
	}

	if pr.Successes == 0 {
		return nil
	}

	// Calculate average RTT from successful attempts.
	var total time.Duration
	for _, rtt := range pr.RTTs {
		total += rtt
	}
	pr.AvgRTT = total / time.Duration(pr.Successes)
	pr.LossRate = 1.0 - float64(pr.Successes)/float64(pr.Total)

	return pr
}

// selectBestPort selects the best port result from a map of per-port results.
// Selection priority:
//  1. Port with lowest AvgRTT
//  2. If tie, prefer port 443
//  3. If no successful ports, pick the one with lowest loss rate
func selectBestPort(portResults map[int]*PortRTT) (int, time.Duration, float64, []time.Duration) {
	var bestPort int
	var bestAvgRTT time.Duration
	var bestLossRate float64
	var bestRTTs []time.Duration
	first := true

	// Collect and sort ports for deterministic selection.
	ports := make([]int, 0, len(portResults))
	for p := range portResults {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	for _, p := range ports {
		pr := portResults[p]
		if first {
			bestPort = p
			bestAvgRTT = pr.AvgRTT
			bestLossRate = pr.LossRate
			bestRTTs = pr.RTTs
			first = false
			continue
		}

		// Prefer lower loss rate; if equal, prefer lower AvgRTT.
		if pr.LossRate < bestLossRate {
			bestPort = p
			bestAvgRTT = pr.AvgRTT
			bestLossRate = pr.LossRate
			bestRTTs = pr.RTTs
		} else if pr.LossRate == bestLossRate {
			if pr.AvgRTT < bestAvgRTT {
				bestPort = p
				bestAvgRTT = pr.AvgRTT
				bestLossRate = pr.LossRate
				bestRTTs = pr.RTTs
			} else if pr.AvgRTT == bestAvgRTT && p == 443 {
				// Tie: prefer port 443.
				bestPort = p
				bestRTTs = pr.RTTs
			}
		}
	}

	return bestPort, bestAvgRTT, bestLossRate, bestRTTs
}

// RunTCPing measures TCP handshake latency for all routed IPs.
// For each IP, all associated ports are tested, the best port is selected,
// and one TCPSpeedResult per IP is returned.
//
// concurrency controls the number of parallel workers (default: 200).
// A 2-second cooldown is applied between batches to avoid rate limiting.
func RunTCPing(routeResults []*RouteResult, ipMap *IPMap, concurrency int) []*TCPSpeedResult {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	if concurrency <= 0 {
		concurrency = 200
	}

	// Convert route results to a lookup map keyed by netip.Addr.
	type ipPorts struct {
		ip    netip.Addr
		ports []int
	}

	var targets []ipPorts
	seen := make(map[netip.Addr]bool)
	for _, rr := range routeResults {
		addr, ok := netip.AddrFromSlice(rr.TargetIP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if seen[addr] {
			continue
		}
		seen[addr] = true
		ports := ipMap.GetPorts(addr)
		if len(ports) == 0 {
			continue
		}
		targets = append(targets, ipPorts{ip: addr, ports: ports})
	}

	total := len(targets)
	results := make([]*TCPSpeedResult, 0, total)
	var mu sync.Mutex

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	log.Printf("tcping: %d target IPs, concurrency %d", total, concurrency)

	for i, t := range targets {
		wg.Add(1)

		// Acquire semaphore slot.
		sem <- struct{}{}

		// Cooldown: after each full batch, sleep before starting the next.
		if i > 0 && i%concurrency == 0 {
			cooldown := 2 * time.Second
			log.Printf("tcping: batch %d complete, cooldown %v (%d/%d)",
				i/concurrency, cooldown, i, total)
			time.Sleep(cooldown)
		}

		go func(t ipPorts) {
			defer wg.Done()
			defer func() { <-sem }()

			// Test all ports for this IP.
			portResults := make(map[int]*PortRTT)
			for _, port := range t.ports {
				// Add small random jitter before starting a new port.
				jitter := time.Duration(rng.Intn(200)) * time.Millisecond
				time.Sleep(jitter)

				pr := TCPingPort(t.ip, port, 4, 5*time.Second)
				if pr != nil {
					portResults[port] = pr
				}
			}

			if len(portResults) == 0 {
				// No port succeeded at all — skip this IP.
				return
			}

			bestPort, avgRTT, lossRate, rawRTTs := selectBestPort(portResults)

			result := &TCPSpeedResult{
				IP:       t.ip,
				Port:     bestPort,
				AvgRTT:   avgRTT,
				LossRate: lossRate,
				RawRTTs:  rawRTTs,
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

			lossStr := ""
			if lossRate > 0.5 {
				lossStr = " (high loss)"
			}
			log.Printf("tcping: %s port %d avg=%v loss=%.0f%%%s",
				t.ip, bestPort, avgRTT, lossRate*100, lossStr)
		}(t)
	}

	wg.Wait()
	log.Printf("tcping: complete, %d/%d IPs succeeded", len(results), total)

	return results
}

// itoa is a small integer-to-string helper to avoid importing strconv
// for a single call in the hot path.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
