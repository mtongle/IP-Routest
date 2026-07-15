package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"
)

// CLI flag defaults.
var (
	topN          = flag.Int("top", 50, "Number of fastest CMIN2 IPs to speed-test")
	traceAll      = flag.Bool("all", false, "Trace every unique IP (skip /24 dedup)")
	resume        = flag.Bool("resume", true, "Resume traceroute from checkpoint")
	traceWorkers  = flag.Int("concurrency", 20, "Traceroute worker count")
	tcpingWorkers = flag.Int("tcping-workers", 200, "TCPing worker count")
	airportFilter = flag.String("airport", "", "Filter by IATA airport codes (comma-separated, e.g., NRT,LAX,HKG)")
	inputFile     = flag.String("input", "", "Input file path(s), comma-separated (default: fetch from https://zip.cm.edu.kg/all.json)")
)

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// Create root context with signal cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Signal handler for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %v, shutting down gracefully...", sig)
		cancel()
	}()

	startTotal := time.Now()
	var phaseStart time.Time

	// ───────────────────────────────────────────────────────────────
	// Phase 1: Fetch IP data from API or parse from file(s)
	// ───────────────────────────────────────────────────────────────
	phaseStart = time.Now()

	var ipMap *IPMap
	var err error
	if *inputFile != "" {
		files := splitAndTrim(*inputFile, ',')
		log.Printf("phase 1: parsing %d file(s)...", len(files))
		ipMap, err = ParseFiles(files...)
		if err != nil {
			log.Fatalf("parse failed: %v", err)
		}
	} else {
		log.Printf("phase 1: fetching IP data from API...")
		ipMap, err = FetchFromAPI(ctx)
		if err != nil {
			log.Fatalf("API fetch failed: %v", err)
		}
	}
	log.Printf("phase 1: got %d unique IPs (%v)", ipMap.Len(), time.Since(phaseStart))

	// Apply airport (IATA) filter if specified.
	if *airportFilter != "" {
		airports := splitAndTrim(*airportFilter, ',')
		log.Printf("airport filter: %v", airports)
		ipMap = ipMap.FilterByAirports(airports)
		log.Printf("after airport filter: %d unique IPs", ipMap.Len())
		if ipMap.Len() == 0 {
			log.Fatalf("no IPs match the specified airport codes: %v", airports)
		}
	}

	// ───────────────────────────────────────────────────────────────
	// Phase 2: Traceroute + CMIN2 detection
	// ───────────────────────────────────────────────────────────────
	phaseStart = time.Now()
	log.Printf("phase 2: tracerouting IPs (concurrency=%d)...", *traceWorkers)
	uniqueIPs := ipMap.UniqueIPs() // []netip.Addr

	// Convert to []net.IP for the traceroute runner.
	ipList := make([]net.IP, 0, len(uniqueIPs))
	for _, a := range uniqueIPs {
		ipList = append(ipList, net.IP(a.AsSlice()))
	}

	// Apply /24 dedup unless -all.
	if !*traceAll {
		ipList = DedupBy24(ipList)
		log.Printf("phase 2: /24 dedup: %d IPs to trace", len(ipList))
	}

	runner := NewTracerouteRunner()
	runner.Concurrent = *traceWorkers
	traceResults := runner.Run(ctx, ipList, *resume)
	log.Printf("phase 2: traced %d IPs (%v)", len(traceResults), time.Since(phaseStart))

	// Classify for CMIN2 routing.
	cmin2Results := ClassifyAllResults(traceResults)
	log.Printf("phase 2: found %d CMIN2-routed IPs", len(cmin2Results))

	// Check for cancellation before proceeding.
	if ctx.Err() != nil {
		log.Printf("program cancelled during phase 2")
		writeResults(ctx, ipMap, traceResults, cmin2Results, nil, nil)
		os.Exit(1)
	}

	// ───────────────────────────────────────────────────────────────
	// Phase 3: TCP handshake latency (TCPing)
	// ───────────────────────────────────────────────────────────────
	phaseStart = time.Now()
	log.Printf("phase 3: TCPing %d CMIN2 IPs...", len(cmin2Results))
	tcpingResults := RunTCPing(cmin2Results, ipMap, *tcpingWorkers)
	log.Printf("phase 3: tcping complete, %d results (%v)", len(tcpingResults), time.Since(phaseStart))

	// Sort by AvgRTT ascending (fastest first).
	sort.Slice(tcpingResults, func(i, j int) bool {
		return tcpingResults[i].AvgRTT < tcpingResults[j].AvgRTT
	})

	// ───────────────────────────────────────────────────────────────
	// Phase 4: Download speed test (top N only)
	// ───────────────────────────────────────────────────────────────
	phaseStart = time.Now()
	log.Printf("phase 4: speed testing top %d IPs...", *topN)
	speedResults := RunSpeedTest(tcpingResults, *topN, 20)
	log.Printf("phase 4: speed test complete, %d results (%v)", len(speedResults), time.Since(phaseStart))

	// Sort by SpeedMbps descending (fastest first).
	sort.Slice(speedResults, func(i, j int) bool {
		return speedResults[i].SpeedMbps > speedResults[j].SpeedMbps
	})

	// ───────────────────────────────────────────────────────────────
	// Phase 5: Write results and summary
	// ───────────────────────────────────────────────────────────────
	writeResults(ctx, ipMap, traceResults, cmin2Results, tcpingResults, speedResults)

	log.Printf("total elapsed: %v", time.Since(startTotal))
}

// writeResults writes all four output files and prints a summary to stdout.
func writeResults(
	ctx context.Context,
	ipMap *IPMap,
	traceResults map[string]*TraceResult,
	cmin2Results []*CMIN2Result,
	tcpingResults []*TCPSpeedResult,
	speedResults []*SpeedResult,
) {
	// Ensure the output directory exists.
	if err := os.MkdirAll("results", 0755); err != nil {
		log.Fatalf("create results dir: %v", err)
	}

	// Build RTT lookup from TCPing results for the speed output.
	rttLookup := make(map[netip.Addr]time.Duration, len(tcpingResults))
	for _, r := range tcpingResults {
		rttLookup[r.IP] = r.AvgRTT
	}

	// Write File 01: CMIN2-routed IPs.
	if err := WriteCMIN2List(cmin2Results, ipMap, "results/01-cmin2-list.txt"); err != nil {
		log.Printf("error writing 01-cmin2-list.txt: %v", err)
	}

	// Write File 02: TCPing results sorted by latency.
	if err := WriteTCPingSorted(tcpingResults, "results/02-tcping-sorted.txt"); err != nil {
		log.Printf("error writing 02-tcping-sorted.txt: %v", err)
	}

	// Write File 03: Speed test results sorted by speed.
	if err := WriteSpeedSorted(speedResults, rttLookup, "results/03-speed-sorted.txt"); err != nil {
		log.Printf("error writing 03-speed-sorted.txt: %v", err)
	}

	// Write File 04: Route analysis.
	if err := WriteRouteAnalysis(cmin2Results, "results/04-route-analysis.txt"); err != nil {
		log.Printf("error writing 04-route-analysis.txt: %v", err)
	}

	// ───────────────────────────────────────────────────────────────
	// Stdout summary
	// ───────────────────────────────────────────────────────────────
	fmt.Println("\n=== Results Summary ===")
	fmt.Printf("Total unique IPs:    %d\n", ipMap.Len())
	fmt.Printf("IPs traced:          %d\n", len(traceResults))
	fmt.Printf("CMIN2 IPs found:     %d\n", len(cmin2Results))
	fmt.Printf("TCPing results:      %d\n", len(tcpingResults))
	fmt.Printf("Speed test results:  %d\n", len(speedResults))

	if len(speedResults) > 0 {
		fmt.Println("\nTop 5 fastest IPs:")
		limit := 5
		if len(speedResults) < limit {
			limit = len(speedResults)
		}
		for i, r := range speedResults[:limit] {
			avgMs := float64(0)
			if rtt, ok := rttLookup[r.IP]; ok {
				avgMs = float64(rtt) / float64(time.Millisecond)
			}
			fmt.Printf(" %d. %s:%d - %.2fms - %.2f Mbps\n", i+1, r.IP, r.Port, avgMs, r.SpeedMbps)
		}
	}

	fmt.Println("\nFiles written:")
	fmt.Println("  results/01-cmin2-list.txt")
	fmt.Println("  results/02-tcping-sorted.txt")
	fmt.Println("  results/03-speed-sorted.txt")
	fmt.Println("  results/04-route-analysis.txt")
}

// splitAndTrim splits s by sep and trims whitespace from each resulting token.
// Empty tokens are omitted from the result.
func splitAndTrim(s string, sep rune) []string {
	if s == "" {
		return nil
	}
	var result []string
	start := 0
	for i, ch := range s {
		if ch == sep {
			token := trimSpace(s[start:i])
			if token != "" {
				result = append(result, token)
			}
			start = i + 1
		}
	}
	token := trimSpace(s[start:])
	if token != "" {
		result = append(result, token)
	}
	return result
}

// trimSpace is a small helper to avoid importing strings for a single call
// at the top level. Returns s with leading and trailing whitespace removed.
func trimSpace(s string) string {
	lo, hi := 0, len(s)
	for lo < hi && (s[lo] == ' ' || s[lo] == '\t' || s[lo] == '\n' || s[lo] == '\r') {
		lo++
	}
	for hi > lo && (s[hi-1] == ' ' || s[hi-1] == '\t' || s[hi-1] == '\n' || s[hi-1] == '\r') {
		hi--
	}
	return s[lo:hi]
}
