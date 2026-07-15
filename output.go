package main

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"
)

// SafeWriter provides concurrent-safe file writing with atomic rename.
// Data is written to a .tmp file, then atomically renamed to the final path
// on Close(). This prevents readers from seeing partially-written files.
type SafeWriter struct {
	mu     sync.Mutex
	writer *bufio.Writer
	file   *os.File
	path   string
}

// NewSafeWriter creates a SafeWriter that writes to path via an atomic .tmp rename.
func NewSafeWriter(path string) (*SafeWriter, error) {
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", tmpPath, err)
	}
	return &SafeWriter{
		writer: bufio.NewWriter(f),
		file:   f,
		path:   path,
	}, nil
}

// Write writes p to the underlying buffered writer, protected by a mutex.
func (sw *SafeWriter) Write(p []byte) (int, error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.writer.Write(p)
}

// WriteString writes s to the underlying buffered writer, protected by a mutex.
func (sw *SafeWriter) WriteString(s string) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	_, err := sw.writer.WriteString(s)
	return err
}

// Close flushes the buffer, closes the file, and atomically renames .tmp to path.
// If any step fails, the .tmp file is cleaned up.
func (sw *SafeWriter) Close() error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if err := sw.writer.Flush(); err != nil {
		sw.file.Close()
		os.Remove(sw.path + ".tmp")
		return fmt.Errorf("flush: %w", err)
	}
	if err := sw.file.Close(); err != nil {
		os.Remove(sw.path + ".tmp")
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(sw.path+".tmp", sw.path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Output formatters
// ---------------------------------------------------------------------------

// WriteCMIN2List writes File 01: CMIN2-routed IPs sorted by IP, with country
// lookup from ipMap.
func WriteCMIN2List(results []*CMIN2Result, ipMap *IPMap, path string) error {
	sw, err := NewSafeWriter(path)
	if err != nil {
		return err
	}
	defer sw.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Sort by IP ascending.
	sorted := make([]*CMIN2Result, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].TargetIP.String() < sorted[j].TargetIP.String()
	})

	sw.WriteString(fmt.Sprintf("# CMIN2-routed IPs - %s\n", timestamp))
	sw.WriteString("# Format: IP Airport CMIN2HopCount Confidence\n")
	sw.WriteString(fmt.Sprintf("# Total: %d\n", len(sorted)))

	for _, r := range sorted {
		airport := getAirport(r.TargetIP, ipMap)
		hopCount := CountCMIN2Hops(r.AllHops)
		sw.WriteString(fmt.Sprintf("%s %s %d %.2f\n", r.TargetIP, airport, hopCount, r.Confidence))
	}

	return nil
}

// WriteTCPingSorted writes File 02: TCPing results sorted by latency (fastest
// first). The input slice should already be sorted by AvgRTT ascending.
func WriteTCPingSorted(results []*TCPSpeedResult, path string) error {
	sw, err := NewSafeWriter(path)
	if err != nil {
		return err
	}
	defer sw.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	sw.WriteString(fmt.Sprintf("# TCPing results sorted by latency (fastest first) - %s\n", timestamp))
	sw.WriteString("# Format: Rank IP:PORT AvgRTT(ms) LossRate(%)\n")
	sw.WriteString(fmt.Sprintf("# Total: %d\n", len(results)))

	for i, r := range results {
		avgMs := float64(r.AvgRTT) / float64(time.Millisecond)
		lossPct := r.LossRate * 100
		sw.WriteString(fmt.Sprintf("%d %s:%d %.2f %.0f\n", i+1, r.IP, r.Port, avgMs, lossPct))
	}

	return nil
}

// WriteSpeedSorted writes File 03: Speed test results sorted by speed (fastest
// first). The input slice should already be sorted by SpeedMbps descending.
// rttLookup provides AvgRTT from the corresponding TCPing results, keyed by IP.
func WriteSpeedSorted(results []*SpeedResult, rttLookup map[netip.Addr]time.Duration, path string) error {
	sw, err := NewSafeWriter(path)
	if err != nil {
		return err
	}
	defer sw.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	sw.WriteString(fmt.Sprintf("# Speed test results sorted by speed (fastest first) - %s\n", timestamp))
	sw.WriteString("# Format: Rank IP:PORT AvgRTT(ms) Speed(Mbps) Duration(s)\n")
	sw.WriteString(fmt.Sprintf("# Total: %d\n", len(results)))

	for i, r := range results {
		avgMs := float64(0)
		if rtt, ok := rttLookup[r.IP]; ok {
			avgMs = float64(rtt) / float64(time.Millisecond)
		}
		durSec := r.Duration.Seconds()
		sw.WriteString(fmt.Sprintf("%d %s:%d %.2f %.2f %.2f\n", i+1, r.IP, r.Port, avgMs, r.SpeedMbps, durSec))
	}

	return nil
}

// WriteRouteAnalysis writes File 04: Detailed route analysis for each
// CMIN2-routed IP, showing every hop with CMIN2 markers.
func WriteRouteAnalysis(results []*CMIN2Result, path string) error {
	sw, err := NewSafeWriter(path)
	if err != nil {
		return err
	}
	defer sw.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	sw.WriteString(fmt.Sprintf("# Route analysis for CMIN2-routed IPs - %s\n", timestamp))
	sw.WriteString("# Format: IP then each hop as Hop TTL IP RTT(ms) [CMIN2]\n")

	for _, r := range results {
		sw.WriteString(fmt.Sprintf("%s:\n", r.TargetIP))
		for _, hop := range r.AllHops {
			rttMs := float64(hop.RTT) / float64(time.Millisecond)

			ipStr := "*"
			if hop.IP != nil {
				ipStr = hop.IP.String()
			}

			marker := ""
			if hop.IP != nil && isCMIN2IP(hop.IP) {
				marker = " [CMIN2]"
			}

			sw.WriteString(fmt.Sprintf(" Hop %d %s %.3f%s\n", hop.TTL, ipStr, rttMs, marker))
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// getAirport returns the first airport (IATA) code for the given IP from ipMap.
// Returns "??" if the IP is not found or has no airport data.
func getAirport(ip net.IP, ipMap *IPMap) string {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "??"
	}
	addr = addr.Unmap()
	airports := ipMap.GetAirports(addr)
	if len(airports) == 0 {
		return "??"
	}
	return airports[0]
}
