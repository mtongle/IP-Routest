package main

import (
	"bufio"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// IPEntry holds the parsed data for a single IP address.
type IPEntry struct {
	Addr      netip.Addr
	Ports     []int
	Countries []string
	BestPort  int // 443 if present, otherwise the lowest port found
}

// IPMap is the central registry of parsed IP entries.
// It deduplicates by IP and preserves insertion order for deterministic iteration.
type IPMap struct {
	entries map[netip.Addr]*IPEntry
	mu      sync.Mutex
	order   []netip.Addr
}

// NewIPMap creates an empty IPMap.
func NewIPMap() *IPMap {
	return &IPMap{
		entries: make(map[netip.Addr]*IPEntry),
	}
}

// ParseLine parses a single line in "IP:PORT#COUNTRY" format.
// Returns the parsed address, port, country code, and any parse error.
// Empty lines and malformed lines return zero values and an error.
func ParseLine(line string) (netip.Addr, int, string, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return netip.Addr{}, 0, "", fmt.Errorf("empty line")
	}

	// Find the last colon to separate IP from port+country.
	// This works for both IPv4 (1.2.3.4:443#US) and IPv6 ([::1]:443#US).
	lastColon := strings.LastIndexByte(line, ':')
	if lastColon < 0 {
		return netip.Addr{}, 0, "", fmt.Errorf("no port separator ':' in line: %s", line)
	}

	ipStr := line[:lastColon]
	rest := line[lastColon+1:]

	// Strip brackets from IPv6 addresses.
	ipStr = strings.Trim(ipStr, "[]")

	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.Addr{}, 0, "", fmt.Errorf("invalid IP %q: %w", ipStr, err)
	}

	portStr, country, found := strings.Cut(rest, "#")
	if !found {
		return netip.Addr{}, 0, "", fmt.Errorf("no country separator '#' in port part: %s", rest)
	}
	if country == "" {
		return netip.Addr{}, 0, "", fmt.Errorf("empty country code for port %s", portStr)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return netip.Addr{}, 0, "", fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	if port < 1 || port > 65535 {
		return netip.Addr{}, 0, "", fmt.Errorf("port %d out of range (1-65535)", port)
	}

	return addr, port, country, nil
}

// ParseFile reads an IP list file, parses every line, and returns a populated IPMap.
// Lines in "IP:PORT#COUNTRY" format, one per line.
// Malformed lines are logged as warnings and skipped.
func ParseFile(filename string) (*IPMap, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filename, err)
	}
	defer f.Close()

	m := NewIPMap()
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		addr, port, country, err := ParseLine(scanner.Text())
		if err != nil {
			log.Printf("warning: %s line %d: %v", filename, lineNum, err)
			continue
		}
		m.add(addr, port, country)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", filename, err)
	}

	// Sort by IP address for deterministic iteration.
	sort.Slice(m.order, func(i, j int) bool {
		return m.order[i].Compare(m.order[j]) < 0
	})

	return m, nil
}

// add merges a parsed (addr, port, country) into the map, deduplicating
// ports and countries per IP and selecting the best port.
func (m *IPMap) add(addr netip.Addr, port int, country string) {
	entry, ok := m.entries[addr]
	if ok {
		if !containsInt(entry.Ports, port) {
			entry.Ports = append(entry.Ports, port)
		}
		if !containsString(entry.Countries, country) {
			entry.Countries = append(entry.Countries, country)
		}
		// BestPort: 443 takes priority; otherwise the lowest port wins.
		if port == 443 {
			entry.BestPort = 443
		} else if entry.BestPort != 443 && port < entry.BestPort {
			entry.BestPort = port
		}
		return
	}

	entry = &IPEntry{
		Addr:      addr,
		Ports:     []int{port},
		Countries: []string{country},
		BestPort:  port,
	}
	m.entries[addr] = entry
	m.order = append(m.order, addr)
}

// UniqueIPs returns all unique IP addresses, sorted in ascending order.
func (m *IPMap) UniqueIPs() []netip.Addr {
	result := make([]netip.Addr, len(m.order))
	copy(result, m.order)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Compare(result[j]) < 0
	})
	return result
}

// GetPorts returns the ports for a given IP, sorted ascending.
// Returns nil if the IP is not found.
func (m *IPMap) GetPorts(ip netip.Addr) []int {
	entry, ok := m.entries[ip]
	if !ok {
		return nil
	}
	result := make([]int, len(entry.Ports))
	copy(result, entry.Ports)
	sort.Ints(result)
	return result
}

// GetCountries returns the unique country codes for a given IP, sorted.
// Returns nil if the IP is not found.
func (m *IPMap) GetCountries(ip netip.Addr) []string {
	entry, ok := m.entries[ip]
	if !ok {
		return nil
	}
	result := make([]string, len(entry.Countries))
	copy(result, entry.Countries)
	sort.Strings(result)
	return result
}

// Len returns the number of unique IPs.
func (m *IPMap) Len() int {
	return len(m.entries)
}

// -- helpers --

func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func containsString(slice []string, val string) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}
