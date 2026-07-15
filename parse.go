package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ────────────────────── API response types ──────────────────────

type apiResponse struct {
	GeneratedAt string     `json:"generated_at"`
	List        apiList    `json:"list"`
	Data        []apiEntry `json:"data"`
}

type apiList struct {
	Country map[string]int `json:"country"`
	IPS     int            `json:"ips"`
}

type apiEntry struct {
	IP   string  `json:"ip"`
	Port []int   `json:"port"`
	Meta apiMeta `json:"meta"`
}

type apiMeta struct {
	Colo apiColo `json:"colo"`
}

type apiColo struct {
	IATA string `json:"iata"`
}

// FetchFromAPI fetches IP data from the remote API and returns an IPMap
// populated with IATA airport codes as the airport identifier.
func FetchFromAPI(ctx context.Context) (*IPMap, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://zip.cm.edu.kg/all.json", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var apiResp apiResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	m := NewIPMap()
	for _, entry := range apiResp.Data {
		addr, err := netip.ParseAddr(entry.IP)
		if err != nil {
			log.Printf("warning: invalid IP %q from API: %v", entry.IP, err)
			continue
		}
		iata := entry.Meta.Colo.IATA
		if iata == "" {
			log.Printf("warning: missing IATA code for IP %s, skipping", entry.IP)
			continue
		}
		for _, port := range entry.Port {
			m.add(addr, port, iata)
		}
	}

	sort.Slice(m.order, func(i, j int) bool {
		return m.order[i].Compare(m.order[j]) < 0
	})

	return m, nil
}

// IPEntry holds the parsed data for a single IP address.
type IPEntry struct {
	Addr      netip.Addr
	Ports     []int
	Airports  []string
	BestPort  int // 443 if present, otherwise the lowest port found
}

// IPMap is the central registry of parsed IP entries.
// It deduplicates by IP and preserves insertion order for deterministic iteration.
type IPMap struct {
	entries map[netip.Addr]*IPEntry
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
func (m *IPMap) add(addr netip.Addr, port int, airport string) {
	entry, ok := m.entries[addr]
	if ok {
		if !containsInt(entry.Ports, port) {
			entry.Ports = append(entry.Ports, port)
		}
		if !containsString(entry.Airports, airport) {
			entry.Airports = append(entry.Airports, airport)
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
		Airports:  []string{airport},
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

// GetAirports returns the unique airport (IATA) codes for a given IP, sorted.
// Returns nil if the IP is not found.
func (m *IPMap) GetAirports(ip netip.Addr) []string {
	entry, ok := m.entries[ip]
	if !ok {
		return nil
	}
	result := make([]string, len(entry.Airports))
	copy(result, entry.Airports)
	sort.Strings(result)
	return result
}

// Len returns the number of unique IPs.
func (m *IPMap) Len() int {
	return len(m.entries)
}

// FilterByAirports returns a new IPMap containing only entries whose airport
// list includes at least one of the given IATA airport codes. Returns the same
// map if the filter list is empty. The returned IPMap shares IPEntry pointers
// with the original (read-only after creation).
func (m *IPMap) FilterByAirports(airports []string) *IPMap {
	if len(airports) == 0 {
		return m
	}
	set := make(map[string]bool, len(airports))
	for _, a := range airports {
		set[strings.ToUpper(a)] = true
	}

	result := &IPMap{
		entries: make(map[netip.Addr]*IPEntry),
	}
	for _, addr := range m.order {
		entry := m.entries[addr]
		for _, ec := range entry.Airports {
			if set[ec] {
				result.entries[addr] = entry
				result.order = append(result.order, addr)
				break
			}
		}
	}
	return result
}

// Merge adds all entries from other into m. Duplicate ports and countries
// are deduplicated via the internal add method.
func (m *IPMap) Merge(other *IPMap) {
	for _, addr := range other.order {
		entry := other.entries[addr]
		for _, port := range entry.Ports {
			for _, airport := range entry.Airports {
				m.add(addr, port, airport)
			}
		}
	}
}

// ParseFiles parses multiple IP list files and merges them into one IPMap.
// Each file follows the same "IP:PORT#COUNTRY" format as ParseFile.
func ParseFiles(files ...string) (*IPMap, error) {
	m := NewIPMap()
	for _, file := range files {
		fileMap, err := ParseFile(file)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		m.Merge(fileMap)
	}
	return m, nil
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
