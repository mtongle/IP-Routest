package main

import (
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// TestParseLine — unit tests for single-line parsing
// ---------------------------------------------------------------------------

func TestParseLine_valid_IPv4_standard_port(t *testing.T) {
	// Given
	line := "101.99.76.88:2053#NL"

	// When
	addr, port, country, err := ParseLine(line)

	// Then
	if err != nil {
		t.Fatalf("ParseLine(%q) unexpected error: %v", line, err)
	}
	if addr.Compare(netip.MustParseAddr("101.99.76.88")) != 0 {
		t.Errorf("addr = %s, want 101.99.76.88", addr)
	}
	if port != 2053 {
		t.Errorf("port = %d, want 2053", port)
	}
	if country != "NL" {
		t.Errorf("country = %q, want %q", country, "NL")
	}
}

func TestParseLine_valid_IPv4_port_443(t *testing.T) {
	// Given
	line := "23.249.17.25:443#US"

	// When
	addr, port, country, err := ParseLine(line)

	// Then
	if err != nil {
		t.Fatalf("ParseLine(%q) unexpected error: %v", line, err)
	}
	if addr.Compare(netip.MustParseAddr("23.249.17.25")) != 0 {
		t.Errorf("addr = %s, want 23.249.17.25", addr)
	}
	if port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
	if country != "US" {
		t.Errorf("country = %q, want %q", country, "US")
	}
}

func TestParseLine_empty_line_returns_error(t *testing.T) {
	// Given
	lines := []string{"", "  ", "\t"}

	for _, line := range lines {
		t.Run("line="+quote(line), func(t *testing.T) {
			// When
			_, _, _, err := ParseLine(line)

			// Then
			if err == nil {
				t.Error("expected error for empty line")
			}
		})
	}
}

func TestParseLine_invalid_IP_returns_error(t *testing.T) {
	// Given
	line := "999.999.999.999:443#US"

	// When
	_, _, _, err := ParseLine(line)

	// Then
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestParseLine_non_IP_string_returns_error(t *testing.T) {
	// Given
	line := "not-an-ip:443#US"

	// When
	_, _, _, err := ParseLine(line)

	// Then
	if err == nil {
		t.Error("expected error for non-IP string")
	}
}

func TestParseLine_missing_port_returns_error(t *testing.T) {
	// Lines missing a port separator or port value.
	lines := []string{
		"101.99.76.88#NL",     // no colon at all
		"101.99.76.88:#NL",    // empty port
		"101.99.76.88:abc#NL", // non-numeric port
	}

	for _, line := range lines {
		t.Run("line="+line, func(t *testing.T) {
			// When
			_, _, _, err := ParseLine(line)

			// Then
			if err == nil {
				t.Errorf("expected error for line %q", line)
			}
		})
	}
}

func TestParseLine_missing_country_returns_error(t *testing.T) {
	// Given
	line := "101.99.76.88:443#"

	// When
	_, _, _, err := ParseLine(line)

	// Then
	if err == nil {
		t.Error("expected error for empty country code")
	}
}

func TestParseLine_port_out_of_range_returns_error(t *testing.T) {
	lines := []string{
		"101.99.76.88:0#NL",
		"101.99.76.88:65536#NL",
		"101.99.76.88:-1#NL",
	}

	for _, line := range lines {
		t.Run("line="+line, func(t *testing.T) {
			// When
			_, _, _, err := ParseLine(line)

			// Then
			if err == nil {
				t.Errorf("expected error for line with out-of-range port: %q", line)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestParseFile — tests with a temporary file
// ---------------------------------------------------------------------------

func TestParseFile_deduplicates_by_IP(t *testing.T) {
	// Given — 6 lines, only 3 unique IPs
	content := "" +
		"101.99.76.88:2053#NL\n" +
		"23.249.17.25:443#US\n" +
		"101.99.76.88:443#NL\n" +
		"103.152.113.60:443#US\n" +
		"23.249.17.25:8443#US\n" +
		"103.152.113.60:8443#DE\n"

	tmpFile := filepath.Join(t.TempDir(), "test-dedup.txt")
	if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// When
	m, err := ParseFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	// Then
	if m.Len() != 3 {
		t.Fatalf("expected 3 unique IPs, got %d", m.Len())
	}

	// 101.99.76.88 — ports [443, 2053], BestPort=443
	ip1 := netip.MustParseAddr("101.99.76.88")
	ports1 := m.GetPorts(ip1)
	if len(ports1) != 2 || ports1[0] != 443 || ports1[1] != 2053 {
		t.Errorf("101.99.76.88 ports = %v, want [443 2053]", ports1)
	}
	if entry := m.entries[ip1]; entry.BestPort != 443 {
		t.Errorf("101.99.76.88 BestPort = %d, want 443", entry.BestPort)
	}

	// 23.249.17.25 — ports [443, 8443], BestPort=443
	ip2 := netip.MustParseAddr("23.249.17.25")
	ports2 := m.GetPorts(ip2)
	if len(ports2) != 2 || ports2[0] != 443 || ports2[1] != 8443 {
		t.Errorf("23.249.17.25 ports = %v, want [443 8443]", ports2)
	}
	if entry := m.entries[ip2]; entry.BestPort != 443 {
		t.Errorf("23.249.17.25 BestPort = %d, want 443", entry.BestPort)
	}

	// 103.152.113.60 — ports [443, 8443] (no 443 duplicate), airports [DE, US]
	ip3 := netip.MustParseAddr("103.152.113.60")
	ports3 := m.GetPorts(ip3)
	if len(ports3) != 2 || ports3[0] != 443 || ports3[1] != 8443 {
		t.Errorf("103.152.113.60 ports = %v, want [443 8443]", ports3)
	}
	airports3 := m.GetAirports(ip3)
	if len(airports3) != 2 || airports3[0] != "DE" || airports3[1] != "US" {
		t.Errorf("103.152.113.60 airports = %v, want [DE US]", airports3)
	}
}

func TestParseFile_best_port_is_lowest_when_443_unavailable(t *testing.T) {
	// Given — no port 443 anywhere
	content := "" +
		"101.99.76.88:2053#NL\n" +
		"101.99.76.88:8443#NL\n" +
		"103.152.113.60:8080#US\n"

	tmpFile := filepath.Join(t.TempDir(), "test-noport443.txt")
	if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// When
	m, err := ParseFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	// Then
	ip1 := netip.MustParseAddr("101.99.76.88")
	if entry := m.entries[ip1]; entry.BestPort != 2053 {
		t.Errorf("BestPort = %d, want 2053 (lowest)", entry.BestPort)
	}

	ip2 := netip.MustParseAddr("103.152.113.60")
	if entry := m.entries[ip2]; entry.BestPort != 8080 {
		t.Errorf("BestPort = %d, want 8080 (only port)", entry.BestPort)
	}
}

func TestParseFile_best_port_prefers_443(t *testing.T) {
	// Given — port 443 appears after non-443 ports
	content := "" +
		"101.99.76.88:2053#NL\n" +
		"101.99.76.88:8443#NL\n" +
		"101.99.76.88:443#NL\n" // 443 found later

	tmpFile := filepath.Join(t.TempDir(), "test-443later.txt")
	if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// When
	m, err := ParseFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	// Then
	ip := netip.MustParseAddr("101.99.76.88")
	if entry := m.entries[ip]; entry.BestPort != 443 {
		t.Errorf("BestPort = %d, want 443 (preferred)", entry.BestPort)
	}
}

func TestParseFile_empty_file_returns_empty_map(t *testing.T) {
	// Given
	tmpFile := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(tmpFile, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	// When
	m, err := ParseFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	// Then
	if m.Len() != 0 {
		t.Errorf("expected 0 entries, got %d", m.Len())
	}
}

func TestParseFile_nonexistent_file_returns_error(t *testing.T) {
	// Given
	_, err := ParseFile(filepath.Join(t.TempDir(), "nonexistent.txt"))

	// Then
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestParseFile_skips_malformed_lines_with_warning(t *testing.T) {
	// Given — mix of valid and malformed lines
	content := "" +
		"101.99.76.88:2053#NL\n" +
		"garbage-line\n" +
		"23.249.17.25:443#US\n" +
		"\n" +
		"103.152.113.60:#US\n" +
		"  \n" +
		"104.16.0.1:8443#DE\n"

	tmpFile := filepath.Join(t.TempDir(), "test-malformed.txt")
	if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// When
	m, err := ParseFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	// Then — only the 3 valid lines should be present
	if m.Len() != 3 {
		t.Errorf("expected 3 unique IPs (4 valid lines, one dup), got %d", m.Len())
	}
}

// ---------------------------------------------------------------------------
// TestParseFullFile — parses the actual data file
// ---------------------------------------------------------------------------

func TestParseFullFile_unique_IP_count(t *testing.T) {
	// This test reads the actual data file; skip if not present.
	if _, err := os.Stat("ALL-2026-07-15.txt"); os.IsNotExist(err) {
		t.Skip("ALL-2026-07-15.txt not found, skipping full-file test")
	}

	// When
	m, err := ParseFile("ALL-2026-07-15.txt")
	if err != nil {
		t.Fatal(err)
	}

	// Then
	if m.Len() != 12992 {
		t.Errorf("expected 12992 unique IPs, got %d", m.Len())
	}
}

func TestParseFullFile_contains_known_IPs(t *testing.T) {
	if _, err := os.Stat("ALL-2026-07-15.txt"); os.IsNotExist(err) {
		t.Skip("ALL-2026-07-15.txt not found, skipping")
	}

	// When
	m, err := ParseFile("ALL-2026-07-15.txt")
	if err != nil {
		t.Fatal(err)
	}

	// Then
	for _, want := range []string{"101.99.76.88", "23.249.17.25"} {
		addr := netip.MustParseAddr(want)
		if _, ok := m.entries[addr]; !ok {
			t.Errorf("expected IP %s to be present", want)
		}
	}
}

func TestParseFullFile_known_IP_has_expected_ports(t *testing.T) {
	if _, err := os.Stat("ALL-2026-07-15.txt"); os.IsNotExist(err) {
		t.Skip("ALL-2026-07-15.txt not found, skipping")
	}

	// When
	m, err := ParseFile("ALL-2026-07-15.txt")
	if err != nil {
		t.Fatal(err)
	}

	// Then
	ip := netip.MustParseAddr("101.99.76.88")
	ports := m.GetPorts(ip)
	if len(ports) == 0 {
		t.Fatal("expected 101.99.76.88 to have at least one port")
	}
	// From the first line of the file: 101.99.76.88:2053#NL
	found2053 := false
	for _, p := range ports {
		if p == 2053 {
			found2053 = true
			break
		}
	}
	if !found2053 {
		t.Errorf("expected port 2053 in 101.99.76.88 ports: %v", ports)
	}
}

// ---------------------------------------------------------------------------
// TestFetchFromAPI — integration test with real API
// ---------------------------------------------------------------------------

func TestFetchFromAPI(t *testing.T) {
	if os.Getenv("OPENCODE_NETWORK_TEST") != "1" {
		t.Skip("set OPENCODE_NETWORK_TEST=1 to run API integration test")
	}

	ctx := t.Context()
	m, err := FetchFromAPI(ctx)
	if err != nil {
		t.Fatalf("FetchFromAPI failed: %v", err)
	}

	if m.Len() == 0 {
		t.Fatal("FetchFromAPI returned empty IPMap")
	}

	// Verify a known IP from the API response.
	addr := netip.MustParseAddr("159.60.146.82")
	entry, ok := m.entries[addr]
	if !ok {
		t.Error("expected IP 159.60.146.82 to be present")
	} else {
		airports := entry.Airports
		if len(airports) == 0 {
			t.Error("expected at least one airport code for 159.60.146.82")
		} else if airports[0] != "DFW" {
			t.Errorf("airport for 159.60.146.82 = %q, want %q", airports[0], "DFW")
		}
	}

	t.Logf("FetchFromAPI returned %d unique IPs", m.Len())
}

// ---------------------------------------------------------------------------
// TestEdgeCases
// ---------------------------------------------------------------------------

func TestEdgeCases_same_IP_same_port_no_duplicate(t *testing.T) {
	// Given
	content := "" +
		"101.99.76.88:443#NL\n" +
		"101.99.76.88:443#US\n" // same IP, same port, different country

	tmpFile := filepath.Join(t.TempDir(), "test-dup-port.txt")
	if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// When
	m, err := ParseFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	// Then — port 443 should appear exactly once
	ip := netip.MustParseAddr("101.99.76.88")
	ports := m.GetPorts(ip)
	if len(ports) != 1 || ports[0] != 443 {
		t.Errorf("ports = %v, want [443] (no duplicate)", ports)
	}
	// Countries should have both
	airports := m.GetAirports(ip)
	if len(airports) != 2 {
		t.Errorf("airports = %v, want [NL US]", airports)
	}
}

func TestEdgeCases_same_line_does_not_crash(t *testing.T) {
	// Given — direct call to ParseLine with identical lines
	line := "101.99.76.88:2053#NL"
	addr1, port1, country1, err1 := ParseLine(line)
	addr2, port2, country2, err2 := ParseLine(line)

	// Then — both parse identically
	if err1 != nil || err2 != nil {
		t.Fatal("both lines should parse successfully")
	}
	if addr1 != addr2 {
		t.Errorf("addr mismatch: %s vs %s", addr1, addr2)
	}
	if port1 != port2 {
		t.Errorf("port mismatch: %d vs %d", port1, port2)
	}
	if country1 != country2 {
		t.Errorf("country mismatch: %s vs %s", country1, country2)
	}
}

// ---------------------------------------------------------------------------
// TestGetPorts — returns sorted ports
// ---------------------------------------------------------------------------

func TestGetPorts_returns_sorted_ports(t *testing.T) {
	// Given
	m := NewIPMap()
	ip := netip.MustParseAddr("104.16.0.1")
	m.add(ip, 8443, "US")
	m.add(ip, 443, "NL")
	m.add(ip, 2053, "DE")

	// When
	ports := m.GetPorts(ip)

	// Then
	want := []int{443, 2053, 8443}
	if len(ports) != len(want) {
		t.Fatalf("len(ports) = %d, want %d; got %v", len(ports), len(want), ports)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Errorf("ports[%d] = %d, want %d; full = %v", i, ports[i], want[i], ports)
		}
	}
}

func TestGetPorts_unknown_IP_returns_nil(t *testing.T) {
	// Given
	m := NewIPMap()
	ip := netip.MustParseAddr("1.2.3.4")

	// When
	ports := m.GetPorts(ip)

	// Then
	if ports != nil {
		t.Errorf("expected nil for unknown IP, got %v", ports)
	}
}

func TestGetAirports_unknown_IP_returns_nil(t *testing.T) {
	// Given
	m := NewIPMap()
	ip := netip.MustParseAddr("1.2.3.4")

	// When
	airports := m.GetAirports(ip)

	// Then
	if airports != nil {
		t.Errorf("expected nil for unknown IP, got %v", airports)
	}
}

func TestGetAirports_returns_sorted(t *testing.T) {
	// Given
	m := NewIPMap()
	ip := netip.MustParseAddr("104.16.0.1")
	m.add(ip, 443, "DFW")
	m.add(ip, 443, "NRT")
	m.add(ip, 443, "HKG")

	// When
	airports := m.GetAirports(ip)

	// Then
	want := []string{"DFW", "HKG", "NRT"}
	if len(airports) != len(want) {
		t.Fatalf("len(airports) = %d, want %d; got %v", len(airports), len(want), airports)
	}
	for i := range want {
		if airports[i] != want[i] {
			t.Errorf("airports[%d] = %s, want %s; full = %v", i, airports[i], want[i], airports)
		}
	}
}

// ---------------------------------------------------------------------------
// TestUniqueIPs
// ---------------------------------------------------------------------------

func TestUniqueIPs_returns_sorted_IPs(t *testing.T) {
	// Given
	m := NewIPMap()
	ip1 := netip.MustParseAddr("103.152.113.60")
	ip2 := netip.MustParseAddr("101.99.76.88")
	ip3 := netip.MustParseAddr("23.249.17.25")
	m.add(ip1, 443, "US")
	m.add(ip2, 2053, "NL")
	m.add(ip3, 443, "US")

	// When
	unique := m.UniqueIPs()

	// Then — should be sorted ascending
	if len(unique) != 3 {
		t.Fatalf("len = %d, want 3", len(unique))
	}
	if unique[0].Compare(unique[1]) >= 0 {
		t.Errorf("not sorted: unique[0]=%s, unique[1]=%s", unique[0], unique[1])
	}
}

func TestUniqueIPs_empty_map_returns_empty_slice(t *testing.T) {
	// Given
	m := NewIPMap()

	// When
	unique := m.UniqueIPs()

	// Then
	if len(unique) != 0 {
		t.Errorf("expected empty slice, got %v", unique)
	}
}

// ---------------------------------------------------------------------------
// TestNewIPMap
// ---------------------------------------------------------------------------

func TestNewIPMap_creates_empty_map(t *testing.T) {
	// When
	m := NewIPMap()

	// Then
	if m == nil {
		t.Fatal("NewIPMap() returned nil")
	}
	if m.Len() != 0 {
		t.Errorf("expected 0 entries, got %d", m.Len())
	}
}

func TestNewIPMap_Len_reflects_added_entries(t *testing.T) {
	m := NewIPMap()
	if m.Len() != 0 {
		t.Fatal("fresh map should be empty")
	}

	m.add(netip.MustParseAddr("1.2.3.4"), 443, "US")
	if m.Len() != 1 {
		t.Errorf("after 1 add: Len=%d, want 1", m.Len())
	}

	m.add(netip.MustParseAddr("1.2.3.4"), 8443, "DE") // same IP
	if m.Len() != 1 {
		t.Errorf("after adding same IP: Len=%d, want 1", m.Len())
	}

	m.add(netip.MustParseAddr("5.6.7.8"), 443, "US") // different IP
	if m.Len() != 2 {
		t.Errorf("after adding second IP: Len=%d, want 2", m.Len())
	}
}

// ---------------------------------------------------------------------------
// TestFilterByAirports
// ---------------------------------------------------------------------------

func TestFilterByAirports_filters_by_IATA_code(t *testing.T) {
	// Given: an IPMap with IPs from multiple airports.
	m := NewIPMap()
	m.add(netip.MustParseAddr("1.2.3.4"), 443, "DFW")
	m.add(netip.MustParseAddr("5.6.7.8"), 443, "NRT")
	m.add(netip.MustParseAddr("9.10.11.12"), 8443, "DFW")
	m.add(netip.MustParseAddr("13.14.15.16"), 443, "HKG")
	m.add(netip.MustParseAddr("17.18.19.20"), 2053, "LAX")

	// When: filter by DFW and NRT.
	filtered := m.FilterByAirports([]string{"DFW", "NRT"})

	// Then: only DFW and NRT IPs remain.
	if filtered.Len() != 3 {
		t.Fatalf("expected 3 IPs after filter, got %d", filtered.Len())
	}

	for _, addr := range []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"} {
		parsed := netip.MustParseAddr(addr)
		if _, ok := filtered.entries[parsed]; !ok {
			t.Errorf("expected IP %s to be present after filter", addr)
		}
	}
	// HKG and LAX should be gone.
	for _, addr := range []string{"13.14.15.16", "17.18.19.20"} {
		parsed := netip.MustParseAddr(addr)
		if _, ok := filtered.entries[parsed]; ok {
			t.Errorf("expected IP %s to be absent after filter", addr)
		}
	}
}

func TestFilterByAirports_empty_filter_returns_original(t *testing.T) {
	// Given: an IPMap with entries.
	m := NewIPMap()
	m.add(netip.MustParseAddr("1.2.3.4"), 443, "DFW")

	// When: empty filter.
	filtered := m.FilterByAirports(nil)

	// Then: same map pointer returned.
	if filtered != m {
		t.Error("expected same map pointer for empty filter")
	}
}

func TestFilterByAirports_no_match_returns_empty_map(t *testing.T) {
	// Given: an IPMap with entries.
	m := NewIPMap()
	m.add(netip.MustParseAddr("1.2.3.4"), 443, "DFW")
	m.add(netip.MustParseAddr("5.6.7.8"), 443, "NRT")

	// When: filter for an airport that doesn't exist.
	filtered := m.FilterByAirports([]string{"XXX"})

	// Then: empty map.
	if filtered.Len() != 0 {
		t.Errorf("expected 0 IPs, got %d", filtered.Len())
	}
}

func TestFilterByAirports_case_insensitive(t *testing.T) {
	// Given: an IPMap with uppercase airport codes.
	m := NewIPMap()
	m.add(netip.MustParseAddr("1.2.3.4"), 443, "DFW")

	// When: filter with lowercase.
	filtered := m.FilterByAirports([]string{"dfw"})

	// Then: still matches.
	if filtered.Len() != 1 {
		t.Errorf("expected 1 IP, got %d", filtered.Len())
	}
}

func TestFilterByAirports_preserves_entry_data(t *testing.T) {
	// Given: an IPMap with an IP that has multiple ports and airports.
	m := NewIPMap()
	m.add(netip.MustParseAddr("1.2.3.4"), 443, "DFW")
	m.add(netip.MustParseAddr("1.2.3.4"), 8443, "NRT")

	// When: filter by DFW.
	filtered := m.FilterByAirports([]string{"DFW"})

	// Then: port data is preserved.
	if filtered.Len() != 1 {
		t.Fatalf("expected 1 IP, got %d", filtered.Len())
	}
	addr := netip.MustParseAddr("1.2.3.4")
	ports := filtered.GetPorts(addr)
	if len(ports) != 2 {
		t.Errorf("expected 2 ports, got %v", ports)
	}
	// BestPort should still be 443.
	entry := filtered.entries[addr]
	if entry.BestPort != 443 {
		t.Errorf("BestPort = %d, want 443", entry.BestPort)
	}
}

// ---------------------------------------------------------------------------
// TestMerge
// ---------------------------------------------------------------------------

func TestMerge_combines_two_maps(t *testing.T) {
	// Given: two IPMaps with disjoint IPs.
	a := NewIPMap()
	a.add(netip.MustParseAddr("1.2.3.4"), 443, "US")

	b := NewIPMap()
	b.add(netip.MustParseAddr("5.6.7.8"), 443, "JP")

	// When: merge b into a.
	a.Merge(b)

	// Then: a has 2 entries.
	if a.Len() != 2 {
		t.Fatalf("expected 2 IPs after merge, got %d", a.Len())
	}
}

func TestMerge_deduplicates_overlapping_IPs(t *testing.T) {
	// Given: two IPMaps with overlapping IP but different ports.
	a := NewIPMap()
	a.add(netip.MustParseAddr("1.2.3.4"), 443, "US")

	b := NewIPMap()
	b.add(netip.MustParseAddr("1.2.3.4"), 8443, "US")

	// When: merge b into a.
	a.Merge(b)

	// Then: still 1 entry with both ports.
	if a.Len() != 1 {
		t.Fatalf("expected 1 IP after merge, got %d", a.Len())
	}
	ports := a.GetPorts(netip.MustParseAddr("1.2.3.4"))
	if len(ports) != 2 || ports[0] != 443 || ports[1] != 8443 {
		t.Errorf("ports = %v, want [443 8443]", ports)
	}
}

func TestMerge_empty_other(t *testing.T) {
	// Given: a map with one entry and an empty map.
	a := NewIPMap()
	a.add(netip.MustParseAddr("1.2.3.4"), 443, "US")
	b := NewIPMap()

	// When: merge empty.
	a.Merge(b)

	// Then: unchanged.
	if a.Len() != 1 {
		t.Errorf("expected 1 IP, got %d", a.Len())
	}
}

// ---------------------------------------------------------------------------
// TestParseFiles
// ---------------------------------------------------------------------------

func TestParseFiles_combines_multiple_files(t *testing.T) {
	// Given: two temp files with different IPs.
	dir := t.TempDir()

	f1 := filepath.Join(dir, "file1.txt")
	if err := os.WriteFile(f1, []byte("1.2.3.4:443#US\n5.6.7.8:443#JP\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f2 := filepath.Join(dir, "file2.txt")
	if err := os.WriteFile(f2, []byte("9.10.11.12:8443#HK\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When: parse both files.
	m, err := ParseFiles(f1, f2)
	if err != nil {
		t.Fatal(err)
	}

	// Then: all 3 IPs are present.
	if m.Len() != 3 {
		t.Errorf("expected 3 IPs, got %d", m.Len())
	}
}

func TestParseFiles_deduplicates_across_files(t *testing.T) {
	// Given: two files with overlapping IPs.
	dir := t.TempDir()

	f1 := filepath.Join(dir, "file1.txt")
	if err := os.WriteFile(f1, []byte("1.2.3.4:443#US\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f2 := filepath.Join(dir, "file2.txt")
	if err := os.WriteFile(f2, []byte("1.2.3.4:8443#US\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When: parse both files.
	m, err := ParseFiles(f1, f2)
	if err != nil {
		t.Fatal(err)
	}

	// Then: 1 entry with both ports.
	if m.Len() != 1 {
		t.Fatalf("expected 1 IP, got %d", m.Len())
	}
	ports := m.GetPorts(netip.MustParseAddr("1.2.3.4"))
	if len(ports) != 2 {
		t.Errorf("expected 2 ports, got %v", ports)
	}
}

func TestParseFiles_single_file(t *testing.T) {
	// Given: single file (backward compatibility).
	dir := t.TempDir()
	f := filepath.Join(dir, "single.txt")
	if err := os.WriteFile(f, []byte("1.2.3.4:443#US\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When: parse single file via ParseFiles.
	m, err := ParseFiles(f)
	if err != nil {
		t.Fatal(err)
	}

	// Then: 1 entry.
	if m.Len() != 1 {
		t.Errorf("expected 1 IP, got %d", m.Len())
	}
}

func TestParseFiles_nonexistent_file_returns_error(t *testing.T) {
	// When: parse a nonexistent file (among valid ones).
	_, err := ParseFiles("/nonexistent/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestParseFiles_empty_file_list(t *testing.T) {
	// When: no files.
	m, err := ParseFiles()
	if err != nil {
		t.Fatal(err)
	}

	// Then: empty map.
	if m.Len() != 0 {
		t.Errorf("expected 0 IPs, got %d", m.Len())
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// quote returns a quoted version of s for use in test names.
func quote(s string) string {
	if s == "" {
		return "empty"
	}
	return s
}

func init() {
	// Suppress log output during tests to keep output clean.
	log.SetFlags(0)
	log.SetOutput(testLogWriter{})
}

// testLogWriter discards log output during normal test runs.
// Tests that verify logging behavior would need their own setup.
type testLogWriter struct{}

func (testLogWriter) Write(p []byte) (int, error) { return len(p), nil }
