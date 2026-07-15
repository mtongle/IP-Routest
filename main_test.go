package main

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TestParseAndDedup — parse a small file, verify UniqueIPs and /24 dedup
// ---------------------------------------------------------------------------

func TestParseAndDedup(t *testing.T) {
	// Given: a small file with IPs spanning multiple /24s.
	content := "" +
		"1.2.3.4:443#US\n" +
		"5.6.7.8:80#NL\n" +
		"1.2.3.5:8443#DE\n" +
		"9.10.11.12:443#US\n" +
		"5.6.7.9:443#FR\n"

	tmpFile := filepath.Join(t.TempDir(), "test-dedup.txt")
	if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// When: parse the file.
	m, err := ParseFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	// Then: 5 unique IPs across 3 /24 groups.
	if m.Len() != 5 {
		t.Fatalf("expected 5 unique IPs before dedup, got %d", m.Len())
	}

	uniqueIPs := m.UniqueIPs()
	ipList := make([]net.IP, 0, len(uniqueIPs))
	for _, a := range uniqueIPs {
		ipList = append(ipList, net.IP(a.AsSlice()))
	}

	if len(ipList) != 5 {
		t.Fatalf("expected 5 IPs in UniqueIPs, got %d", len(ipList))
	}

	// When: apply /24 dedup.
	deduped := DedupBy24(ipList)

	// Then: 3 /24 groups (1.2.3.x, 5.6.7.x, 9.10.11.x).
	if len(deduped) != 3 {
		t.Errorf("expected 3 IPs after /24 dedup, got %d: %v", len(deduped), deduped)
	}
}

// ---------------------------------------------------------------------------
// TestMainHelp — run the binary with -h and check flag names appear
// ---------------------------------------------------------------------------

func TestMainHelp(t *testing.T) {
	// Given: the main binary.
	cmd := exec.Command("go", "run", ".", "-h")

	// When: run with -h.
	out, _ := cmd.CombinedOutput()
	output := string(out)

	// Then: all flag names appear in the usage output.
	expectedFlags := []string{"-top", "-all", "-resume", "-concurrency", "-tcping-workers", "-input", "-airport", "-route"}
	for _, flag := range expectedFlags {
		if !strings.Contains(output, flag) {
			t.Errorf("usage output missing flag %q", flag)
		}
	}
}

// ---------------------------------------------------------------------------
// TestWriteRouteList — write File 01 and verify content
// ---------------------------------------------------------------------------

func TestWriteRouteList(t *testing.T) {
	// Given: sample route results with an IPMap for country lookup.
	dir := t.TempDir()
	path := filepath.Join(dir, "01-cmin2-list.txt")

	ipMap := NewIPMap()
	ipMap.add(netip.MustParseAddr("101.99.76.88"), 443, "AMS")
	ipMap.add(netip.MustParseAddr("23.249.17.25"), 443, "DFW")

	results := []*RouteResult{
		{
			TargetIP:   net.ParseIP("101.99.76.88"),
			RouteType:  RouteCMIN2,
			IsRouted:   true,
			Confidence: 0.95,
			AllHops: []Hop{
				{TTL: 1, IP: net.ParseIP("192.168.1.1")},
				{TTL: 2, IP: net.ParseIP("223.120.3.201")},
				{TTL: 3, IP: net.ParseIP("101.99.76.88")},
			},
		},
		{
			TargetIP:   net.ParseIP("23.249.17.25"),
			RouteType:  RouteCMIN2,
			IsRouted:   true,
			Confidence: 0.70,
			AllHops: []Hop{
				{TTL: 9, IP: net.ParseIP("223.120.141.50")},
			},
		},
	}

	// When: write the file.
	if err := WriteRouteList(results, RouteCMIN2, ipMap, path); err != nil {
		t.Fatal(err)
	}

	// Then: read back and verify.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "101.99.76.88") {
		t.Error("missing IP 101.99.76.88")
	}
	if !strings.Contains(content, "AMS") {
		t.Error("missing airport AMS for 101.99.76.88")
	}
	if !strings.Contains(content, "23.249.17.25") {
		t.Error("missing IP 23.249.17.25")
	}
	if !strings.Contains(content, "DFW") {
		t.Error("missing airport DFW for 23.249.17.25")
	}
	if !strings.Contains(content, "Total: 2") {
		t.Error("missing Total: 2 header")
	}
	if !strings.Contains(content, "cmin2-routed IPs") {
		t.Error("missing title header")
	}
}

// ---------------------------------------------------------------------------
// TestWriteTCPingSorted — write File 02 and verify content
// ---------------------------------------------------------------------------

func TestWriteTCPingSorted(t *testing.T) {
	// Given: sample TCPing results.
	dir := t.TempDir()
	path := filepath.Join(dir, "02-tcping-sorted.txt")

	results := []*TCPSpeedResult{
		{
			IP:       netip.MustParseAddr("101.99.76.88"),
			Port:     443,
			AvgRTT:   12 * time.Millisecond,
			LossRate: 0.0,
		},
		{
			IP:       netip.MustParseAddr("23.249.17.25"),
			Port:     8443,
			AvgRTT:   65*time.Millisecond + 200*time.Microsecond,
			LossRate: 0.25,
		},
	}

	// When: write the file.
	if err := WriteTCPingSorted(results, path); err != nil {
		t.Fatal(err)
	}

	// Then: read back and verify.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "101.99.76.88:443") {
		t.Error("missing 101.99.76.88:443")
	}
	if !strings.Contains(content, "23.249.17.25:8443") {
		t.Error("missing 23.249.17.25:8443")
	}
	if !strings.Contains(content, "12.00") {
		t.Error("missing AvgRTT 12.00ms")
	}
	if !strings.Contains(content, "65.20") {
		t.Error("missing AvgRTT 65.20ms")
	}
	if !strings.Contains(content, "Total: 2") {
		t.Error("missing Total: 2")
	}
	if !strings.Contains(content, "Rank") {
		t.Error("missing Format header with Rank")
	}
}

// ---------------------------------------------------------------------------
// TestWriteSpeedSorted — write File 03 and verify content
// ---------------------------------------------------------------------------

func TestWriteSpeedSorted(t *testing.T) {
	// Given: sample speed results with RTT lookup.
	dir := t.TempDir()
	path := filepath.Join(dir, "03-speed-sorted.txt")

	rttLookup := map[netip.Addr]time.Duration{
		netip.MustParseAddr("101.99.76.88"): 12 * time.Millisecond,
	}

	results := []*SpeedResult{
		{
			IP:        netip.MustParseAddr("101.99.76.88"),
			Port:      443,
			SpeedMbps: 45.67,
			Duration:  30 * time.Second,
		},
	}

	// When: write the file.
	if err := WriteSpeedSorted(results, rttLookup, path); err != nil {
		t.Fatal(err)
	}

	// Then: read back and verify.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "45.67") {
		t.Error("missing speed value 45.67")
	}
	if !strings.Contains(content, "101.99.76.88:443") {
		t.Error("missing IP:port")
	}
	if !strings.Contains(content, "12.00") {
		t.Error("missing AvgRTT 12.00ms from lookup")
	}
	if !strings.Contains(content, "30.00") {
		t.Error("missing duration 30.00s")
	}
	if !strings.Contains(content, "Total: 1") {
		t.Error("missing Total: 1")
	}
}

// ---------------------------------------------------------------------------
// TestWriteRouteAnalysis — write File 04 and verify hop format
// ---------------------------------------------------------------------------

func TestWriteRouteAnalysis(t *testing.T) {
	// Given: sample route result with mixed hops.
	dir := t.TempDir()
	path := filepath.Join(dir, "04-route-analysis.txt")

	results := []*RouteResult{
		{
			TargetIP:  net.ParseIP("101.99.76.88"),
			RouteType: RouteCMIN2,
			AllHops: []Hop{
				{TTL: 1, IP: net.ParseIP("192.168.1.1"), RTT: 1*time.Millisecond + 234*time.Microsecond},
				{TTL: 2, IP: net.ParseIP("10.0.0.1"), RTT: 5 * time.Millisecond},
				{TTL: 3, IP: net.ParseIP("223.120.3.201"), RTT: 39*time.Millisecond + 160*time.Microsecond},
			},
		},
	}

	// When: write the file.
	if err := WriteRouteAnalysis(results, RouteCMIN2, path); err != nil {
		t.Fatal(err)
	}

	// Then: read back and verify.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "101.99.76.88:") {
		t.Error("missing IP header")
	}
	if !strings.Contains(content, "Hop 1") {
		t.Error("missing Hop 1")
	}
	if !strings.Contains(content, "Hop 2") {
		t.Error("missing Hop 2")
	}
	if !strings.Contains(content, "Hop 3") {
		t.Error("missing Hop 3")
	}
	if !strings.Contains(content, "192.168.1.1") {
		t.Error("missing hop IP 192.168.1.1")
	}
	if !strings.Contains(content, "1.234") {
		t.Error("missing RTT 1.234ms")
	}
	if !strings.Contains(content, "[CMIN2]") {
		t.Error("missing CMIN2 marker for 223.120.3.201")
	}
}

// ---------------------------------------------------------------------------
// TestSafeWriterAtomicity — verify .tmp → final rename semantics
// ---------------------------------------------------------------------------

func TestSafeWriterAtomicity(t *testing.T) {
	// Given: a SafeWriter pointing to a temp file.
	dir := t.TempDir()
	path := filepath.Join(dir, "test-atomic.txt")

	sw, err := NewSafeWriter(path)
	if err != nil {
		t.Fatal(err)
	}

	// When: write and close.
	content := "hello world\nsecond line\n"
	if err := sw.WriteString(content); err != nil {
		t.Fatal(err)
	}

	// .tmp should exist before Close.
	if _, err := os.Stat(path + ".tmp"); err != nil {
		t.Errorf(".tmp file should exist before Close(): %v", err)
	}
	// Final file should NOT exist before Close.
	if _, err := os.Stat(path); err == nil {
		t.Error("final file should NOT exist before Close()")
	}

	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}

	// Then: .tmp is gone, final file has correct content.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error(".tmp file should not exist after Close()")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("final file should exist after Close(): %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != content {
		t.Errorf("content = %q, want %q", string(data), content)
	}
}

// TestSafeWriterWriteBytes tests the Write([]byte) method.
func TestSafeWriterWriteBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-bytes.txt")

	sw, err := NewSafeWriter(path)
	if err != nil {
		t.Fatal(err)
	}

	n, err := sw.Write([]byte("bytes content"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 13 {
		t.Errorf("wrote %d bytes, want 13", n)
	}

	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "bytes content" {
		t.Errorf("content = %q, want %q", string(data), "bytes content")
	}
}

// ---------------------------------------------------------------------------
// TestWriteFunctions_empty_input — empty slices produce valid headers
// ---------------------------------------------------------------------------

func TestWriteRouteList_empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "01-empty.txt")
	if err := WriteRouteList(nil, RouteCMIN2, NewIPMap(), path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "Total: 0") {
		t.Error("empty list should show Total: 0")
	}
}

func TestWriteTCPingSorted_empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "02-empty.txt")
	if err := WriteTCPingSorted(nil, path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "Total: 0") {
		t.Error("empty list should show Total: 0")
	}
}

func TestWriteSpeedSorted_empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "03-empty.txt")
	if err := WriteSpeedSorted(nil, nil, path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "Total: 0") {
		t.Error("empty list should show Total: 0")
	}
}

func TestWriteRouteAnalysis_empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "04-empty.txt")
	if err := WriteRouteAnalysis(nil, RouteCMIN2, path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "Route analysis") {
		t.Error("empty file should still have header")
	}
}

// ---------------------------------------------------------------------------
// TestGetAirport — helper that looks up airport (IATA) code from IPMap
// ---------------------------------------------------------------------------

func TestGetAirport(t *testing.T) {
	// Given: an IPMap with known entries.
	ipMap := NewIPMap()
	ipMap.add(netip.MustParseAddr("101.99.76.88"), 443, "AMS")
	ipMap.add(netip.MustParseAddr("23.249.17.25"), 443, "DFW")

	// When/Then: lookup by net.IP.
	if c := getAirport(net.ParseIP("101.99.76.88"), ipMap); c != "AMS" {
		t.Errorf("getAirport = %q, want %q", c, "AMS")
	}
	if c := getAirport(net.ParseIP("23.249.17.25"), ipMap); c != "DFW" {
		t.Errorf("getAirport = %q, want %q", c, "DFW")
	}
	if c := getAirport(net.ParseIP("1.2.3.4"), ipMap); c != "??" {
		t.Errorf("getAirport for unknown IP = %q, want %q", c, "??")
	}
}

// ---------------------------------------------------------------------------
// TestSafeWriterConcurrentWrite — concurrent writes don't race
// ---------------------------------------------------------------------------

func TestSafeWriterConcurrentWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-concurrent.txt")

	sw, err := NewSafeWriter(path)
	if err != nil {
		t.Fatal(err)
	}

	// When: goroutines write concurrently.
	done := make(chan struct{})
	go func() {
		sw.WriteString("goroutine1\n")
		done <- struct{}{}
	}()
	go func() {
		sw.WriteString("goroutine2\n")
		done <- struct{}{}
	}()
	<-done
	<-done

	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}

	// Then: file exists with content (order is non-deterministic, but
	// both lines should be present).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "goroutine1") {
		t.Error("missing goroutine1 output")
	}
	if !strings.Contains(content, "goroutine2") {
		t.Error("missing goroutine2 output")
	}
}

// ---------------------------------------------------------------------------
// init — suppress log output during tests (defined in parse_test.go)
// ---------------------------------------------------------------------------
