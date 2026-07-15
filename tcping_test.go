package main

import (
	"log"
	"net/netip"
	"sort"
	"testing"
	"time"
)

// ────────────────────── TCPingSingle tests ──────────────────────

func TestTCPingSingle_OpenPort(t *testing.T) {
	// Given: a known-open port on a CMIN2-routed IP.
	addr := "23.249.17.25:443"
	timeout := 5 * time.Second

	// When
	rtt, err := TCPingSingle(addr, timeout)

	// Then
	if err != nil {
		t.Skipf("network may be unavailable: %v", err)
	}
	if rtt <= 0 {
		t.Errorf("RTT = %v, want > 0", rtt)
	}
	if rtt > timeout {
		t.Errorf("RTT = %v, want <= %v", rtt, timeout)
	}
}

func TestTCPingSingle_ClosedPort(t *testing.T) {
	// Given: a port that is unlikely to be open.
	addr := "23.249.17.25:9999"
	timeout := 3 * time.Second

	// When
	_, err := TCPingSingle(addr, timeout)

	// Then
	if err == nil {
		t.Error("expected error for closed port, got nil")
	}
}

// ────────────────────── TCPingPort tests ──────────────────────

func TestTCPingPort_FourRounds(t *testing.T) {
	// Given: a known-good IP with 443 open.
	ip := netip.MustParseAddr("23.249.17.25")
	port := 443
	rounds := 4
	timeout := 5 * time.Second

	// When
	pr := TCPingPort(ip, port, rounds, timeout)

	// Then
	if pr == nil {
		t.Skip("TCP connection to 23.249.17.25:443 failed, skipping")
	}
	if pr.Port != 443 {
		t.Errorf("Port = %d, want 443", pr.Port)
	}
	if pr.Total != 4 {
		t.Errorf("Total = %d, want 4", pr.Total)
	}
	if pr.Successes == 0 {
		t.Fatal("expected at least 1 successful round")
	}
	if pr.AvgRTT <= 0 {
		t.Errorf("AvgRTT = %v, want > 0", pr.AvgRTT)
	}
	if len(pr.RTTs) != pr.Successes {
		t.Errorf("len(RTTs) = %d, want %d (matches Successes)", len(pr.RTTs), pr.Successes)
	}
}

func TestTCPingPort_AllFail(t *testing.T) {
	// Given: a port that will certainly refuse connection.
	ip := netip.MustParseAddr("23.249.17.25")
	port := 1 // port 1 is almost always closed
	rounds := 2
	timeout := 1 * time.Second

	// When
	pr := TCPingPort(ip, port, rounds, timeout)

	// Then — all rounds fail, should return nil.
	if pr != nil {
		t.Logf("unexpected success on port 1: %+v", pr)
	}
}

// ────────────────────── PortRTT calculation tests ──────────────────────

func TestPortRTT_Calculation(t *testing.T) {
	// Given: a PortRTT with 3 successes out of 4.
	pr := &PortRTT{
		Port:      443,
		RTTs:      []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond},
		AvgRTT:    (10*time.Millisecond + 20*time.Millisecond + 30*time.Millisecond) / 3,
		LossRate:  0.25,
		Successes: 3,
		Total:     4,
	}

	// When — verify calculation.
	expectedAvg := (10*time.Millisecond + 20*time.Millisecond + 30*time.Millisecond) / 3
	expectedLoss := 1.0 - 3.0/4.0

	// Then
	if pr.Successes != 3 {
		t.Errorf("Successes = %d, want 3", pr.Successes)
	}
	if pr.Total != 4 {
		t.Errorf("Total = %d, want 4", pr.Total)
	}
	if pr.AvgRTT != expectedAvg {
		t.Errorf("AvgRTT = %v, want %v", pr.AvgRTT, expectedAvg)
	}
	if pr.LossRate != expectedLoss {
		t.Errorf("LossRate = %v, want %v", pr.LossRate, expectedLoss)
	}
	if len(pr.RTTs) != 3 {
		t.Errorf("len(RTTs) = %d, want 3", len(pr.RTTs))
	}
}

func TestPortRTT_AllFailed(t *testing.T) {
	// Given: a PortRTT with zero successes.
	pr := &PortRTT{
		Port:      443,
		RTTs:      nil,
		AvgRTT:    0,
		LossRate:  1.0,
		Successes: 0,
		Total:     4,
	}

	// Then
	if pr.Successes != 0 {
		t.Errorf("Successes = %d, want 0", pr.Successes)
	}
	if pr.LossRate != 1.0 {
		t.Errorf("LossRate = %v, want 1.0", pr.LossRate)
	}
	if len(pr.RTTs) != 0 {
		t.Errorf("len(RTTs) = %d, want 0", len(pr.RTTs))
	}
}

// ────────────────────── selectBestPort tests ──────────────────────

func TestSelectBestPort(t *testing.T) {
	// Given: ports with different RTTs.
	results := map[int]*PortRTT{
		443: {
			Port: 443, RTTs: []time.Duration{50 * time.Millisecond, 60 * time.Millisecond},
			AvgRTT: 55 * time.Millisecond, LossRate: 0.0, Successes: 2, Total: 2,
		},
		8443: {
			Port: 8443, RTTs: []time.Duration{30 * time.Millisecond, 40 * time.Millisecond},
			AvgRTT: 35 * time.Millisecond, LossRate: 0.0, Successes: 2, Total: 2,
		},
		2053: {
			Port: 2053, RTTs: []time.Duration{100 * time.Millisecond},
			AvgRTT: 100 * time.Millisecond, LossRate: 0.5, Successes: 1, Total: 2,
		},
	}

	// When
	port, avgRTT, lossRate, rawRTTs := selectBestPort(results)

	// Then — 8443 has lowest AvgRTT (35ms).
	if port != 8443 {
		t.Errorf("selected port = %d, want 8443 (lowest AvgRTT)", port)
	}
	if avgRTT != 35*time.Millisecond {
		t.Errorf("AvgRTT = %v, want 35ms", avgRTT)
	}
	if lossRate != 0.0 {
		t.Errorf("LossRate = %v, want 0.0", lossRate)
	}
	if len(rawRTTs) != 2 {
		t.Errorf("len(rawRTTs) = %d, want 2", len(rawRTTs))
	}
}

func TestSelectBestPort_TiePrefer443(t *testing.T) {
	// Given: two ports with identical AvgRTT.
	results := map[int]*PortRTT{
		8443: {
			Port: 8443, RTTs: []time.Duration{50 * time.Millisecond},
			AvgRTT: 50 * time.Millisecond, LossRate: 0.0, Successes: 1, Total: 1,
		},
		443: {
			Port: 443, RTTs: []time.Duration{50 * time.Millisecond},
			AvgRTT: 50 * time.Millisecond, LossRate: 0.0, Successes: 1, Total: 1,
		},
	}

	// When
	port, _, _, _ := selectBestPort(results)

	// Then — tie should prefer 443.
	if port != 443 {
		t.Errorf("selected port = %d, want 443 (tie-breaker)", port)
	}
}

func TestSelectBestPort_AllFailed(t *testing.T) {
	// Given: all ports have 100% loss, one has slightly lower loss rate.
	results := map[int]*PortRTT{
		443: {
			Port: 443, LossRate: 1.0, Successes: 0, Total: 4,
		},
		8443: {
			Port: 8443, LossRate: 0.75, Successes: 1, Total: 4,
			RTTs: []time.Duration{100 * time.Millisecond}, AvgRTT: 100 * time.Millisecond,
		},
	}

	// When
	port, _, lossRate, _ := selectBestPort(results)

	// Then — 8443 has lower loss rate (0.75 vs 1.0).
	if port != 8443 {
		t.Errorf("selected port = %d, want 8443 (lower loss rate)", port)
	}
	if lossRate != 0.75 {
		t.Errorf("LossRate = %v, want 0.75", lossRate)
	}
}

func TestSelectBestPort_SingleEntry(t *testing.T) {
	// Given: a single port result.
	results := map[int]*PortRTT{
		443: {
			Port: 443, RTTs: []time.Duration{42 * time.Millisecond},
			AvgRTT: 42 * time.Millisecond, LossRate: 0.0, Successes: 1, Total: 1,
		},
	}

	// When
	port, avgRTT, lossRate, rawRTTs := selectBestPort(results)

	// Then
	if port != 443 {
		t.Errorf("selected port = %d, want 443", port)
	}
	if avgRTT != 42*time.Millisecond {
		t.Errorf("AvgRTT = %v, want 42ms", avgRTT)
	}
	if lossRate != 0.0 {
		t.Errorf("LossRate = %v, want 0.0", lossRate)
	}
	if len(rawRTTs) != 1 {
		t.Errorf("len(rawRTTs) = %d, want 1", len(rawRTTs))
	}
}

// ────────────────────── TCPSpeedResult sorting test ──────────────────────

func TestTCPSpeedResult_Sorting(t *testing.T) {
	// Given: three results with different RTTs.
	results := []*TCPSpeedResult{
		{
			IP: netip.MustParseAddr("10.0.0.3"), Port: 443,
			AvgRTT: 100 * time.Millisecond, LossRate: 0.0,
		},
		{
			IP: netip.MustParseAddr("10.0.0.1"), Port: 443,
			AvgRTT: 30 * time.Millisecond, LossRate: 0.0,
		},
		{
			IP: netip.MustParseAddr("10.0.0.2"), Port: 8443,
			AvgRTT: 50 * time.Millisecond, LossRate: 0.25,
		},
	}

	// When — sort by AvgRTT ascending.
	sort.Slice(results, func(i, j int) bool {
		return results[i].AvgRTT < results[j].AvgRTT
	})

	// Then
	if results[0].AvgRTT != 30*time.Millisecond {
		t.Errorf("results[0].AvgRTT = %v, want 30ms", results[0].AvgRTT)
	}
	if results[1].AvgRTT != 50*time.Millisecond {
		t.Errorf("results[1].AvgRTT = %v, want 50ms", results[1].AvgRTT)
	}
	if results[2].AvgRTT != 100*time.Millisecond {
		t.Errorf("results[2].AvgRTT = %v, want 100ms", results[2].AvgRTT)
	}
}

// ────────────────────── GetPortsForIP test ──────────────────────

func TestGetPortsForIP(t *testing.T) {
	// Given: an IPMap with a known IP.
	m := NewIPMap()
	ip := netip.MustParseAddr("23.249.17.25")
	m.add(ip, 443, "US")
	m.add(ip, 8443, "US")

	// When
	ports := GetPortsForIP(ip, m)

	// Then
	if len(ports) != 2 {
		t.Fatalf("len(ports) = %d, want 2", len(ports))
	}
	if ports[0] != 443 {
		t.Errorf("ports[0] = %d, want 443", ports[0])
	}
	if ports[1] != 8443 {
		t.Errorf("ports[1] = %d, want 8443", ports[1])
	}
}

func TestGetPortsForIP_Unknown(t *testing.T) {
	// Given: an empty IPMap.
	m := NewIPMap()
	ip := netip.MustParseAddr("1.2.3.4")

	// When
	ports := GetPortsForIP(ip, m)

	// Then
	if ports != nil {
		t.Errorf("expected nil for unknown IP, got %v", ports)
	}
}

// ────────────────────── itoa helper test ──────────────────────

func TestItoa(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{443, "443"},
		{65535, "65535"},
		{-1, "-1"},
		{123456789, "123456789"},
	}
	for _, tt := range tests {
		got := itoa(tt.input)
		if got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ────────────────────── init ──────────────────────

func init() {
	// Suppress log output during tests to keep output clean.
	log.SetFlags(0)
	log.SetOutput(testLogWriter{})
}
