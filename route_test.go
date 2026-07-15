package main

import (
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"
)

// ────────────────────── ParseHopLine tests ──────────────────────

func TestParseHopLine_Standard(t *testing.T) {
	line := " 8  223.120.3.201  39.160 ms"

	hop := ParseHopLine(line)

	if hop == nil {
		t.Fatal("ParseHopLine returned nil, expected a Hop")
	}
	if hop.TTL != 8 {
		t.Errorf("TTL = %d, want 8", hop.TTL)
	}
	if !hop.IP.Equal(net.ParseIP("223.120.3.201")) {
		t.Errorf("IP = %v, want 223.120.3.201", hop.IP)
	}
	if hop.RTT != 39160000 { // 39.160 ms in nanoseconds
		t.Errorf("RTT = %v, want 39.160ms", hop.RTT)
	}
	if hop.Unreachable {
		t.Error("Unreachable = true, want false")
	}
}

func TestParseHopLine_NoResponse(t *testing.T) {
	lines := []string{
		" 9  *",
		" 10  * * *",
	}
	for _, line := range lines {
		hop := ParseHopLine(line)
		if hop != nil {
			t.Errorf("ParseHopLine(%q) = %+v, want nil", line, hop)
		}
	}
}

func TestParseHopLine_Unreachable(t *testing.T) {
	line := " 8  1.2.3.4 !H  1.234 ms"

	hop := ParseHopLine(line)

	if hop == nil {
		t.Fatal("ParseHopLine returned nil, expected a Hop")
	}
	if !hop.IP.Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("IP = %v, want 1.2.3.4", hop.IP)
	}
	if !hop.Unreachable {
		t.Error("Unreachable = false, want true")
	}
	if hop.RTT != 1234000 { // 1.234 ms in nanoseconds
		t.Errorf("RTT = %v, want 1.234ms", hop.RTT)
	}
}

func TestParseHopLine_HeaderLine(t *testing.T) {
	line := "traceroute to 1.2.3.4 (1.2.3.4), 30 hops max, 60 byte packets"

	hop := ParseHopLine(line)
	if hop != nil {
		t.Errorf("ParseHopLine returned %+v, want nil", hop)
	}
}

func TestParseHopLine_NetworkUnreachable(t *testing.T) {
	line := " 5  10.0.0.1 !N  5.000 ms"

	hop := ParseHopLine(line)

	if hop == nil {
		t.Fatal("ParseHopLine returned nil, expected a Hop")
	}
	if !hop.IP.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("IP = %v, want 10.0.0.1", hop.IP)
	}
	if !hop.Unreachable {
		t.Error("Unreachable = false, want true")
	}
	if hop.RTT != 5000000 { // 5.000 ms in nanoseconds
		t.Errorf("RTT = %v, want 5.000ms", hop.RTT)
	}
}

// ────────────────────── DedupBy24 tests ──────────────────────

func TestDedupBy24(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("223.120.3.1"),
		net.ParseIP("223.120.3.200"),
		net.ParseIP("223.120.3.50"),
		net.ParseIP("223.120.4.1"),
	}
	result := DedupBy24(ips)

	if len(result) != 2 {
		t.Fatalf("DedupBy24 returned %d IPs, want 2", len(result))
	}

	// For /24 223.120.3.x, the lowest numeric value is 223.120.3.1.
	if !result[0].Equal(net.ParseIP("223.120.3.1")) {
		t.Errorf("result[0] = %v, want 223.120.3.1 (lowest in /24)", result[0])
	}
	// For /24 223.120.4.x, only 223.120.4.1 exists.
	if !result[1].Equal(net.ParseIP("223.120.4.1")) {
		t.Errorf("result[1] = %v, want 223.120.4.1", result[1])
	}
}

func TestDedupBy24_SingleIP(t *testing.T) {
	ips := []net.IP{net.ParseIP("10.0.0.1")}
	result := DedupBy24(ips)
	if len(result) != 1 {
		t.Fatalf("DedupBy24 returned %d IPs, want 1", len(result))
	}
	if !result[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("result[0] = %v, want 10.0.0.1", result[0])
	}
}

func TestDedupBy24_Empty(t *testing.T) {
	result := DedupBy24(nil)
	if len(result) != 0 {
		t.Errorf("DedupBy24 returned %d IPs, want 0", len(result))
	}
}

// ────────────────────── Checkpoint tests ──────────────────────

func TestCheckpoint(t *testing.T) {
	cm := NewCheckpointManager("/24")

	// Use a temp path to avoid clobbering real checkpoints.
	savedPath := cm.checkpointPath
	cm.checkpointPath = t.TempDir() + "/checkpoint.json"
	defer func() { cm.checkpointPath = savedPath }()

	// Given: a checkpoint with one completed IP.
	cp := &CheckpointData{
		CompletedSet: make(map[string]bool),
		DedupMode:    "/24",
		StartTime:    time.Now(),
	}
	cm.MarkCompleted(cp, "1.2.3.4")

	// When: save then load.
	if err := cm.Save(cp); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := cm.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load returned nil data")
	}

	// Then: the IP is marked completed.
	if !loaded.CompletedSet["1.2.3.4"] {
		t.Error("1.2.3.4 not marked as completed after load")
	}
	if len(loaded.CompletedIPs) != 1 {
		t.Errorf("CompletedIPs length = %d, want 1", len(loaded.CompletedIPs))
	}
}

func TestCheckpointResume(t *testing.T) {
	cm := NewCheckpointManager("/24")
	savedPath := cm.checkpointPath
	cm.checkpointPath = t.TempDir() + "/checkpoint-resume.json"
	defer func() { cm.checkpointPath = savedPath }()

	// Given: a checkpoint with 3 completed IPs.
	cp := &CheckpointData{
		CompletedSet: make(map[string]bool),
		DedupMode:    "/24",
		StartTime:    time.Now(),
	}
	cm.MarkCompleted(cp, "1.2.3.4")
	cm.MarkCompleted(cp, "5.6.7.8")
	cm.MarkCompleted(cp, "9.10.11.12")
	if err := cm.Save(cp); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// When: load with resume.
	loaded, err := cm.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load returned nil data")
	}

	// Then: all 3 IPs are completed.
	expected := []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"}
	for _, ip := range expected {
		if !loaded.CompletedSet[ip] {
			t.Errorf("IP %s not marked as completed", ip)
		}
	}
	if !cm.IsCompleted(loaded, "1.2.3.4") {
		t.Error("IsCompleted returns false for 1.2.3.4")
	}
	if !cm.IsCompleted(loaded, "9.10.11.12") {
		t.Error("IsCompleted returns false for 9.10.11.12")
	}
}

func TestCheckpointClear(t *testing.T) {
	cm := NewCheckpointManager("/24")
	savedPath := cm.checkpointPath
	cm.checkpointPath = t.TempDir() + "/checkpoint-clear.json"
	defer func() { cm.checkpointPath = savedPath }()

	// Given: a saved checkpoint.
	cp := &CheckpointData{
		CompletedSet: make(map[string]bool),
		DedupMode:    "/24",
		StartTime:    time.Now(),
	}
	cm.MarkCompleted(cp, "1.2.3.4")
	if err := cm.Save(cp); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// When: clear.
	if err := cm.Clear(); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	// Then: load returns nil.
	loaded, err := cm.Load()
	if err != nil {
		t.Fatalf("Load after clear failed: %v", err)
	}
	if loaded != nil {
		t.Error("Load after clear returned non-nil data")
	}
}

func TestCheckpointDifferentModes(t *testing.T) {
	// Given: a checkpoint saved with dedup_mode "/24" via the production path.
	cm := NewCheckpointManager("/24")
	savedPath := cm.checkpointPath
	cm.checkpointPath = t.TempDir() + "/checkpoint-modes.json"
	defer func() { cm.checkpointPath = savedPath }()

	cp := &CheckpointData{
		CompletedSet: make(map[string]bool),
		StartTime:    time.Now(),
	}
	cm.MarkCompleted(cp, "1.2.3.4")
	if err := cm.Save(cp); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// When: load the checkpoint.
	loaded, err := cm.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	// Then: DedupMode was set by Save() from the CheckpointManager.
	if loaded.DedupMode != "/24" {
		t.Errorf("DedupMode = %q, want \"/24\"", loaded.DedupMode)
	}

	// When: simulate an incompatible mode (e.g. caller wants "all" but
	// checkpoint was saved with "/24"). The caller must treat this as
	// stale data and use an empty completed set.
	if loaded.DedupMode != "all" {
		// Incompatible — start fresh.
		loaded.CompletedSet = make(map[string]bool)
	}
	if loaded.CompletedSet["1.2.3.4"] {
		t.Error("1.2.3.4 should not be marked completed with incompatible dedup mode")
	}
}

// ────────────────────── JSON serialization test ──────────────────────

func TestCheckpointJSONRoundTrip(t *testing.T) {
	// Given: a checkpoint with mixed completed IPs.
	orig := &CheckpointData{
		CompletedIPs: []string{"1.2.3.4", "5.6.7.8"},
		CompletedSet: map[string]bool{"1.2.3.4": true, "5.6.7.8": true},
		DedupMode:    "/24",
		StartTime:    time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC),
	}

	// When: marshal and unmarshal.
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var got CheckpointData
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Then: fields match (CompletedSet is excluded from JSON).
	if len(got.CompletedIPs) != 2 {
		t.Errorf("CompletedIPs length = %d, want 2", len(got.CompletedIPs))
	}
	if got.DedupMode != "/24" {
		t.Errorf("DedupMode = %q, want \"/24\"", got.DedupMode)
	}
	if !got.StartTime.Equal(orig.StartTime) {
		t.Errorf("StartTime = %v, want %v", got.StartTime, orig.StartTime)
	}
}

// ────────────────────── ParseTracerouteOutput tests ──────────────────────

func TestParseTracerouteOutput_Complete(t *testing.T) {
	output := `traceroute to 223.120.3.201 (223.120.3.201), 30 hops max, 60 byte packets
 1  192.168.1.1  1.234 ms
 2  10.0.0.1  5.000 ms
 3  223.120.3.201  39.160 ms
`
	target := net.ParseIP("223.120.3.201")
	result := ParseTracerouteOutput(output, target)

	if result == nil {
		t.Fatal("ParseTracerouteOutput returned nil")
	}
	if !result.TargetIP.Equal(target) {
		t.Errorf("TargetIP = %v, want %v", result.TargetIP, target)
	}
	if len(result.Hops) != 3 {
		t.Fatalf("Hops length = %d, want 3", len(result.Hops))
	}
	if !result.Complete {
		t.Error("Complete = false, want true (target reached)")
	}
	if result.Error != "" {
		t.Errorf("Error = %q, want empty", result.Error)
	}

	// Verify hop details.
	if result.Hops[0].TTL != 1 || !result.Hops[0].IP.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("Hop 0: TTL=%d IP=%v, want TTL=1 IP=192.168.1.1", result.Hops[0].TTL, result.Hops[0].IP)
	}
	if result.Hops[2].TTL != 3 || !result.Hops[2].IP.Equal(target) {
		t.Errorf("Hop 2: should be target IP")
	}
}

func TestParseTracerouteOutput_Incomplete(t *testing.T) {
	output := `traceroute to 1.2.3.4 (1.2.3.4), 30 hops max, 60 byte packets
 1  192.168.1.1  1.000 ms
 2  *\n
 3  10.0.0.1  2.000 ms
`
	target := net.ParseIP("1.2.3.4")
	result := ParseTracerouteOutput(output, target)

	if result == nil {
		t.Fatal("ParseTracerouteOutput returned nil")
	}
	if len(result.Hops) != 2 {
		t.Fatalf("Hops length = %d, want 2", len(result.Hops))
	}
	if result.Complete {
		t.Error("Complete = true, want false (target not reached)")
	}
}

func TestParseTracerouteOutput_Empty(t *testing.T) {
	target := net.ParseIP("1.2.3.4")
	result := ParseTracerouteOutput("", target)

	if result == nil {
		t.Fatal("ParseTracerouteOutput returned nil")
	}
	if len(result.Hops) != 0 {
		t.Errorf("Hops length = %d, want 0", len(result.Hops))
	}
}

// ────────────────────── Helper tests ──────────────────────

func Test_ipsSame24(t *testing.T) {
	tests := []struct {
		name string
		a, b net.IP
		want bool
	}{
		{"same subnet", net.ParseIP("223.120.3.1"), net.ParseIP("223.120.3.200"), true},
		{"different subnet", net.ParseIP("223.120.3.1"), net.ParseIP("223.120.4.1"), false},
		{"exact match", net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.1"), true},
		{"IPv6 returns false", net.ParseIP("::1"), net.ParseIP("::2"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipsSame24(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("ipsSame24(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// ────────────────────── NewTracerouteRunner defaults ──────────────────────

func TestNewTracerouteRunner(t *testing.T) {
	tr := NewTracerouteRunner()
	if tr.Concurrent != 20 {
		t.Errorf("Concurrent = %d, want 20", tr.Concurrent)
	}
	if tr.Cooldown != 10*time.Second {
		t.Errorf("Cooldown = %v, want 10s", tr.Cooldown)
	}
	if tr.PerIPTimeout != 30*time.Second {
		t.Errorf("PerIPTimeout = %v, want 30s", tr.PerIPTimeout)
	}
	if tr.Checkpoint == nil {
		t.Error("Checkpoint is nil, want non-nil")
	}
}

// ────────────────────── File system helpers ──────────────────────

func TestCheckpointFileNotFound(t *testing.T) {
	cm := NewCheckpointManager("/24")
	savedPath := cm.checkpointPath
	cm.checkpointPath = "/tmp/.nonexistent-checkpoint-" + t.Name() + ".json"
	defer func() { cm.checkpointPath = savedPath }()

	// Load on non-existent file returns nil, nil.
	cp, err := cm.Load()
	if err != nil {
		t.Fatalf("Load on non-existent file returned error: %v", err)
	}
	if cp != nil {
		t.Error("Load on non-existent file returned non-nil data")
	}

	// Clean up.
	os.Remove(cm.checkpointPath)
}

// ────────────────────── Route detection tests ──────────────────────

func TestIsRouted_CMIN2_Positive(t *testing.T) {
	// Given: a trace result with a CMIN2 hop.
	tr := &TraceResult{
		TargetIP: net.ParseIP("23.249.17.25"),
		Hops: []Hop{
			{TTL: 1, IP: net.ParseIP("192.168.1.1")},
			{TTL: 9, IP: net.ParseIP("223.120.141.50")},
		},
	}

	// When
	got := tr.IsRouted(RouteCMIN2)

	// Then
	if !got {
		t.Error("IsRouted(RouteCMIN2) = false, want true (hop 223.120.141.50 is in CMIN2 range)")
	}
}

func TestIsRouted_CMIN2_Negative(t *testing.T) {
	// Given: a trace result with only non-CMIN2 hops.
	tr := &TraceResult{
		TargetIP: net.ParseIP("1.1.1.1"),
		Hops: []Hop{
			{TTL: 1, IP: net.ParseIP("192.168.1.1")},
			{TTL: 2, IP: net.ParseIP("1.1.1.1")},
		},
	}

	// When
	got := tr.IsRouted(RouteCMIN2)

	// Then
	if got {
		t.Error("IsRouted(RouteCMIN2) = true, want false (1.1.1.1 is not in CMIN2 range)")
	}
}

func TestIsRouted_CMIN2_SecondaryRange(t *testing.T) {
	// Given: a trace result with a hop in the secondary CMIN2 range.
	tr := &TraceResult{
		TargetIP: net.ParseIP("10.0.0.1"),
		Hops: []Hop{
			{TTL: 1, IP: net.ParseIP("223.119.1.1")},
		},
	}

	// When
	got := tr.IsRouted(RouteCMIN2)

	// Then
	if !got {
		t.Error("IsRouted(RouteCMIN2) = false, want true (223.119.1.1 is in secondary CMIN2 range)")
	}
}

func TestIsRouted_CMIN2_NotMatched(t *testing.T) {
	// Given: a trace result with a hop in a nearby but non-CMIN2 range.
	tr := &TraceResult{
		TargetIP: net.ParseIP("10.0.0.1"),
		Hops: []Hop{
			{TTL: 1, IP: net.ParseIP("223.118.1.1")},
		},
	}

	// When
	got := tr.IsRouted(RouteCMIN2)

	// Then
	if got {
		t.Error("IsRouted(RouteCMIN2) = true, want false (223.118.1.1 is regular CMI, not CMIN2)")
	}
}

func TestCountRouteHops_CMIN2(t *testing.T) {
	// Given: hops with 2 CMIN2 and 3 non-CMIN2 IPs.
	hops := []Hop{
		{TTL: 1, IP: net.ParseIP("192.168.1.1")},
		{TTL: 2, IP: net.ParseIP("223.120.3.201")},
		{TTL: 3, IP: net.ParseIP("10.0.0.1")},
		{TTL: 4, IP: net.ParseIP("223.120.141.50")},
		{TTL: 5, IP: net.ParseIP("8.8.8.8")},
	}

	// When
	count := CountRouteHops(hops, RouteCMIN2)

	// Then
	if count != 2 {
		t.Errorf("CountRouteHops(hops, RouteCMIN2) = %d, want 2", count)
	}
}

func TestClassifyRouteResult_CMIN2_HighConfidence(t *testing.T) {
	// Given: a trace result with 2 CMIN2 hops.
	tr := &TraceResult{
		TargetIP: net.ParseIP("23.249.17.25"),
		Hops: []Hop{
			{TTL: 9, IP: net.ParseIP("223.120.141.50")},
			{TTL: 10, IP: net.ParseIP("223.120.130.34")},
		},
	}

	// When
	result := ClassifyRouteResult(tr, RouteCMIN2)

	// Then
	if !result.IsRouted {
		t.Error("IsRouted = false, want true")
	}
	if result.RouteType != RouteCMIN2 {
		t.Errorf("RouteType = %v, want %v", result.RouteType, RouteCMIN2)
	}
	if result.Confidence != 0.95 {
		t.Errorf("Confidence = %v, want 0.95", result.Confidence)
	}
	if len(result.RouteHops) != 2 {
		t.Errorf("RouteHops count = %d, want 2", len(result.RouteHops))
	}
	if !result.TargetIP.Equal(net.ParseIP("23.249.17.25")) {
		t.Errorf("TargetIP = %v, want 23.249.17.25", result.TargetIP)
	}
	if len(result.AllHops) != 2 {
		t.Errorf("AllHops count = %d, want 2", len(result.AllHops))
	}
}

func TestClassifyRouteResult_CMIN2_LowConfidence(t *testing.T) {
	// Given: a trace result with 1 CMIN2 hop.
	tr := &TraceResult{
		TargetIP: net.ParseIP("10.0.0.1"),
		Hops: []Hop{
			{TTL: 1, IP: net.ParseIP("192.168.1.1")},
			{TTL: 5, IP: net.ParseIP("223.120.3.201")},
			{TTL: 6, IP: net.ParseIP("8.8.8.8")},
		},
	}

	// When
	result := ClassifyRouteResult(tr, RouteCMIN2)

	// Then
	if !result.IsRouted {
		t.Error("IsRouted = false, want true")
	}
	if result.Confidence != 0.70 {
		t.Errorf("Confidence = %v, want 0.70", result.Confidence)
	}
	if len(result.RouteHops) != 1 {
		t.Errorf("RouteHops count = %d, want 1", len(result.RouteHops))
	}
}

func TestClassifyRouteResult_CMIN2_NotRouted(t *testing.T) {
	// Given: a trace result with no CMIN2 hops.
	tr := &TraceResult{
		TargetIP: net.ParseIP("1.1.1.1"),
		Hops: []Hop{
			{TTL: 1, IP: net.ParseIP("192.168.1.1")},
			{TTL: 2, IP: net.ParseIP("1.1.1.1")},
		},
	}

	// When
	result := ClassifyRouteResult(tr, RouteCMIN2)

	// Then
	if result.IsRouted {
		t.Error("IsRouted = true, want false")
	}
	if result.Confidence != 0.05 {
		t.Errorf("Confidence = %v, want 0.05", result.Confidence)
	}
	if len(result.RouteHops) != 0 {
		t.Errorf("RouteHops count = %d, want 0", len(result.RouteHops))
	}
}

func TestClassifyRouteResult_CMIN2_EmptyHops(t *testing.T) {
	// Given: a trace result with no hops.
	tr := &TraceResult{
		TargetIP: net.ParseIP("10.0.0.1"),
	}

	// When
	result := ClassifyRouteResult(tr, RouteCMIN2)

	// Then
	if result.IsRouted {
		t.Error("IsRouted = true, want false for empty hops")
	}
	if result.Confidence != 0.05 {
		t.Errorf("Confidence = %v, want 0.05", result.Confidence)
	}
	if len(result.RouteHops) != 0 {
		t.Errorf("RouteHops count = %d, want 0", len(result.RouteHops))
	}
}

func TestCMIN2Prefixes_Contains(t *testing.T) {
	// Given: the CMIN2 prefix table.
	prefixes := RoutePrefixes[RouteCMIN2]

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"in primary range", "223.120.3.201", true},
		{"not in range", "1.1.1.1", false},
		{"in secondary range", "223.119.1.1", true},
		{"adjacent not in range", "223.118.1.1", false},
		{"boundary low", "223.120.0.0", true},
		{"boundary high", "223.120.255.255", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			matched := false
			for _, p := range prefixes {
				if p.Contains(ip) {
					matched = true
					break
				}
			}
			if matched != tt.want {
				t.Errorf("Contains(%s) = %v, want %v", tt.ip, matched, tt.want)
			}
		})
	}
}
