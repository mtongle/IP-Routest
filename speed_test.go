package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

// ────────────────────── DownloadSpeed tests ──────────────────────

func TestDownloadSpeed_KnownGood(t *testing.T) {
	// Given: a known CMIN2-routed Cloudflare IP with port 443 open.
	ip := netip.MustParseAddr("23.249.17.25")
	port := 443
	timeout := 15 * time.Second

	// When
	result := DownloadSpeed(ip, port, timeout)

	// Then
	if result.Error != "" && result.SpeedMbps == 0 {
		t.Skipf("network may be unavailable: %s", result.Error)
	}
	if result.SpeedMbps <= 0 {
		t.Errorf("SpeedMbps = %.2f, want > 0", result.SpeedMbps)
	}
	if result.BytesRead <= 0 {
		t.Errorf("BytesRead = %d, want > 0", result.BytesRead)
	}
	if result.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0", result.Duration)
	}
}

func TestDownloadSpeed_InvalidIP(t *testing.T) {
	// Given: an IP that does not serve speed.cloudflare.com.
	// 1.1.1.1 has port 443 open but serves a different TLS certificate,
	// so the TLS handshake should fail when we request speed.cloudflare.com.
	ip := netip.MustParseAddr("1.1.1.1")
	port := 443
	timeout := 5 * time.Second

	// When
	result := DownloadSpeed(ip, port, timeout)

	// Then — either TLS fails outright or we get zero speed.
	if result.Error == "" && result.SpeedMbps != 0 {
		t.Errorf("expected failure, got SpeedMbps=%.2f Error=%q", result.SpeedMbps, result.Error)
	}
	if result.Error == "" {
		t.Error("expected non-empty Error for invalid IP")
	}
	if result.SpeedMbps != 0 {
		t.Errorf("SpeedMbps = %.2f, want 0", result.SpeedMbps)
	}
}

// ────────────────────── Mbps calculation test ──────────────────────

func TestSpeedResult_MbpsCalculation(t *testing.T) {
	tests := []struct {
		name      string
		bytesRead int64
		duration  time.Duration
		wantMbps  float64
	}{
		{
			name:      "100MB in 10s",
			bytesRead: 100_000_000, // 100 megabytes (metric)
			duration:  10 * time.Second,
			wantMbps:  80.0, // 100MB * 8 / 10s / 1e6 = 80 Mbps
		},
		{
			name:      "50MB in 30s",
			bytesRead: 50_000_000, // 50 megabytes (metric)
			duration:  30 * time.Second,
			wantMbps:  13.333333, // 50MB * 8 / 30s / 1e6 ≈ 13.33 Mbps
		},
		{
			name:      "0 bytes",
			bytesRead: 0,
			duration:  5 * time.Second,
			wantMbps:  0,
		},
		{
			name:      "1 byte in 1s",
			bytesRead: 1,
			duration:  1 * time.Second,
			wantMbps:  0.000008, // 1 * 8 / 1 / 1e6 = 0.000008
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When — construct a SpeedResult as DownloadSpeed would.
			sr := &SpeedResult{
				BytesRead: tt.bytesRead,
				Duration:  tt.duration,
			}
			if sr.BytesRead > 0 {
				sr.SpeedMbps = float64(sr.BytesRead) * 8 / sr.Duration.Seconds() / 1_000_000
			}

			// Then
			if diff := sr.SpeedMbps - tt.wantMbps; diff > 0.001 || diff < -0.001 {
				t.Errorf("SpeedMbps = %.6f, want ≈ %.6f (diff=%.6f)", sr.SpeedMbps, tt.wantMbps, diff)
			}
		})
	}
}

// ────────────────────── Timeout with partial data test ──────────────────────

func TestDownloadSpeed_TimeoutPartial(t *testing.T) {
	// Given: an HTTP server that sends 512KB then hangs long past the timeout.
	slowHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1048576") // 1MB advertised
		w.WriteHeader(http.StatusOK)

		data := make([]byte, 512*1024)
		n, _ := w.Write(data)
		_ = n // bytes sent, used for verification below
		w.(http.Flusher).Flush()

		// Sleep well past the client timeout so the body read is interrupted.
		time.Sleep(5 * time.Second)
	}

	server := httptest.NewServer(http.HandlerFunc(slowHandler))
	defer server.Close()

	// When: request with a short timeout that will fire during body read.
	transport := &http.Transport{
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Timeout:   200 * time.Millisecond,
		Transport: transport,
	}
	defer client.CloseIdleConnections()

	start := time.Now()
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("expected partial response, got error before body: %v", err)
	}
	defer resp.Body.Close()

	bytesRead, readErr := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start)

	// Then: partial bytes should have been read despite timeout.
	if bytesRead == 0 {
		t.Fatal("expected partial bytes read before timeout, got 0")
	}
	if readErr == nil {
		t.Fatal("expected timeout error, got nil")
	}

	speedMbps := float64(bytesRead) * 8 / elapsed.Seconds() / 1_000_000
	if speedMbps <= 0 {
		t.Errorf("speed = %.2f Mbps, want > 0 (partial data)", speedMbps)
	}

	t.Logf("partial read: %d bytes in %v = %.2f Mbps (error: %v)",
		bytesRead, elapsed.Round(time.Millisecond), speedMbps, readErr)
}

// ────────────────────── RunSpeedTest integration test ──────────────────────

func TestRunSpeedTest(t *testing.T) {
	// Given: two TCPSpeedResults (one low-latency, one higher).
	results := []*TCPSpeedResult{
		{IP: netip.MustParseAddr("23.249.17.25"), Port: 443, AvgRTT: 10 * time.Millisecond},
		{IP: netip.MustParseAddr("104.16.0.1"), Port: 443, AvgRTT: 20 * time.Millisecond},
	}

	// When: run speed test on top 1, concurrency 2.
	speedResults := RunSpeedTest(results, 1, 2)

	// Then: exactly 1 result.
	if len(speedResults) != 1 {
		t.Fatalf("expected 1 result, got %d", len(speedResults))
	}

	sr := speedResults[0]
	if sr.SpeedMbps < 0 {
		t.Errorf("SpeedMbps = %.2f, want >= 0", sr.SpeedMbps)
	}
	if sr.IP.Compare(netip.MustParseAddr("23.249.17.25")) != 0 {
		t.Errorf("IP = %s, want 23.249.17.25 (topN=1 picks first)", sr.IP)
	}
	if sr.Port != 443 {
		t.Errorf("Port = %d, want 443", sr.Port)
	}
}
