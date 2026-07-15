package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// SpeedResult holds the download speed test result for one IP.
type SpeedResult struct {
	IP        netip.Addr
	Port      int
	SpeedMbps float64 // calculated from bytesRead * 8 / elapsed / 1_000_000
	BytesRead int64
	Duration  time.Duration // actual elapsed time (may be < 30s on timeout)
	Error     string        // non-empty if test failed
}

// DownloadSpeed performs a single HTTP download speed test against
// speed.cloudflare.com through the specified IP:port, measuring real throughput.
// The custom dialer bypasses DNS and connects directly to the target IP.
// TLS uses ServerName="speed.cloudflare.com" for certificate matching.
//
// On timeout with partial data, bytesRead is used (not zeroed) to calculate Mbps.
// On TLS error, SpeedMbps=0 and Error="TLS fail".
func DownloadSpeed(ip netip.Addr, port int, timeout time.Duration) *SpeedResult {
	start := time.Now()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), itoa(port)))
		},
		TLSClientConfig: &tls.Config{
			ServerName: "speed.cloudflare.com",
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
	defer client.CloseIdleConnections()

	resp, err := client.Get("https://speed.cloudflare.com/__down?bytes=99999999")
	if err != nil {
		sr := &SpeedResult{
			IP:   ip,
			Port: port,
		}
		if isTLSError(err) {
			sr.Error = "TLS fail"
		} else {
			sr.Error = err.Error()
		}
		return sr
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return &SpeedResult{
			IP:    ip,
			Port:  port,
			Error: fmt.Sprintf("HTTP %d", resp.StatusCode),
		}
	}

	bytesRead, readErr := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start)
	_ = resp.Body.Close()

	sr := &SpeedResult{
		IP:        ip,
		Port:      port,
		BytesRead: bytesRead,
		Duration:  elapsed,
	}

	if bytesRead > 0 {
		sr.SpeedMbps = float64(bytesRead) * 8 / elapsed.Seconds() / 1_000_000
	}

	if readErr != nil {
		sr.Error = readErr.Error()
	}

	return sr
}

// isTLSError checks whether err is related to TLS handshake or certificate
// validation. http.Client wraps transport errors, so we check the full
// error string for TLS-related keywords.
func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "tls:") ||
		strings.Contains(errStr, "x509:") ||
		strings.Contains(errStr, "certificate") ||
		strings.Contains(errStr, "handshake failure")
}

// RunSpeedTest runs HTTP download speed tests against the top N TCPSpeedResults
// (sorted by AvgRTT ascending). A worker pool limits concurrency, and a 2-second
// delay paces test starts to avoid rate-limiting.
//
// All SpeedResults are returned; sorting for output happens in the caller.
func RunSpeedTest(results []*TCPSpeedResult, topN int, concurrency int) []*SpeedResult {
	if concurrency <= 0 {
		concurrency = 20
	}

	n := topN
	if n <= 0 || n > len(results) {
		n = len(results)
	}

	candidates := results[:n]

	log.Printf("speedtest: testing top %d of %d IPs, concurrency %d", n, len(results), concurrency)

	speedResults := make([]*SpeedResult, 0, n)
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, tcpr := range candidates {
		wg.Add(1)

		// 2s pacing delay between test starts (first starts immediately).
		if i > 0 {
			time.Sleep(2 * time.Second)
		}

		sem <- struct{}{}

		go func(sr *TCPSpeedResult) {
			defer wg.Done()
			defer func() { <-sem }()

			log.Printf("speedtest: %s:%d - testing...", sr.IP, sr.Port)

			result := DownloadSpeed(sr.IP, sr.Port, 30*time.Second)

			log.Printf("speedtest: %s:%d - %.2f Mbps (%d bytes in %v)",
				sr.IP, sr.Port, result.SpeedMbps, result.BytesRead, result.Duration)

			mu.Lock()
			speedResults = append(speedResults, result)
			mu.Unlock()
		}(tcpr)
	}

	wg.Wait()

	return speedResults
}
