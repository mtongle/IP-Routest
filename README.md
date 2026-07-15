# RouteTest

A Go tool for detecting China Mobile CMIN2 (AS58807) premium routing on a list of IPs, then benchmarking TCP latency and HTTP download speed.

## Workflow

1. **Parse** — Reads `IP:PORT#COUNTRY` lines from input file(s).
2. **Traceroute** — Runs `traceroute` against each IP (with `/24` dedup and checkpoint resume).
3. **CMIN2 Detect** — Classifies routes that transit `223.120.0.0/16` or `223.119.0.0/16`.
4. **TCPing** — Measures TCP handshake RTT on all ports for CMIN2-routed IPs.
5. **Speed Test** — Downloads from `speed.cloudflare.com` via the top-N fastest IPs.

## Usage

```bash
go build -o RouteTest
./RouteTest -input ALL-2026-07-15.txt -top 50 -concurrency 20 -airport US,JP
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-input` | `ALL-2026-07-15.txt` | Input file(s), comma-separated |
| `-top` | `50` | Number of fastest IPs to speed-test |
| `-all` | `false` | Trace every unique IP (skip /24 dedup) |
| `-resume` | `true` | Resume traceroute from checkpoint |
| `-concurrency` | `20` | Traceroute worker count |
| `-tcping-workers` | `200` | TCPing worker count |
| `-airport` | `""` | Filter by country codes (e.g. `US,JP,HK`) |

## Output

Results are written to `results/`:

| File | Content |
|------|---------|
| `01-cmin2-list.txt` | CMIN2-routed IPs with country & confidence |
| `02-tcping-sorted.txt` | TCPing results sorted by latency |
| `03-speed-sorted.txt` | Speed test results sorted by throughput |
| `04-route-analysis.txt` | Full hop-by-hop route for each CMIN2 IP |

## Input format

```
IP:PORT#COUNTRY
```

Example:
```
1.2.3.4:443#US
5.6.7.8:80#JP
```

## IP Source

IP lists sourced from [@zip_cm_edu_kg](https://t.me/zip_cm_edu_kg) on Telegram.
