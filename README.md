# IP-Routest

A Go tool for detecting China Mobile CMIN2 (AS58807) premium routing on a list of IPs, then benchmarking TCP latency and HTTP download speed.

## Workflow

1. **Fetch** — Fetches IP list with IATA airport codes from `https://zip.cm.edu.kg/all.json` (or parses local file via `-input`).
2. **Traceroute** — Runs `traceroute` against each IP (with `/24` dedup and checkpoint resume).
3. **CMIN2 Detect** — Classifies routes that transit `223.120.0.0/16` or `223.119.0.0/16`.
4. **TCPing** — Measures TCP handshake RTT on all ports for CMIN2-routed IPs.
5. **Speed Test** — Downloads from `speed.cloudflare.com` via the top-N fastest IPs.

## Usage

```bash
go build -o IP-Routest
./IP-Routest -top 50 -concurrency 20 -airport NRT,LAX,HKG
```

Use a local file instead of the API:

```bash
./IP-Routest -input my-ips.txt
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-input` | `""` | Input file(s), comma-separated (empty = fetch from API) |
| `-top` | `50` | Number of fastest IPs to speed-test |
| `-all` | `false` | Trace every unique IP (skip /24 dedup) |
| `-resume` | `true` | Resume traceroute from checkpoint |
| `-concurrency` | `20` | Traceroute worker count |
| `-tcping-workers` | `200` | TCPing worker count |
| `-airport` | `""` | Filter by IATA airport codes (e.g. `NRT,LAX,HKG`) |

## Output

Results are written to `results/`:

| File | Content |
|------|---------|
| `01-cmin2-list.txt` | CMIN2-routed IPs with airport (IATA) & confidence |
| `02-tcping-sorted.txt` | TCPing results sorted by latency |
| `03-speed-sorted.txt` | Speed test results sorted by throughput |
| `04-route-analysis.txt` | Full hop-by-hop route for each CMIN2 IP |

## Input format (file fallback)

```
IP:PORT#IATA
```

Example:
```
1.2.3.4:443#DFW
5.6.7.8:80#NRT
```

## IP Source

By default, IP data is fetched from [zip.cm.edu.kg](https://zip.cm.edu.kg/all.json) which includes colo IATA codes for each IP. Alternatively, a custom file can be supplied via `-input`.
