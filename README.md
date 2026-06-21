# harvester-importer

> Import, normalize, and explore theHarvester OSINT intel via CLI + community Intel Board.

## What it does

theHarvester collects emails, hosts, IPs from public sources. Its JSON output is flat, undeduped, and mixes IPs into the hosts array. harvester-importer normalizes this: deduplicates, separates IPs from hostnames, counts, caches (24h SQLite TTL), and optionally submits to the community Intel Board.

## Install

```bash
git clone https://github.com/fmfalgun/harvester-importer
cd harvester-importer
python3 harvester-importer.py --help
```

No pip install needed. Python 3.8+.

theHarvester (for data collection — separate install):
```bash
pipx install theharvester
# or: pip install theHarvester
```

## Usage

```bash
# Step 1: collect intel with theHarvester
theHarvester -d target.com -b all -f results

# Step 2: import and normalize
python3 harvester-importer.py -d target.com -f results.json

# Save normalized JSON
python3 harvester-importer.py -d target.com -f results.json -o normalized.json

# Specify which sources you used (shows on Intel Board)
python3 harvester-importer.py -d target.com -f results.json --sources "crtsh,baidu,bing"

# Bypass cache (re-reads file)
python3 harvester-importer.py -d target.com -f results.json --no-cache

# Submit to Intel Board
python3 harvester-importer.py -d target.com -f results.json --submit

# Reconfigure GitHub token / display info
python3 harvester-importer.py --reconfigure
```

## Output schema

```json
{
  "domain":       "nmap.org",
  "queried_at":   "2026-06-21T00:00:00Z",
  "email_count":  4,
  "host_count":   11,
  "ip_count":     3,
  "source_count": 4,
  "emails":  ["fyodor@insecure.org", "nmap-dev@insecure.org"],
  "hosts":   ["nmap.org", "shop.nmap.org", "svn.nmap.org"],
  "ips":     ["45.33.32.156", "45.33.49.119"],
  "sources": ["certspotter", "crtsh", "hackertarget"]
}
```

## Intel Board

Community-submitted theHarvester runs indexed at:
https://fmfalgun.github.io/harvester-importer/intel-board.html

Run with `--submit` to add your domain. Cards sorted by email count.

## Cache

Results cached in `./cache.db` (SQLite, 24h TTL). Cache key: domain name. Override with `--no-cache` or tune with `--ttl HOURS`.

## License

MIT
