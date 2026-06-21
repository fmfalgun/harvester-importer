"""
build_demo.py — write nmap.org seed intel for the Intel Board.

harvester-importer cannot auto-refresh via CI (theHarvester requires live
queries and API keys). This script writes a static nmap.org seed entry and
updates last_refreshed to the current timestamp.
Called by .github/workflows/build-demo.yml on a daily cron.
"""

import json
from pathlib import Path
from datetime import datetime, timezone

DOMAIN       = "nmap.org"
DISPLAY_NAME = "fmfalgun"
DISPLAY_LOC  = "Chennai, India"
DOMAIN_OUT   = Path("web/data/domains/nmap.org.json")
INDEX_OUT    = Path("web/data/index.json")

SEED_INTEL = {
    "emails": [
        "fyodor@insecure.org",
        "nmap-announce@insecure.org",
        "nmap-dev@insecure.org",
        "nmap-hackers@insecure.org",
    ],
    "hosts": [
        "insecure.org",
        "mail.nmap.org",
        "nmap.org",
        "sectools.org",
        "secwiki.org",
        "seclists.org",
        "shop.nmap.org",
        "svn.nmap.org",
        "wiki.nmap.org",
        "www.nmap.org",
        "www.seclists.org",
    ],
    "ips": [
        "45.33.32.156",
        "45.33.49.119",
        "45.79.182.96",
    ],
    "sources": [
        "certspotter",
        "crtsh",
        "dnsdumpster",
        "hackertarget",
    ],
}


def write_domain_file() -> dict:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    DOMAIN_OUT.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "domain":         DOMAIN,
        "display_name":   DISPLAY_NAME,
        "display_loc":    DISPLAY_LOC,
        "queried_at":     now_str,
        "last_refreshed": now_str,
        "email_count":    len(SEED_INTEL["emails"]),
        "host_count":     len(SEED_INTEL["hosts"]),
        "ip_count":       len(SEED_INTEL["ips"]),
        "source_count":   len(SEED_INTEL["sources"]),
        "emails":         SEED_INTEL["emails"],
        "hosts":          SEED_INTEL["hosts"],
        "ips":            SEED_INTEL["ips"],
        "sources":        SEED_INTEL["sources"],
    }
    DOMAIN_OUT.write_text(json.dumps(data, indent=2))
    print(f"[+] Written: {DOMAIN_OUT}")
    return data


def update_index(data: dict) -> None:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if INDEX_OUT.exists():
        index = json.loads(INDEX_OUT.read_text())
    else:
        index = {
            "generated_at":  now_str,
            "total_domains": 0,
            "total_scans":   0,
            "domains":       [],
        }

    entry = {
        "domain":         DOMAIN,
        "display_name":   DISPLAY_NAME,
        "display_loc":    DISPLAY_LOC,
        "queried_at":     data.get("queried_at", now_str),
        "last_refreshed": now_str,
        "email_count":    data.get("email_count", 0),
        "host_count":     data.get("host_count", 0),
        "ip_count":       data.get("ip_count", 0),
        "source_count":   data.get("source_count", 0),
    }

    domains = [d for d in index.get("domains", []) if d.get("domain") != DOMAIN]
    domains.append(entry)
    domains.sort(key=lambda d: d["domain"])

    index["domains"]       = domains
    index["total_domains"] = len(domains)
    index["total_scans"]   = index.get("total_scans", 0) + 1
    index["generated_at"]  = now_str

    INDEX_OUT.write_text(json.dumps(index, indent=2))
    print(f"[+] Updated: {INDEX_OUT} ({len(domains)} domains)")


def main():
    data = write_domain_file()
    update_index(data)
    print("[+] build_demo.py complete")


if __name__ == "__main__":
    main()
