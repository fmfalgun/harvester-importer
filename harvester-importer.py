#!/usr/bin/env python3
"""
harvester-importer.py

Reads theHarvester's JSON output file, normalises the raw data (dedup, sort,
filter), prints a colour terminal summary, caches the result in a local SQLite
cache (./cache.db), and optionally submits the findings to the community Intel
Board via a GitHub Issue.

Part of a portfolio of open-source pentest CLI tools (#6 of 9).
Community board: intel-board.html (sorted by email_count desc).

Output behaviour:
  - stdout     : always (coloured terminal summary)
  - cache.db   : always (SQLite TTL cache, ./cache.db — auto-created)
  - JSON file  : optional (--output <path>)

Cache behaviour:
  - Results are cached for 24 hours by default (tune with --ttl)
  - Use --no-cache to force a fresh import (cache is still written)

theHarvester usage (run this first, then import the output here):
  theHarvester -d nmap.org -b certspotter,crtsh,hackertarget -f results
  # produces results.json

Usage examples:
  python3 harvester-importer.py -d nmap.org -f results.json
  python3 harvester-importer.py -d nmap.org -f results.json -o normalized.json
  python3 harvester-importer.py -d nmap.org -f results.json --sources "certspotter,crtsh,hackertarget"
  python3 harvester-importer.py -d nmap.org -f results.json --submit
  python3 harvester-importer.py -d nmap.org -f results.json --no-cache
  python3 harvester-importer.py -d nmap.org -f results.json --ttl 6
  python3 harvester-importer.py --reconfigure

Output JSON schema (what this tool produces):
  {
    "domain":       "nmap.org",
    "queried_at":   "2026-06-21T00:00:00Z",
    "email_count":  4,
    "host_count":   11,
    "ip_count":     3,
    "source_count": 4,
    "emails":  ["fyodor@insecure.org", ...],   // sorted, deduped, must contain @
    "hosts":   ["nmap.org", "shop.nmap.org"],   // sorted, deduped, non-IP hostnames only
    "ips":     ["45.33.32.156", ...],           // sorted, deduped, all IPs
    "sources": ["certspotter", "crtsh", ...]   // from --sources flag or []
  }
"""

import json
import re
import sqlite3
import sys
import argparse
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional


# ════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════

__version__       = "1.0.0"
CONFIG_PATH       = Path.home() / ".config" / "harvester-importer" / "config.json"
GITHUB_ISSUES_URL = "https://api.github.com/repos/fmfalgun/harvester-importer/issues"
CACHE_DB          = "./cache.db"

# ANSI colour codes — used to make terminal output visually distinct.
# Falls back to plain text if stdout is piped (not a TTY).
COLOURS = {
    "HIGH":   "\033[91m",  # bright red
    "MEDIUM": "\033[93m",  # bright yellow
    "LOW":    "\033[94m",  # bright blue
    "INFO":   "\033[92m",  # bright green
    "RESET":  "\033[0m",
    "BOLD":   "\033[1m",
    "DIM":    "\033[2m",
}


def c(level_or_key: str, text: str) -> str:
    """Apply ANSI colour to text if stdout is a terminal, otherwise return plain."""
    if not sys.stdout.isatty():
        return text
    colour = COLOURS.get(level_or_key, "")
    return f"{colour}{text}{COLOURS['RESET']}"


# ════════════════════════════════════════════════════════════════════════════
# CACHE — SQLite TTL cache
# ════════════════════════════════════════════════════════════════════════════

def _cache_connect() -> sqlite3.Connection:
    """
    Open (or create) the cache.db and ensure the schema exists.

    The table uses domain as the PRIMARY KEY so UPSERT (INSERT OR REPLACE)
    keeps exactly one row per domain — no unbounded growth across runs.
    """
    conn = sqlite3.connect(CACHE_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS harvester_cache (
            domain      TEXT PRIMARY KEY,
            fetched_at  TEXT NOT NULL,
            json_data   TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def cache_read(domain: str, ttl_hours: int) -> Optional[dict]:
    """
    Return the cached result for `domain` if it was fetched within `ttl_hours`.

    Returns None if:
      - No cache entry for this domain
      - Entry exists but is older than ttl_hours
    """
    conn = _cache_connect()
    try:
        row = conn.execute(
            "SELECT fetched_at, json_data FROM harvester_cache WHERE domain = ?",
            (domain,)
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None

    fetched_at_str, json_data = row
    try:
        fetched_at = datetime.fromisoformat(fetched_at_str)
        # Attach UTC if naive — should always be UTC from our writes, but be safe
        if fetched_at.tzinfo is None:
            fetched_at = fetched_at.replace(tzinfo=timezone.utc)
    except ValueError:
        return None

    age = datetime.now(timezone.utc) - fetched_at
    if age > timedelta(hours=ttl_hours):
        return None  # expired

    return json.loads(json_data)


def cache_write(domain: str, result: dict) -> None:
    """
    Write (or overwrite) a result dict to the cache.

    `fetched_at` is stored as an ISO 8601 UTC string so it survives
    process restarts without needing a real datetime column type.
    """
    fetched_at = datetime.now(timezone.utc).isoformat()
    conn = _cache_connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO harvester_cache (domain, fetched_at, json_data) "
            "VALUES (?, ?, ?)",
            (domain, fetched_at, json.dumps(result))
        )
        conn.commit()
    finally:
        conn.close()


# ════════════════════════════════════════════════════════════════════════════
# STEP 1 — Load raw theHarvester JSON output
# ════════════════════════════════════════════════════════════════════════════

def load_input(file_path: str) -> dict:
    """
    Read and JSON-parse the theHarvester output file.

    theHarvester -f flag writes <name>.json. Keys present vary by version
    and which sources were queried — we use .get() everywhere downstream.

    Aborts with a clear error message if:
      - The file does not exist
      - The file is not valid JSON
    """
    path = Path(file_path)
    if not path.exists():
        print(f"[!] Input file not found: {file_path}")
        sys.exit(1)

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as e:
        print(f"[!] Could not read input file: {e}")
        sys.exit(1)

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as e:
        print(f"[!] Input file is not valid JSON: {e}")
        print(f"    File: {file_path}")
        sys.exit(1)


# ════════════════════════════════════════════════════════════════════════════
# STEP 2 — Normalise raw data into canonical output schema
# ════════════════════════════════════════════════════════════════════════════

def normalize(raw: dict, domain: str, sources_str: Optional[str]) -> dict:
    """
    Normalise theHarvester's raw JSON into the canonical harvester-importer schema.

    Rules applied:
      emails  — filter to only strings containing "@", sort, deduplicate
      hosts   — items in raw["hosts"] that look like pure IPv4 addresses
                (match r'^[\\d.]+$') are silently moved to the ips set
      ips     — union of raw["ips"] and the IP-looking items from raw["hosts"],
                sorted and deduplicated
      sources — parsed from the --sources flag string, or empty list

    All keys in raw are read with .get() so missing keys are handled gracefully
    regardless of theHarvester version.
    """
    # ── Emails ────────────────────────────────────────────────────────────────
    raw_emails = raw.get("emails") or []
    emails = sorted({
        e.strip()
        for e in raw_emails
        if isinstance(e, str) and "@" in e
    })

    # ── Hosts + IPs (split by content type) ──────────────────────────────────
    ip_pattern = re.compile(r'^[\d.]+$')

    hosts_set: set = set()
    ips_set:   set = set()

    # Items under "hosts" may be hostnames OR bare IP strings depending on source
    for item in (raw.get("hosts") or []):
        item = item.strip()
        if not item:
            continue
        if ip_pattern.match(item):
            ips_set.add(item)
        else:
            hosts_set.add(item)

    # Items explicitly under "ips" are always IPs
    for item in (raw.get("ips") or []):
        item = item.strip()
        if item:
            ips_set.add(item)

    hosts = sorted(hosts_set)
    ips   = sorted(ips_set)

    # ── Sources ───────────────────────────────────────────────────────────────
    if sources_str:
        sources = [s.strip() for s in sources_str.split(",") if s.strip()]
    else:
        sources = []

    # ── Timestamp ─────────────────────────────────────────────────────────────
    queried_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "domain":       domain,
        "queried_at":   queried_at,
        "email_count":  len(emails),
        "host_count":   len(hosts),
        "ip_count":     len(ips),
        "source_count": len(sources),
        "emails":       emails,
        "hosts":        hosts,
        "ips":          ips,
        "sources":      sources,
    }


# ════════════════════════════════════════════════════════════════════════════
# STEP 3 — Terminal Printer
# ════════════════════════════════════════════════════════════════════════════

def print_result(result: dict) -> None:
    """
    Print a human-readable colour summary to stdout.

    Layout:
      Header     — domain + key counts
      Emails     — up to 10 shown, rest dimmed
      Hosts      — up to 15 shown, rest dimmed
      IPs        — all (usually small list)
      Sources    — comma-joined or "(not specified)"
      Next steps — dynamically suggested follow-on commands
    """
    domain        = result.get("domain", "")
    email_count   = result.get("email_count", 0)
    host_count    = result.get("host_count", 0)
    ip_count      = result.get("ip_count", 0)
    source_count  = result.get("source_count", 0)
    emails        = result.get("emails", [])
    hosts         = result.get("hosts", [])
    ips           = result.get("ips", [])
    sources       = result.get("sources", [])

    sep = "═" * 65

    # ── Header ────────────────────────────────────────────────────────────────
    print(f"\n{c('BOLD', sep)}")
    print(f"  {c('BOLD', 'HARVESTER INTEL')}  →  {c('BOLD', domain)}")
    print(sep)

    # ── Counts ────────────────────────────────────────────────────────────────
    print(
        f"\n  Emails: {c('HIGH', str(email_count))}   "
        f"Hosts: {c('MEDIUM', str(host_count))}   "
        f"IPs: {c('LOW', str(ip_count))}   "
        f"Sources: {c('INFO', str(source_count))}"
    )

    # ── Emails ────────────────────────────────────────────────────────────────
    print(f"\n  {c('BOLD', 'Emails')}  ({email_count})")
    if emails:
        shown_emails = emails[:10]
        for email in shown_emails:
            print(f"    {c('HIGH', email)}")
        remainder = len(emails) - len(shown_emails)
        if remainder > 0:
            print(f"    {c('DIM', f'... {remainder} more')}")
    else:
        print(f"    {c('DIM', '(none found)')}")

    # ── Hosts ─────────────────────────────────────────────────────────────────
    print(f"\n  {c('BOLD', 'Hosts')}  ({host_count})")
    if hosts:
        shown_hosts = hosts[:15]
        for host in shown_hosts:
            print(f"    {c('MEDIUM', host)}")
        remainder = len(hosts) - len(shown_hosts)
        if remainder > 0:
            print(f"    {c('DIM', f'... {remainder} more')}")
    else:
        print(f"    {c('DIM', '(none found)')}")

    # ── IPs ───────────────────────────────────────────────────────────────────
    print(f"\n  {c('BOLD', 'IPs')}  ({ip_count})")
    if ips:
        for ip in ips:
            print(f"    {c('LOW', ip)}")
    else:
        print(f"    {c('DIM', '(none found)')}")

    # ── Sources ───────────────────────────────────────────────────────────────
    print(f"\n  {c('BOLD', 'Sources')}")
    if sources:
        print(f"    {c('INFO', ', '.join(sources))}")
    else:
        print(f"    {c('DIM', '(not specified)')}")

    # ── Suggested next steps ──────────────────────────────────────────────────
    print(f"\n  {c('BOLD', 'Suggested Next Steps')}")

    if emails:
        print(f"    {c('DIM', f'theHarvester -d {domain} -b google,bing -f followup  # expand sources')}")

    if hosts:
        print(f"    {c('DIM', f'subfinder -d {domain}                                  # passive sub enum')}")
        print(f"    {c('DIM', 'cat hosts.txt | httprobe                               # check which are alive')}")

    print(
        f"    {c('DIM', f'python3 harvester-importer.py -d {domain} -f results.json --submit'
                        '  # add to Intel Board')}"
    )

    print()


# ════════════════════════════════════════════════════════════════════════════
# STEP 4 — Config helpers
# ════════════════════════════════════════════════════════════════════════════

def load_config() -> Optional[dict]:
    """Load stored config from CONFIG_PATH. Returns None if missing or invalid."""
    if not CONFIG_PATH.exists():
        return None
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_config(cfg: dict) -> None:
    """Write config dict to CONFIG_PATH, creating parent dirs if needed."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def setup_wizard() -> dict:
    """
    First-time interactive setup. Asks for GitHub PAT, display name, location.
    Saves to CONFIG_PATH. Returns the config dict.
    """
    print("\n[setup] harvester-importer first-time configuration")
    print("        Your GitHub PAT needs Issues: write scope.")
    print("        Create one at: https://github.com/settings/tokens\n")

    token        = input("  GitHub PAT       : ").strip()
    display_name = input("  Display name     : ").strip()
    display_loc  = input("  Location (city)  : ").strip()

    cfg = {
        "github_token": token,
        "display_name": display_name,
        "display_loc":  display_loc,
    }
    save_config(cfg)
    print(f"[setup] Config saved to {CONFIG_PATH}\n")
    return cfg


# ════════════════════════════════════════════════════════════════════════════
# STEP 5 — Submission
# ════════════════════════════════════════════════════════════════════════════

def submit_result(result: dict, config: dict) -> None:
    """
    POST a GitHub Issue to the harvester-importer repo.

    Issue title: "[submission] {domain}"
    Issue body:  JSON blob with domain intel + submitter identity.

    The GitHub Actions workflow reads issues with this title prefix and
    rebuilds intel-board.html sorted by email_count desc.

    Uses stdlib urllib.request only — no external dependencies.
    """
    domain = result.get("domain", "")
    token  = config.get("github_token", "")

    if not token:
        print("[!] No GitHub token in config — run with --reconfigure to set one.")
        return

    body_data = {
        "domain":       result["domain"],
        "display_name": config.get("display_name", ""),
        "display_loc":  config.get("display_loc", ""),
        "queried_at":   result.get("queried_at", ""),
        "email_count":  result.get("email_count", 0),
        "host_count":   result.get("host_count", 0),
        "ip_count":     result.get("ip_count", 0),
        "source_count": result.get("source_count", 0),
        "emails":       result.get("emails", []),
        "hosts":        result.get("hosts", []),
        "ips":          result.get("ips", []),
        "sources":      result.get("sources", []),
    }

    issue = {
        "title": f"[submission] {domain}",
        "body":  json.dumps(body_data),
    }

    req = urllib.request.Request(
        GITHUB_ISSUES_URL,
        data=json.dumps(issue).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
            "Accept":        "application/vnd.github+json",
            "User-Agent":    f"harvester-importer/{__version__}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp_data = json.loads(resp.read())
            issue_url = resp_data.get("html_url", "")
            print(f"[+] Submitted → {issue_url}")
            print("    Your domain will appear on the Intel Board once GitHub Actions processes it (~2 min).")
    except Exception as e:
        print(f"[!] Submission failed: {e}")


# ════════════════════════════════════════════════════════════════════════════
# STEP 6 — Orchestrator
# ════════════════════════════════════════════════════════════════════════════

def run(
    domain:      str,
    file_path:   str,
    sources_str: Optional[str],
    output_path: Optional[str],
    no_cache:    bool,
    ttl_hours:   int,
) -> dict:
    """
    Full import pipeline for one domain:
      [cache check] → load_input → normalize → print_result → cache_write [→ --output]

    Cache behaviour:
      - If no_cache is False and a valid cache entry exists: return cached result
      - Otherwise: run full pipeline, write to cache

    Returns the normalised result dict on success, or {} on failure.
    """
    print(f"[*] Importing harvester data for: {domain}")

    # ── Cache check ────────────────────────────────────────────────────────
    if not no_cache:
        cached = cache_read(domain, ttl_hours)
        if cached is not None:
            print(f"[*] Cache hit (TTL={ttl_hours}h) — using cached result")
            print_result(cached)
            if output_path:
                Path(output_path).write_text(
                    json.dumps(cached, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
                print(f"[*] JSON written → {output_path}")
            return cached

    # ── Load + normalise ───────────────────────────────────────────────────
    raw    = load_input(file_path)
    result = normalize(raw, domain, sources_str)

    # ── Print ──────────────────────────────────────────────────────────────
    print_result(result)

    # ── Cache write ────────────────────────────────────────────────────────
    cache_write(domain, result)
    print(f"[*] Cached → {CACHE_DB}")

    # ── Optional JSON output ───────────────────────────────────────────────
    if output_path:
        Path(output_path).write_text(
            json.dumps(result, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"[*] JSON written → {output_path}")

    return result


# ════════════════════════════════════════════════════════════════════════════
# STEP 7 — CLI Entry Point
# ════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="harvester-importer — normalize and explore theHarvester OSINT output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 harvester-importer.py -d nmap.org -f results.json
  python3 harvester-importer.py -d nmap.org -f results.json -o normalized.json
  python3 harvester-importer.py -d nmap.org -f results.json --sources "certspotter,crtsh,hackertarget"
  python3 harvester-importer.py -d nmap.org -f results.json --submit
  python3 harvester-importer.py -d nmap.org -f results.json --no-cache
  python3 harvester-importer.py -d nmap.org -f results.json --ttl 6
  python3 harvester-importer.py --reconfigure

Note: -d/--domain and -f/--file are not required when using --reconfigure.
        """,
    )

    parser.add_argument(
        "-d", "--domain", metavar="DOMAIN", default=None,
        help="Target domain (e.g. nmap.org — no https://, no trailing slash)"
    )
    parser.add_argument(
        "-f", "--file", metavar="FILE", default=None,
        help="Path to theHarvester JSON output file"
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE", default=None,
        help="Write normalised JSON result to this file path (optional)"
    )
    parser.add_argument(
        "--sources", metavar="LIST", default=None,
        help='Comma-separated source list used when running theHarvester (e.g. "crtsh,baidu")'
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="Bypass cache read — always import fresh (result is still written to cache)"
    )
    parser.add_argument(
        "--ttl", type=int, default=24, metavar="HOURS",
        help="Cache TTL in hours (default: 24)"
    )
    parser.add_argument(
        "--submit", action="store_true",
        help="Submit result to the Intel Board after import (opt-in; requires GitHub token on first use)"
    )
    parser.add_argument(
        "--reconfigure", action="store_true",
        help="Re-run setup wizard to update stored GitHub token / display name"
    )

    args = parser.parse_args()

    # ── --reconfigure ─────────────────────────────────────────────────────
    if args.reconfigure:
        setup_wizard()
        return

    # ── Validate required flags ───────────────────────────────────────────
    if not args.domain or not args.file:
        print("[!] Both -d/--domain and -f/--file are required.")
        print("    Run with --reconfigure to set up credentials, or -h for help.")
        sys.exit(1)

    # ── Load config if submitting ─────────────────────────────────────────
    config = None
    if args.submit:
        config = load_config()
        if config is None:
            config = setup_wizard()

    # ── Run import pipeline ───────────────────────────────────────────────
    result = run(
        domain      = args.domain.strip().lower(),
        file_path   = args.file,
        sources_str = args.sources,
        output_path = args.output,
        no_cache    = args.no_cache,
        ttl_hours   = args.ttl,
    )

    # ── Optional submission ───────────────────────────────────────────────
    if args.submit and result and config:
        print(f"\n  Domain    : {result.get('domain')}")
        print(f"  Emails    : {result.get('email_count')}   "
              f"Hosts: {result.get('host_count')}   "
              f"IPs: {result.get('ip_count')}")
        print(f"  Listed as : {config.get('display_name')} — {config.get('display_loc')}")
        print("\n  This result will be publicly listed on the Intel Board.")
        confirm = input("  Submit? [y/N] : ").strip().lower()
        if confirm == "y":
            submit_result(result, config)
        else:
            print("[*] Submission cancelled.")


if __name__ == "__main__":
    main()
