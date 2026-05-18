<p align="center">
  <img src="logo.svg" alt="grafsentinel" width="440">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="license MIT">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="python 3.9+">
  <img src="https://img.shields.io/badge/dependencies-none-2ea043" alt="zero dependencies">
  <img src="https://img.shields.io/badge/CVEs-33-ff8a3d" alt="33 CVEs">
</p>

# grafsentinel

A single-file security scanner for Grafana instances. grafsentinel fingerprints
the running Grafana version, flags every known CVE that affects it, runs active
probes for remotely verifiable issues, and audits the deployment for
misconfigurations.

The whole scanner is one self-contained Python script with **no dependencies
beyond the standard library** — clone it and run it on any host with
Python 3.9+.

## ⚠️ Authorized use only

Use grafsentinel only against Grafana instances you own or are explicitly
authorized to assess. Unauthorized scanning may be illegal.

## Features

- **Version-aware CVE detection** — 33 Grafana CVEs (2018–2026) in a curated
  database with precise affected-version ranges.
- **Active checks** — verifies real issues directly: plugin path traversal,
  default credentials, publicly listable snapshots, exposed metrics, missing
  security headers, CORS misconfiguration, unsigned plugins.
- **Authenticated mode** — with credentials, audits the live server
  configuration and ties CVEs to the auth providers and features actually
  enabled.
- **Confidence levels** — every finding is `confirmed` (verified directly),
  `evidenced` (preconditions verified against the live config), or `potential`
  (matched by version).
- **Parallel scanning** — scan many targets concurrently with `--threads`.
- **Proxy support** — route traffic through Burp, ZAP, or any HTTP proxy.
- **Reports** — console, JSON, HTML, and CSV.
- **Zero dependencies** — one file, standard library only.

## Installation

    git clone https://github.com/evkl1d/grafsentinel.git
    cd grafsentinel
    python3 grafsentinel.py --help

No build step and no `pip install` — the script runs as-is on Python 3.9+.

## Usage

    python3 grafsentinel.py -u https://grafana.example.com
    python3 grafsentinel.py -u https://grafana.example.com -o report
    python3 grafsentinel.py -f targets.txt --threads 10 --no-verify
    python3 grafsentinel.py -u https://grafana.example.com --proxy http://127.0.0.1:8080
    python3 grafsentinel.py -u https://grafana.example.com --min-severity high

Run `python3 grafsentinel.py --help` for the full list of options.

## Example output

    grafsentinel 0.1.0  -  Grafana security scanner
    ===============================================

    target  https://grafana.example.com
      version  8.3.0

      [CRITICAL] potential CVE-2023-3128  Authentication bypass via Azure AD OAuth account spoofing
        version 8.3.0 is within the affected range
      [CRITICAL] confirmed config  Default credentials are active
        The account admin:admin is valid and has server-admin access
      [HIGH]     confirmed CVE-2021-43798  Directory traversal and arbitrary file read via plugin path
        Read /etc/passwd via the 'alertlist' plugin static path
      [MEDIUM]   confirmed config  Anonymous access enabled
        The authenticated API endpoint /api/org is reachable without credentials

      20 findings  (2 critical, 8 high, 7 medium, 3 low)
      confidence   5 confirmed, 15 potential

## Authenticated scanning

Given credentials, grafsentinel performs extra verification against the live
server configuration — confirming insecure settings and tying CVEs to the auth
providers and features that are actually enabled.

    python3 grafsentinel.py -u https://grafana.example.com --auth-token glsa_xxx
    python3 grafsentinel.py -u https://grafana.example.com --auth-user admin --auth-pass <password>

## Docker

    docker build -t grafsentinel:latest .
    docker run --rm grafsentinel:latest -u https://grafana.example.com

Or use the bundled `docker-compose.yml`:

    docker compose run --rm grafsentinel -u https://grafana.example.com

## How it works

1. Connectivity check.
2. Version fingerprinting from multiple endpoints and response headers.
3. Version-based CVE matching against the bundled database.
4. Active probes and configuration checks — plus authenticated checks when
   credentials are supplied.
5. Report generation — console output plus optional JSON, HTML, and CSV files.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 devklid.
