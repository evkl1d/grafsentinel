# Changelog

## 0.1.0 — 2026-05-18

Initial release.

- Single-file scanner — one Python script, no dependencies beyond the Python
  standard library.
- Version-based detection of 33 Grafana CVEs (2018–2026), each with precise
  affected-version ranges.
- Active probes: plugin path traversal (CVE-2021-43798) and default
  credentials.
- Configuration audit: anonymous access, exposed metrics, listable snapshots,
  missing security headers, CORS misconfiguration, and unsigned plugins.
- Authenticated mode — audits the live server settings and ties CVEs to the
  auth providers and features that are enabled.
- Confidence levels on every finding: confirmed, evidenced, and potential.
- Parallel multi-target scanning, HTTP proxy support, and severity filtering.
- Console, JSON, HTML, and CSV reports.
