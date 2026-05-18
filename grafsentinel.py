#!/usr/bin/env python3
# =============================================================================
# grafsentinel - single-file security scanner for Grafana
# =============================================================================
#
# grafsentinel fingerprints the running Grafana version, flags every known CVE
# that affects it, runs active probes for remotely verifiable issues, and audits
# the deployment for misconfigurations. The entire scanner is this one file,
# with no dependencies beyond the Python standard library.
#
# Usage:
#     python3 grafsentinel.py -u https://grafana.example.com
#     python3 grafsentinel.py -u https://grafana.example.com -o report
#     python3 grafsentinel.py -f targets.txt --threads 10 --no-verify
#     python3 grafsentinel.py -u https://grafana.example.com --auth-user USER --auth-pass PW
#
#     Run  python3 grafsentinel.py --help  for the full list of options.
#
# Authorized use only - scan only Grafana instances you own or are explicitly
# authorized to assess. Unauthorized scanning may be illegal.
#
# Author:  devklid (evkl1d)
# Project: https://github.com/evkl1d/grafsentinel
# License: MIT - Copyright (c) 2026 devklid
# =============================================================================
import argparse
import base64
import csv
import html
import io
import json
import logging
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

__version__ = "0.1.0"

log = logging.getLogger("grafsentinel")

CONFIRMED = "confirmed"
EVIDENCED = "evidenced"
POTENTIAL = "potential"
CONFIDENCE_RANK = {CONFIRMED: 3, EVIDENCED: 2, POTENTIAL: 1}
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

CVE_DB = [
    {"id": "CVE-2018-15727", "title": "Authentication bypass via forgeable remember-me cookie", "severity": "critical", "cvss": 9.8, "component": "grafana", "affected": [("2.0.0", "4.6.4"), ("5.0.0", "5.2.3")]},
    {"id": "CVE-2020-11110", "title": "Stored XSS via the originalUrl field in dashboard snapshots", "severity": "medium", "cvss": 5.4, "component": "grafana", "affected": [("0.0.0", "6.7.2")]},
    {"id": "CVE-2021-27358", "title": "Denial of service via the unauthenticated snapshot API", "severity": "high", "cvss": 7.5, "component": "grafana", "affected": [("6.7.3", "7.4.2")]},
    {"id": "CVE-2021-39226", "title": "Snapshot authentication bypass exposing dashboard snapshots", "severity": "high", "cvss": 7.3, "component": "grafana", "affected": [("0.0.0", "7.5.11"), ("8.0.0", "8.1.6")]},
    {"id": "CVE-2021-41174", "title": "Stored XSS via AngularJS template injection on login pages", "severity": "medium", "cvss": 6.1, "component": "grafana", "affected": [("8.0.0", "8.2.3")]},
    {"id": "CVE-2021-43798", "title": "Directory traversal and arbitrary file read via plugin path", "severity": "high", "cvss": 7.5, "component": "grafana", "affected": [("8.0.0", "8.0.7"), ("8.1.0", "8.1.8"), ("8.2.0", "8.2.7"), ("8.3.0", "8.3.1")]},
    {"id": "CVE-2022-23498", "title": "Datasource query caching leaks the grafana_session cookie", "severity": "high", "cvss": 7.1, "component": "grafana", "affected": [("8.3.0", "9.2.10"), ("9.3.0", "9.3.4")]},
    {"id": "CVE-2022-23552", "title": "Stored XSS in the GeoMap panel via unsanitized SVG files", "severity": "high", "cvss": 7.3, "component": "grafana", "affected": [("8.1.0", "8.5.16"), ("9.0.0", "9.2.10"), ("9.3.0", "9.3.4")]},
    {"id": "CVE-2022-24812", "title": "API key permission caching enables privilege escalation", "severity": "high", "cvss": 8.8, "component": "grafana", "affected": [("8.1.0", "8.4.6")]},
    {"id": "CVE-2022-31097", "title": "Stored XSS via the Unified Alerting feature", "severity": "high", "cvss": 8.7, "component": "grafana", "affected": [("8.0.0", "8.3.10"), ("8.4.0", "8.4.10"), ("8.5.0", "8.5.9"), ("9.0.0", "9.0.3")]},
    {"id": "CVE-2022-31107", "title": "OAuth login account takeover via username matching", "severity": "high", "cvss": 7.5, "component": "grafana", "affected": [("5.3.0", "8.3.10"), ("8.4.0", "8.4.10"), ("8.5.0", "8.5.9"), ("9.0.0", "9.0.3")]},
    {"id": "CVE-2022-31176", "title": "Unauthorized file disclosure in the Grafana Image Renderer plugin", "severity": "high", "cvss": 7.6, "component": "grafana-image-renderer", "affected": [("0.0.0", "3.6.1")]},
    {"id": "CVE-2022-36062", "title": "Privilege escalation via permission loss on RBAC migration", "severity": "low", "cvss": 3.8, "component": "grafana", "affected": [("0.0.0", "8.5.13"), ("9.0.0", "9.0.9"), ("9.1.0", "9.1.6")]},
    {"id": "CVE-2022-39306", "title": "Improper validation in invitations enabling unauthorized org access", "severity": "medium", "cvss": 6.4, "component": "grafana", "affected": [("8.0.0", "8.5.15"), ("9.0.0", "9.2.4")]},
    {"id": "CVE-2022-39307", "title": "Username and email enumeration via the password-reset endpoint", "severity": "medium", "cvss": 5.3, "component": "grafana", "affected": [("8.0.0", "8.5.15"), ("9.0.0", "9.2.4")]},
    {"id": "CVE-2022-39328", "title": "Race condition in auth middleware exposing admin endpoints", "severity": "critical", "cvss": 9.8, "component": "grafana", "affected": [("9.2.0", "9.2.4")]},
    {"id": "CVE-2023-0507", "title": "Stored XSS in the GeoMap panel via map attribution", "severity": "medium", "cvss": 5.4, "component": "grafana", "affected": [("8.1.0", "8.5.21"), ("9.2.0", "9.2.13"), ("9.3.0", "9.3.8")]},
    {"id": "CVE-2023-0594", "title": "Stored XSS in the trace view via span attributes", "severity": "medium", "cvss": 5.4, "component": "grafana", "affected": [("7.0.0", "8.5.21"), ("9.2.0", "9.2.13"), ("9.3.0", "9.3.8")]},
    {"id": "CVE-2023-1410", "title": "Stored XSS in the Graphite function-description tooltip", "severity": "medium", "cvss": 4.8, "component": "grafana", "affected": [("8.0.0", "8.5.22"), ("9.2.0", "9.2.15"), ("9.3.0", "9.3.11")]},
    {"id": "CVE-2023-2183", "title": "Broken access control lets Viewers send Alertmanager test alerts", "severity": "high", "cvss": 7.5, "component": "grafana", "affected": [("8.0.0", "8.5.26"), ("9.0.0", "9.2.19"), ("9.3.0", "9.3.15"), ("9.4.0", "9.4.12"), ("9.5.0", "9.5.3")]},
    {"id": "CVE-2023-2801", "title": "Race condition in the data source proxy", "severity": "high", "cvss": 7.5, "component": "grafana", "affected": [("9.4.0", "9.4.12"), ("9.5.0", "9.5.3")]},
    {"id": "CVE-2023-3010", "title": "DOM-based XSS in the WorldMap panel plugin", "severity": "high", "cvss": 7.3, "component": "grafana-worldmap-panel", "affected": [("0.0.0", "1.0.4")]},
    {"id": "CVE-2023-3128", "title": "Authentication bypass via Azure AD OAuth account spoofing", "severity": "critical", "cvss": 9.4, "component": "grafana", "affected": [("6.7.0", "8.5.27"), ("9.2.0", "9.2.20"), ("9.3.0", "9.3.16"), ("9.4.0", "9.4.13"), ("9.5.0", "9.5.4")]},
    {"id": "CVE-2023-4822", "title": "Cross-organization privilege escalation via permission management", "severity": "medium", "cvss": 6.7, "component": "grafana", "affected": [("8.0.0", "9.4.17"), ("9.5.0", "9.5.12"), ("10.0.0", "10.0.8"), ("10.1.0", "10.1.5")]},
    {"id": "CVE-2023-5123", "title": "Path traversal via improper sanitization in the JSON datasource plugin", "severity": "high", "cvss": 8.0, "component": "marcusolsson-json-datasource", "affected": [("0.0.0", "1.3.21")]},
    {"id": "CVE-2024-1313", "title": "Authorization bypass allowing cross-org snapshot deletion", "severity": "medium", "cvss": 6.5, "component": "grafana", "affected": [("9.5.0", "9.5.18"), ("10.0.0", "10.0.13"), ("10.1.0", "10.1.9"), ("10.2.0", "10.2.6"), ("10.3.0", "10.3.5")]},
    {"id": "CVE-2024-6322", "title": "Authorization bypass in plugin datasource routes", "severity": "high", "cvss": 8.2, "component": "grafana", "affected": [("11.1.0", "11.1.1"), ("11.1.2", "11.1.3")]},
    {"id": "CVE-2024-8118", "title": "Wrong permission enforced on the Alerting datasource rule API", "severity": "medium", "cvss": 5.1, "component": "grafana", "affected": [("8.5.0", "10.3.10"), ("10.4.0", "10.4.9"), ("11.0.0", "11.0.5"), ("11.1.0", "11.1.6"), ("11.2.0", "11.2.1")]},
    {"id": "CVE-2024-9264", "title": "Remote code execution via SQL Expressions", "severity": "critical", "cvss": 9.4, "component": "grafana", "affected": [("11.0.0", "11.0.5"), ("11.1.0", "11.1.6"), ("11.2.0", "11.2.1")]},
    {"id": "CVE-2025-3260", "title": "Authorization bypass in the dashboard API", "severity": "high", "cvss": 8.3, "component": "grafana", "affected": [("11.6.0", "11.6.1")]},
    {"id": "CVE-2025-4123", "title": "XSS via a malicious frontend plugin through client path traversal", "severity": "high", "cvss": 7.6, "component": "grafana", "affected": [("0.0.0", "10.4.18"), ("11.2.0", "11.2.9"), ("11.3.0", "11.3.6"), ("11.4.0", "11.4.4"), ("11.5.0", "11.5.4"), ("11.6.0", "11.6.1")]},
    {"id": "CVE-2025-6023", "title": "XSS via scripted dashboards through open redirect and path traversal", "severity": "high", "cvss": 7.6, "component": "grafana", "affected": [("11.5.0", "11.5.6"), ("11.6.0", "11.6.3"), ("12.0.0", "12.0.2")]},
    {"id": "CVE-2026-27876", "title": "Remote code execution via sqlExpressions arbitrary file write", "severity": "critical", "cvss": 9.1, "component": "grafana", "affected": [("11.6.0", "11.6.14"), ("12.0.0", "12.1.10"), ("12.2.0", "12.2.8"), ("12.3.0", "12.3.6"), ("12.4.0", "12.4.2")]},
]

_SUFFIX = re.compile(r"[-+].*$")
_DIGITS = re.compile(r"\d+")


def parse_version(value):
    if not value:
        return (0, 0, 0)
    cleaned = _SUFFIX.sub("", str(value).strip())
    parts = []
    for chunk in cleaned.split("."):
        match = _DIGITS.match(chunk)
        parts.append(int(match.group()) if match else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def compare_versions(left, right):
    a, b = parse_version(left), parse_version(right)
    return (a > b) - (a < b)


def in_range(value, introduced, fixed):
    if not value:
        return False
    if introduced and compare_versions(value, introduced) < 0:
        return False
    if fixed and compare_versions(value, fixed) >= 0:
        return False
    return True


def version_affected(value, ranges):
    for introduced, fixed in ranges:
        if in_range(value, introduced, fixed):
            return True
    return False


def cves_for(version, component="grafana"):
    matches = []
    for cve in CVE_DB:
        if cve.get("component", "grafana") != component:
            continue
        if version_affected(version, cve["affected"]):
            matches.append(cve)
    return matches


_USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
_MAX_RETRIES = 2
_RETRY_BACKOFF = 2.0
_TIMEOUT_ERRORS = (socket.timeout, TimeoutError)


class Response:
    def __init__(self, status_code, headers, text):
        self.status_code = status_code
        self.headers = headers
        self.text = text

    def json(self):
        return json.loads(self.text)


class HttpClient:
    def __init__(self, timeout=10, verify_ssl=True, auth_token=None,
                 auth_user=None, auth_pass=None, proxy=None):
        self.timeout = timeout
        self.rate_limited = False
        self.authenticated = bool(auth_token or (auth_user and auth_pass))
        self._headers = {"User-Agent": _USER_AGENT,
                         "Accept": "application/json, text/html, */*"}
        if auth_token:
            self._headers["Authorization"] = "Bearer " + auth_token
        self._auth = (auth_user, auth_pass) if (auth_user and auth_pass) else None
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        proxies = {"http": proxy, "https": proxy} if proxy else {}
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.ProxyHandler(proxies))

    def get(self, url, auth=None, headers=None, anonymous=False):
        if self.rate_limited:
            return None
        request_headers = dict(self._headers)
        if anonymous:
            request_headers.pop("Authorization", None)
        if headers:
            request_headers.update(headers)
        basic = None if anonymous else (auth or self._auth)
        if basic:
            token = base64.b64encode((basic[0] + ":" + basic[1]).encode()).decode()
            request_headers["Authorization"] = "Basic " + token
        request = urllib.request.Request(url, headers=request_headers, method="GET")
        for attempt in range(_MAX_RETRIES + 1):
            try:
                raw = self._opener.open(request, timeout=self.timeout)
                status = raw.status
            except urllib.error.HTTPError as exc:
                raw, status = exc, exc.code
            except urllib.error.URLError as exc:
                if isinstance(exc.reason, _TIMEOUT_ERRORS) and attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_BACKOFF)
                    continue
                return None
            except _TIMEOUT_ERRORS:
                if attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_BACKOFF)
                    continue
                return None
            except Exception:
                return None
            try:
                text = raw.read().decode("utf-8", "replace")
            except Exception:
                text = ""
            response = Response(status, raw.headers, text)
            if _is_rate_limited(response):
                self.rate_limited = True
                return None
            return response
        return None


def _is_rate_limited(response):
    if response.status_code == 429:
        return True
    if response.headers.get("X-RateLimit-Remaining") == "0":
        return True
    return False


@dataclass
class Finding:
    title: str
    severity: str
    confidence: str
    detail: str = ""
    cve_id: Optional[str] = None
    cvss: Optional[float] = None
    category: str = "cve"
    test_url: Optional[str] = None


@dataclass
class ScanResult:
    target: str
    reachable: bool = False
    version: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)

    def by_severity(self):
        return sorted(self.findings,
                      key=lambda item: SEVERITY_ORDER.get(item.severity, 0),
                      reverse=True)


@dataclass
class CheckContext:
    http: HttpClient
    target: str
    version: Optional[str] = None
    cve_index: dict = field(default_factory=dict)
    authenticated: bool = False


def cve_finding(ctx, cve_id, confidence, detail, test_url=None):
    cve = ctx.cve_index.get(cve_id, {})
    return Finding(title=cve.get("title", cve_id), severity=cve.get("severity", "medium"),
                   confidence=confidence, detail=detail, cve_id=cve_id,
                   cvss=cve.get("cvss"), test_url=test_url)


def config_finding(title, severity, detail, test_url=None):
    return Finding(title=title, severity=severity, confidence=CONFIRMED,
                   detail=detail, category="config", test_url=test_url)


_PASSWD_MARKERS = ("root:", ":x:", "daemon:", "/bin/", "nobody:")
_TRAVERSAL_PLUGINS = (
    "alertlist", "annolist", "barchart", "bargauge", "candlestick", "canvas",
    "cloudwatch", "dashlist", "elasticsearch", "gauge", "geomap", "graph",
    "graphite", "heatmap", "histogram", "influxdb", "jaeger", "logs", "loki",
    "mysql", "news", "nodeGraph", "opentsdb", "piechart", "pluginlist",
    "postgres", "prometheus", "stat", "state-timeline", "status-history",
    "table", "table-old", "tempo", "testdata", "text", "timeseries", "zipkin",
)
_TRAVERSAL_PATHS = (
    "../" * 12 + "etc/passwd",
    "../" * 6 + "etc/passwd",
    "..%2f" * 12 + "etc%2fpasswd",
    "%2e%2e%2f" * 12 + "etc%2fpasswd",
    "%2e%2e/" * 12 + "etc/passwd",
    "..%252f" * 12 + "etc%252fpasswd",
    "..%5c" * 12 + "etc%5cpasswd",
    "..%c0%af" * 12 + "etc%c0%afpasswd",
)


def probe_path_traversal(ctx):
    for plugin in _TRAVERSAL_PLUGINS:
        probe = ctx.http.get(ctx.target + "/public/plugins/" + plugin + "/plugin.json")
        if probe is None or probe.status_code != 200:
            continue
        for traversal in _TRAVERSAL_PATHS:
            url = ctx.target + "/public/plugins/" + plugin + "/" + traversal
            response = ctx.http.get(url)
            if response is None or response.status_code != 200:
                continue
            body = response.text
            markers = sum(1 for marker in _PASSWD_MARKERS if marker in body)
            if markers >= 3 and len(body) > 80:
                detail = "Read /etc/passwd via the '%s' plugin static path" % plugin
                return [cve_finding(ctx, "CVE-2021-43798", CONFIRMED, detail, url)]
        return []
    return []


_DEFAULT_CREDENTIALS = (
    ("admin", "admin"),
    ("admin", "prom-operator"),
    ("admin", "grafana"),
    ("admin", "password"),
)


def check_default_credentials(ctx):
    url = ctx.target + "/api/admin/settings"
    for user, password in _DEFAULT_CREDENTIALS:
        response = ctx.http.get(url, auth=(user, password))
        if response is None or response.status_code != 200:
            continue
        try:
            data = response.json()
        except ValueError:
            continue
        if isinstance(data, dict) and data:
            return [config_finding(
                "Default credentials are active", "critical",
                "The account %s:%s is valid and has server-admin access"
                % (user, password), url)]
    return []


def check_anonymous_access(ctx):
    url = ctx.target + "/api/org"
    response = ctx.http.get(url, anonymous=True)
    if response is None or response.status_code != 200:
        return []
    try:
        data = response.json()
    except ValueError:
        return []
    if isinstance(data, dict) and "name" in data:
        return [config_finding(
            "Anonymous access enabled", "medium",
            "The authenticated API endpoint /api/org is reachable without credentials", url)]
    return []


def check_snapshot_exposure(ctx):
    url = ctx.target + "/api/dashboard/snapshots"
    response = ctx.http.get(url, anonymous=True)
    if response is None or response.status_code != 200:
        return []
    try:
        snapshots = response.json()
    except ValueError:
        return []
    if isinstance(snapshots, list) and snapshots:
        return [config_finding(
            "Dashboard snapshots are publicly listable", "medium",
            str(len(snapshots)) + " dashboard snapshot(s) are listed without authentication", url)]
    return []


def check_exposed_metrics(ctx):
    url = ctx.target + "/metrics"
    response = ctx.http.get(url, anonymous=True)
    if response is None or response.status_code != 200:
        return []
    if "# HELP" in response.text or "# TYPE" in response.text:
        return [config_finding(
            "Prometheus metrics endpoint exposed", "low",
            "/metrics is publicly accessible and discloses runtime metrics", url)]
    return []


_SECURITY_HEADERS = ("Content-Security-Policy", "Strict-Transport-Security",
                     "X-Content-Type-Options", "X-Frame-Options")


def check_security_headers(ctx):
    response = ctx.http.get(ctx.target)
    if response is None:
        return []
    present = {name.lower() for name in response.headers}
    missing = [name for name in _SECURITY_HEADERS if name.lower() not in present]
    if not missing:
        return []
    return [config_finding(
        "Missing security headers", "low",
        "Response does not set: " + ", ".join(missing), ctx.target)]


def check_cors(ctx):
    probe_origin = "https://grafsentinel-probe.example"
    response = ctx.http.get(ctx.target, headers={"Origin": probe_origin})
    if response is None:
        return []
    allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
    if allow_origin == "*":
        detail, severity = "Access-Control-Allow-Origin is set to a wildcard", "medium"
    elif allow_origin == probe_origin:
        detail, severity = "Access-Control-Allow-Origin reflects an arbitrary Origin header", "medium"
    else:
        return []
    if (response.headers.get("Access-Control-Allow-Credentials", "") or "").lower() == "true":
        severity = "high"
        detail += " while allowing credentials"
    return [config_finding("CORS misconfiguration", severity, detail, ctx.target)]


_BAD_SIGNATURES = ("unsigned", "invalid", "modified")


def check_plugins(ctx):
    response = ctx.http.get(ctx.target + "/api/plugins")
    if response is None or response.status_code != 200:
        return []
    try:
        plugins = response.json()
    except ValueError:
        return []
    if not isinstance(plugins, list):
        return []
    findings = []
    for plugin in plugins:
        if not isinstance(plugin, dict):
            continue
        plugin_id = plugin.get("id")
        info = plugin.get("info")
        plugin_version = info.get("version") if isinstance(info, dict) else None
        signature = str(plugin.get("signature", "")).lower()
        if plugin_id and signature in _BAD_SIGNATURES:
            findings.append(config_finding(
                "Unsigned or tampered plugin", "medium",
                "Plugin '%s' has signature state '%s'" % (plugin_id, signature)))
        if not plugin_id or not plugin_version:
            continue
        for cve in CVE_DB:
            if cve.get("component") != plugin_id:
                continue
            if version_affected(plugin_version, cve["affected"]):
                findings.append(cve_finding(
                    ctx, cve["id"], POTENTIAL,
                    "plugin %s %s is within the affected range" % (plugin_id, plugin_version)))
    return findings


_RISKY_SETTINGS = (
    ("users", "allow_sign_up", "true", "medium", "Open user self-registration is enabled"),
    ("users", "viewers_can_edit", "true", "low", "Viewers are allowed to edit dashboards"),
    ("users", "editors_can_admin", "true", "low", "Editors are allowed to administer resources"),
    ("security", "cookie_secure", "false", "medium", "Session cookie is not marked Secure"),
    ("security", "disable_brute_force_login_protection", "true", "medium", "Brute-force login protection is disabled"),
    ("security", "allow_embedding", "true", "low", "Embedding in iframes is allowed (clickjacking risk)"),
    ("snapshots", "external_enabled", "true", "low", "Publishing snapshots to an external service is enabled"),
)

_OAUTH_SECTIONS = ("auth.generic_oauth", "auth.github", "auth.gitlab",
                   "auth.google", "auth.okta", "auth.grafana_com")


def _fetch_settings(ctx):
    response = ctx.http.get(ctx.target + "/api/admin/settings")
    if response is None or response.status_code != 200:
        return None
    try:
        settings = response.json()
    except ValueError:
        return None
    return settings if isinstance(settings, dict) else None


def _setting(settings, section, key):
    data = settings.get(section)
    return str(data.get(key, "")).lower() if isinstance(data, dict) else ""


def _section_enabled(settings, section):
    return _setting(settings, section, "enabled") == "true"


def _evidenced_cve(ctx, cve_id, evidence):
    cve = ctx.cve_index.get(cve_id)
    if not cve or not version_affected(ctx.version, cve["affected"]):
        return None
    return cve_finding(ctx, cve_id, EVIDENCED,
                       evidence + "; installed version is in the affected range")


def check_server_settings(ctx):
    if not ctx.authenticated:
        return []
    settings = _fetch_settings(ctx)
    if settings is None:
        return []
    findings = []
    for section, key, risky_value, severity, detail in _RISKY_SETTINGS:
        if _setting(settings, section, key) == risky_value:
            findings.append(config_finding(
                "Insecure server setting: " + section + "." + key, severity, detail))
    return findings


def check_auth_provider_cves(ctx):
    if not ctx.authenticated or not ctx.version:
        return []
    settings = _fetch_settings(ctx)
    if settings is None:
        return []
    azuread = _section_enabled(settings, "auth.azuread")
    ldap = _section_enabled(settings, "auth.ldap")
    oauth = azuread or any(_section_enabled(settings, name) for name in _OAUTH_SECTIONS)
    candidates = []
    if azuread:
        candidates.append(_evidenced_cve(ctx, "CVE-2023-3128", "Azure AD OAuth is configured"))
    if oauth:
        candidates.append(_evidenced_cve(ctx, "CVE-2022-31107", "an OAuth login provider is configured"))
    if ldap or oauth:
        candidates.append(_evidenced_cve(ctx, "CVE-2018-15727", "LDAP or OAuth authentication is configured"))
    return [finding for finding in candidates if finding is not None]


def check_sql_expression_cves(ctx):
    if not ctx.authenticated or not ctx.version:
        return []
    settings = _fetch_settings(ctx)
    if settings is None:
        return []
    toggles = settings.get("feature_toggles")
    enabled = False
    if isinstance(toggles, dict):
        for key, value in toggles.items():
            if "sqlexpressions" in (str(key) + " " + str(value)).lower():
                enabled = True
    if not enabled:
        return []
    candidates = [_evidenced_cve(ctx, cve_id, "the sqlExpressions feature toggle is enabled")
                  for cve_id in ("CVE-2024-9264", "CVE-2026-27876")]
    return [finding for finding in candidates if finding is not None]


CHECKS = (
    probe_path_traversal,
    check_default_credentials,
    check_anonymous_access,
    check_snapshot_exposure,
    check_exposed_metrics,
    check_security_headers,
    check_cors,
    check_plugins,
    check_server_settings,
    check_auth_provider_cves,
    check_sql_expression_cves,
)

VERSION_ENDPOINTS = ("/api/health", "/api/frontend/settings", "/login", "/",
                     "/grafana/api/health", "/grafana/login")
_VERSION_HEADERS = ("X-Grafana-Version", "X-Grafana-Build-Version")
_SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_HTML_PATTERNS = (
    re.compile(r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"'),
    re.compile(r'"buildVersion"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"'),
    re.compile(r"grafana[_-]?version['\"\s:=]+([0-9]+\.[0-9]+\.[0-9]+)", re.I),
    re.compile(r"gitVersion['\"\s:=]+([0-9]+\.[0-9]+\.[0-9]+)", re.I),
    re.compile(r"Grafana v([0-9]+\.[0-9]+\.[0-9]+)"),
)


def normalize_url(target):
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")


def _version_from_json(payload):
    if not isinstance(payload, dict):
        return None
    build = payload.get("buildInfo")
    if isinstance(build, dict) and build.get("version"):
        return str(build["version"])
    if payload.get("version"):
        return str(payload["version"])
    return None


def extract_version(response):
    for header in _VERSION_HEADERS:
        match = _SEMVER.match(response.headers.get(header, "") or "")
        if match:
            return match.group(0)
    if "json" in (response.headers.get("Content-Type", "") or "").lower():
        try:
            found = _version_from_json(response.json())
        except ValueError:
            found = None
        if found:
            return found
    for pattern in _HTML_PATTERNS:
        match = pattern.search(response.text)
        if match:
            return match.group(1)
    return None


def scan(http, target):
    target = normalize_url(target)
    result = ScanResult(target=target)
    log.info("scanning %s", target)
    connect = http.get(target)
    if connect is None:
        log.warning("target unreachable: %s", target)
        return result
    result.reachable = True
    log.info("target reachable (HTTP %s)", connect.status_code)
    result.version = _detect_version(http, target)
    if result.version:
        for cve in cves_for(result.version):
            result.findings.append(Finding(
                title=cve["title"], severity=cve["severity"], confidence=POTENTIAL,
                detail="version " + result.version + " is within the affected range",
                cve_id=cve["id"], cvss=cve.get("cvss")))
    ctx = CheckContext(http=http, target=target, version=result.version,
                       cve_index={cve["id"]: cve for cve in CVE_DB},
                       authenticated=http.authenticated)
    for check in CHECKS:
        try:
            result.findings.extend(check(ctx))
        except Exception as exc:
            log.warning("check %s failed: %s", check.__name__, exc)
    _dedupe(result)
    log.info("%d findings on %s", len(result.findings), target)
    return result


def _detect_version(http, target):
    for endpoint in VERSION_ENDPOINTS:
        response = http.get(target + endpoint)
        if response is None or response.status_code != 200:
            continue
        found = extract_version(response)
        if found:
            log.info("version detected: %s (via %s)", found, endpoint)
            return found
    log.warning("Grafana version could not be detected")
    return None


def _dedupe(result):
    best = {}
    for finding in result.findings:
        if not finding.cve_id:
            continue
        rank = CONFIDENCE_RANK.get(finding.confidence, 0)
        current = best.get(finding.cve_id)
        if current is None or rank > CONFIDENCE_RANK.get(current.confidence, 0):
            best[finding.cve_id] = finding
    result.findings = [finding for finding in result.findings
                       if not finding.cve_id or best[finding.cve_id] is finding]


_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_COLORS = {"critical": "\033[1;91m", "high": "\033[91m", "medium": "\033[93m",
           "low": "\033[94m", "info": "\033[90m"}
_SEVERITY_RANK = ("critical", "high", "medium", "low", "info")
_CONFIDENCE_COLORS = {CONFIRMED: "\033[92m", EVIDENCED: "\033[93m", POTENTIAL: "\033[2m"}
_CONFIDENCE_RANK_ORDER = (CONFIRMED, EVIDENCED, POTENTIAL)


def _wrap(text, code, enabled):
    return code + text + _RESET if (enabled and code) else text


def render_console(results, use_color=True):
    enabled = use_color and sys.stdout.isatty()
    lines = []
    for result in results:
        lines.append("")
        lines.append(_wrap("target  " + result.target, _BOLD, enabled))
        if not result.reachable:
            lines.append("  unreachable")
            continue
        lines.append("  version  " + (result.version or "unknown"))
        lines.append("")
        if not result.findings:
            lines.append("  no findings")
            continue
        for finding in result.by_severity():
            label = ("[" + finding.severity.upper() + "]").ljust(10)
            confidence = finding.confidence.ljust(9)
            ident = finding.cve_id or finding.category
            lines.append("  " + _wrap(label, _COLORS.get(finding.severity, ""), enabled)
                          + " " + _wrap(confidence,
                                        _CONFIDENCE_COLORS.get(finding.confidence, ""), enabled)
                          + " " + ident + "  " + finding.title)
            if finding.detail:
                lines.append("    " + _wrap(finding.detail, _DIM, enabled))
            if finding.test_url:
                lines.append("    " + _wrap(finding.test_url, _DIM, enabled))
        counts = {}
        conf_counts = {}
        for finding in result.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
            conf_counts[finding.confidence] = conf_counts.get(finding.confidence, 0) + 1
        parts = ["%d %s" % (counts[name], name) for name in _SEVERITY_RANK if counts.get(name)]
        conf_parts = ["%d %s" % (conf_counts[name], name)
                      for name in _CONFIDENCE_RANK_ORDER if conf_counts.get(name)]
        lines.append("")
        lines.append("  %d findings  (%s)" % (len(result.findings), ", ".join(parts)))
        if conf_parts:
            lines.append("  confidence   " + ", ".join(conf_parts))
    output = "\n".join(lines).strip("\n")
    print(output)
    return output


def render_json(results):
    return json.dumps(
        {"tool": "grafsentinel", "version": __version__,
         "results": [asdict(result) for result in results]}, indent=2)


def render_csv(results):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["target", "version", "severity", "confidence", "category",
                     "cve_id", "cvss", "title", "detail", "test_url"])
    for result in results:
        for finding in result.findings:
            writer.writerow([result.target, result.version or "", finding.severity,
                             finding.confidence, finding.category, finding.cve_id or "",
                             "" if finding.cvss is None else finding.cvss, finding.title,
                             finding.detail, finding.test_url or ""])
    return buffer.getvalue()


_HTML_STYLE = (
    "body{font-family:-apple-system,Segoe UI,sans-serif;background:#0d1117;"
    "color:#c9d1d9;margin:0;padding:24px;}h1{font-size:20px;margin:0 0 4px;}"
    "h2{font-size:15px;margin:0 0 8px;}.target{background:#161b22;border:1px solid "
    "#30363d;border-radius:8px;padding:16px;margin:16px 0;}.meta{color:#8b949e;"
    "font-size:13px;margin-bottom:12px;}table{width:100%;border-collapse:collapse;}"
    "th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #30363d;"
    "font-size:13px;vertical-align:top;}th{color:#8b949e;text-transform:uppercase;"
    "font-size:11px;}.sev{font-weight:700;border-radius:4px;padding:2px 8px;"
    "font-size:11px;}.critical{background:#da3633;color:#fff;}.high{background:"
    "#f85149;color:#fff;}.medium{background:#d29922;color:#000;}.low{background:"
    "#388bfd;color:#fff;}.info{background:#6e7681;color:#fff;}code{color:#79c0ff;}"
)


def render_html(results):
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
            "<title>grafsentinel report</title><style>", _HTML_STYLE,
            "</style></head><body><h1>grafsentinel report</h1>",
            '<div class="meta">generated ', html.escape(generated), "</div>"]
    for result in results:
        body.append('<div class="target"><h2>')
        body.append(html.escape(result.target))
        body.append("</h2>")
        if not result.reachable:
            body.append('<div class="meta">unreachable</div></div>')
            continue
        body.append('<div class="meta">version: ' + html.escape(result.version or "unknown")
                    + " &middot; " + str(len(result.findings)) + " findings</div>")
        if result.findings:
            body.append("<table><tr><th>Severity</th><th>ID</th><th>Confidence</th>"
                        "<th>Title</th><th>Detail</th></tr>")
            for finding in result.by_severity():
                severity = html.escape(finding.severity)
                body.append('<tr><td><span class="sev ' + severity + '">'
                            + severity.upper() + "</span></td><td><code>"
                            + html.escape(finding.cve_id or finding.category)
                            + "</code></td><td>" + html.escape(finding.confidence)
                            + "</td><td>" + html.escape(finding.title) + "</td><td>"
                            + html.escape(finding.detail) + "</td></tr>")
            body.append("</table>")
        else:
            body.append('<div class="meta">no findings</div>')
        body.append("</div>")
    body.append("</body></html>")
    return "".join(body)


def write_reports(results, base_path):
    written = []
    for extension, renderer in (("json", render_json), ("html", render_html),
                                ("csv", render_csv)):
        path = base_path + "." + extension
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(renderer(results))
        written.append(path)
    return written


def banner(use_color=True):
    enabled = use_color and sys.stdout.isatty()
    line = "grafsentinel " + __version__ + "  -  Grafana security scanner"
    print(_wrap(line + "\n" + "=" * len(line), _BOLD, enabled))


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="grafsentinel", description="Security scanner for Grafana instances")
    parser.add_argument("-u", "--url", help="target Grafana URL")
    parser.add_argument("-f", "--file", help="file with target URLs, one per line")
    parser.add_argument("-o", "--output", help="base path for json/html/csv reports")
    parser.add_argument("--min-severity",
                        choices=("critical", "high", "medium", "low", "info"),
                        default="info",
                        help="only report findings at or above this severity")
    parser.add_argument("-t", "--timeout", type=float, default=10.0,
                        help="HTTP timeout in seconds")
    parser.add_argument("--threads", type=int, default=1,
                        help="number of targets to scan in parallel (default: 1)")
    parser.add_argument("--no-verify", action="store_true",
                        help="disable TLS certificate verification")
    parser.add_argument("--proxy", help="route requests through an HTTP/HTTPS proxy")
    parser.add_argument("--auth-token", help="bearer token for authenticated scanning")
    parser.add_argument("--auth-user", help="basic-auth username")
    parser.add_argument("--auth-pass", help="basic-auth password")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    parser.add_argument("--version", action="version", version="grafsentinel " + __version__)
    return parser


def _load_targets(args):
    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    return targets


def main(argv=None):
    args = _build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(message)s")
    try:
        targets = _load_targets(args)
    except OSError as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    if not targets:
        print("error: provide -u URL or -f FILE", file=sys.stderr)
        return 2
    banner(use_color=not args.no_color)

    def scan_one(target):
        http = HttpClient(timeout=args.timeout, verify_ssl=not args.no_verify,
                          auth_token=args.auth_token, auth_user=args.auth_user,
                          auth_pass=args.auth_pass, proxy=args.proxy)
        return scan(http, target)

    if args.threads > 1 and len(targets) > 1:
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            results = list(pool.map(scan_one, targets))
    else:
        results = [scan_one(target) for target in targets]

    min_rank = SEVERITY_ORDER.get(args.min_severity, 0)
    if min_rank:
        for result in results:
            result.findings = [finding for finding in result.findings
                               if SEVERITY_ORDER.get(finding.severity, 0) >= min_rank]

    render_console(results, use_color=not args.no_color)
    if args.output:
        for path in write_reports(results, args.output):
            print("report written: " + path)
    if not any(result.reachable for result in results):
        return 2
    return 1 if sum(len(result.findings) for result in results) else 0


if __name__ == "__main__":
    sys.exit(main())
