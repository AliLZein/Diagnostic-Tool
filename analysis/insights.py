"""
analysis/insights.py

Adds four features on top of the raw findings table:
1. Plain-English "verdict" summaries (root-cause style conclusions)
2. Historical trend data (findings-per-time-bucket, for charting)
3. GeoIP/ISP lookup for external IPs (free, no API key, cached)
4. A tunable alert threshold, persisted to a small JSON settings file

This module deliberately does NOT do any network calls (GeoIP lookups)
on the hot logging path (every single retransmission). GeoIP is only
looked up when building a verdict, and results are cached in memory,
so it can't slow down or rate-limit the fast background loop.
"""

import ipaddress
import json
import os
import urllib.request
from datetime import datetime, timedelta

from storage.db import get_all_findings

# Set by desktop_app.py at startup to an absolute path (e.g. data/settings.json)
SETTINGS_FILE = None

_geoip_cache = {}
DEFAULT_THRESHOLD = 5


# ---------------------------------------------------------------------
# GeoIP / ISP lookup (free, no API key: ip-api.com, 45 req/min limit)
# ---------------------------------------------------------------------
def is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
    except ValueError:
        return False


def geoip_lookup(ip):
    """Returns {'country': ..., 'isp': ...} or None. Cached in memory."""
    if ip in _geoip_cache:
        return _geoip_cache[ip]

    if not is_public_ip(ip):
        _geoip_cache[ip] = None
        return None

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,isp,org"
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            result = {"country": data.get("country", "Unknown"), "isp": data.get("isp") or data.get("org") or "Unknown"}
        else:
            result = None
    except Exception:
        result = None

    _geoip_cache[ip] = result
    return result


# ---------------------------------------------------------------------
# Tunable alert threshold, persisted to disk
# ---------------------------------------------------------------------
def load_threshold():
    if SETTINGS_FILE and os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE) as f:
                return json.load(f).get("retransmission_threshold", DEFAULT_THRESHOLD)
        except Exception:
            return DEFAULT_THRESHOLD
    return DEFAULT_THRESHOLD


def save_threshold(value):
    if not SETTINGS_FILE:
        return
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump({"retransmission_threshold": int(value)}, f)


# ---------------------------------------------------------------------
# Historical trend data (for the Chart.js line chart)
# ---------------------------------------------------------------------
def get_trend_data(hours=6, bucket_minutes=10):
    since = datetime.utcnow() - timedelta(hours=hours)
    findings = [f for f in get_all_findings() if f.timestamp >= since]

    buckets = {}
    for f in findings:
        bucket_time = f.timestamp.replace(second=0, microsecond=0)
        bucket_time = bucket_time - timedelta(minutes=bucket_time.minute % bucket_minutes)
        key = bucket_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        buckets[key] = buckets.get(key, 0) + 1

    sorted_keys = sorted(buckets.keys())
    return {"labels": sorted_keys, "counts": [buckets[k] for k in sorted_keys]}


# ---------------------------------------------------------------------
# Root-cause verdict — the plain-English summary
# ---------------------------------------------------------------------
def get_verdict(window_minutes=5):
    since = datetime.utcnow() - timedelta(minutes=window_minutes)
    findings = [f for f in get_all_findings() if f.timestamp >= since]

    if not findings:
        return f"No findings in the last {window_minutes} minutes — system looks stable."

    threshold = load_threshold()

    retrans_by_source = {}
    security_flags = []
    for f in findings:
        if "retransmission" in f.message.lower():
            retrans_by_source[f.source] = retrans_by_source.get(f.source, 0) + 1
        if f.category == "security":
            security_flags.append(f)

    verdicts = []

    for source, count in retrans_by_source.items():
        if count >= threshold:
            geo = geoip_lookup(source)
            geo_str = f" ({geo['country']}, {geo['isp']})" if geo else ""
            verdicts.append(
                f"{count} TCP retransmissions from {source}{geo_str} in the last {window_minutes} min "
                f"— possible unstable connection or congestion (threshold: {threshold})"
            )

    if security_flags:
        latest = security_flags[-1]
        verdicts.append(f"Security flag: {latest.message} (source: {latest.source})")

    if not verdicts:
        return f"{len(findings)} findings in the last {window_minutes} minutes, none above the alert threshold ({threshold})."

    return "Verdict: " + " | ".join(verdicts)