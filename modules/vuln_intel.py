#!/usr/bin/env python3
"""
Vulnerability intelligence (reference-only).

Sources:
  - Offline curated seed: data/vuln_intel_seed.json
  - Optional online NVD API 2.0 keyword lookup (cached)
  - Exploit-DB / NVD deep-links (no payloads downloaded)

This module never returns exploit code. It only returns CVE metadata and URLs
for authorized research / reporting.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import APP_DIR

SEED_PATH = APP_DIR / "data" / "vuln_intel_seed.json"
CACHE_PATH = APP_DIR / "data" / "vuln_intel_cache.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "WPS-Toolkit-VulnIntel/1.0 (+authorized-security-research)"

_SEED_CACHE = None
_HTTP_CACHE = None


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_seed():
    global _SEED_CACHE
    if _SEED_CACHE is not None:
        return _SEED_CACHE
    payload = {"database_version": "unavailable", "entries": []}
    try:
        with open(SEED_PATH, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError, TypeError):
        pass
    _SEED_CACHE = payload
    return payload


def _load_http_cache():
    global _HTTP_CACHE
    if _HTTP_CACHE is not None:
        return _HTTP_CACHE
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as handle:
            _HTTP_CACHE = json.load(handle)
    except (OSError, ValueError, TypeError):
        _HTTP_CACHE = {"queries": {}}
    if "queries" not in _HTTP_CACHE:
        _HTTP_CACHE = {"queries": {}}
    return _HTTP_CACHE


def _save_http_cache():
    cache = _load_http_cache()
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CACHE_PATH, "w", encoding="utf-8") as handle:
        json.dump(cache, handle, indent=2, ensure_ascii=False)


def exploitdb_search_url(query):
    return "https://www.exploit-db.com/search?q={q}".format(
        q=urllib.parse.quote(str(query or ""))
    )


def nvd_detail_url(cve_id):
    return "https://nvd.nist.gov/vuln/detail/{cve}".format(cve=cve_id)


def nvd_search_url(query):
    return "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={q}&search_type=all".format(
        q=urllib.parse.quote(str(query or ""))
    )


def get_seed_info():
    seed = _load_seed()
    return {
        "version": seed.get("database_version", "unavailable"),
        "entries": len(seed.get("entries") or []),
        "path": str(SEED_PATH),
        "exists": SEED_PATH.exists(),
    }


def lookup_offline(vendor=None, model=None, title=None, limit=20):
    """
    Match curated seed entries against vendor/model/title tokens.
    Returns a structured report of candidate CVEs + reference URLs.
    """
    seed = _load_seed()
    hay = " ".join(
        [
            str(vendor or ""),
            str(model or ""),
            str(title or ""),
        ]
    ).upper()

    matches = []
    for entry in seed.get("entries") or []:
        patterns = entry.get("product_patterns") or []
        vendor_name = str(entry.get("vendor") or "")
        hit_patterns = []
        for pattern in patterns:
            if str(pattern).upper() in hay:
                hit_patterns.append(pattern)
        vendor_hit = vendor_name and vendor_name.upper() in hay and vendor_name.lower() != "generic"
        # generic WPS entry matches when WPS mentioned or always low priority
        if entry.get("vendor") == "generic":
            if "WPS" in hay or not hay.strip():
                vendor_hit = True
                hit_patterns = hit_patterns or ["WPS"]
        if not hit_patterns and not vendor_hit:
            continue

        score = 20
        if hit_patterns:
            score += 40 + min(30, 10 * len(hit_patterns))
        if vendor_hit:
            score += 15
        score = min(100, score)

        cves = []
        for cve in entry.get("cves") or []:
            cve_id = cve.get("cve_id") or ""
            refs = list(cve.get("refs") or [])
            # Ensure standard links exist
            if cve_id and nvd_detail_url(cve_id) not in refs:
                refs.insert(0, nvd_detail_url(cve_id))
            cves.append({
                "cve_id": cve_id,
                "summary": cve.get("summary") or "",
                "severity": cve.get("severity") or "UNKNOWN",
                "refs": refs,
                "source": "offline_seed",
            })

        matches.append({
            "vendor": vendor_name,
            "matched_patterns": hit_patterns,
            "score": score,
            "notes": list(entry.get("notes") or []),
            "tags": list(entry.get("tags") or []),
            "cves": cves[: max(1, int(limit))],
            "search_links": {
                "nvd": nvd_search_url(
                    " ".join([vendor_name] + hit_patterns[:2]).strip() or vendor_name
                ),
                "exploit_db": exploitdb_search_url(
                    " ".join([vendor_name] + hit_patterns[:2]).strip() or vendor_name
                ),
            },
        })

    matches.sort(key=lambda m: m.get("score", 0), reverse=True)
    return {
        "mode": "offline",
        "query": {"vendor": vendor, "model": model, "title": title},
        "seed_version": seed.get("database_version"),
        "match_count": len(matches),
        "matches": matches[: max(1, int(limit))],
        "disclaimer": seed.get("disclaimer")
        or "Reference only — no exploit payloads. Verify firmware applicability.",
        "generated_at": _now_iso(),
    }


def _http_get_json(url, timeout=12):
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read(2_000_000)
        return json.loads(raw.decode("utf-8", errors="replace")), None
    except urllib.error.HTTPError as exc:
        return None, "HTTP {code}".format(code=exc.code)
    except Exception as exc:
        return None, str(exc)


def lookup_nvd_online(keyword, results_per_page=5, use_cache=True, cache_ttl_hours=24):
    """
    Optional NVD keyword search. Cached under data/vuln_intel_cache.json.

    Respects public rate limits by caching aggressively. Returns reference
    metadata only.
    """
    keyword = (keyword or "").strip()
    if not keyword:
        return {
            "mode": "nvd_online",
            "ok": False,
            "error": "empty_keyword",
            "cves": [],
        }

    cache = _load_http_cache()
    key = keyword.lower()
    if use_cache and key in cache.get("queries", {}):
        item = cache["queries"][key]
        age = time.time() - float(item.get("ts", 0))
        if age < cache_ttl_hours * 3600:
            return {
                "mode": "nvd_online",
                "ok": True,
                "cached": True,
                "keyword": keyword,
                "cves": item.get("cves") or [],
                "fetched_at": item.get("fetched_at"),
            }

    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": max(1, min(20, int(results_per_page))),
    })
    url = "{base}?{params}".format(base=NVD_API, params=params)
    data, error = _http_get_json(url, timeout=15)
    if error or not data:
        return {
            "mode": "nvd_online",
            "ok": False,
            "error": error or "empty_response",
            "keyword": keyword,
            "cves": [],
            "fallback_links": {
                "nvd": nvd_search_url(keyword),
                "exploit_db": exploitdb_search_url(keyword),
            },
        }

    cves = []
    for item in data.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cve_id = cve.get("id") or ""
        descriptions = cve.get("descriptions") or []
        summary = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                summary = desc.get("value") or ""
                break
        if not summary and descriptions:
            summary = descriptions[0].get("value") or ""

        severity = "UNKNOWN"
        score = None
        metrics = cve.get("metrics") or {}
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            rows = metrics.get(metric_key) or []
            if not rows:
                continue
            cvss_data = (rows[0] or {}).get("cvssData") or {}
            severity = cvss_data.get("baseSeverity") or severity
            score = cvss_data.get("baseScore")
            break

        refs = [nvd_detail_url(cve_id)] if cve_id else []
        refs.append(exploitdb_search_url(cve_id or keyword))
        cves.append({
            "cve_id": cve_id,
            "summary": summary[:400],
            "severity": severity,
            "score": score,
            "refs": refs,
            "source": "nvd_api",
        })

    payload = {
        "ts": time.time(),
        "fetched_at": _now_iso(),
        "cves": cves,
    }
    cache.setdefault("queries", {})[key] = payload
    try:
        _save_http_cache()
    except OSError:
        pass

    return {
        "mode": "nvd_online",
        "ok": True,
        "cached": False,
        "keyword": keyword,
        "cves": cves,
        "fetched_at": payload["fetched_at"],
        "totalResults": data.get("totalResults"),
    }


def enrich_device(vendor=None, model=None, title=None, online=False, limit=12):
    """
    Combine offline seed matches with optional NVD online keyword results.
    """
    offline = lookup_offline(vendor=vendor, model=model, title=title, limit=limit)
    keyword_parts = [p for p in [vendor, model, title] if p]
    keyword = " ".join(str(p) for p in keyword_parts).strip()
    # Prefer model-ish keyword for NVD
    if model:
        keyword = "{vendor} {model}".format(
            vendor=vendor or "", model=model
        ).strip()
    elif title and re.search(r"[A-Za-z]*\d", str(title)):
        keyword = "{vendor} {title}".format(
            vendor=vendor or "", title=title
        ).strip()

    online_result = None
    if online and keyword:
        online_result = lookup_nvd_online(keyword, results_per_page=min(8, limit))

    # Flatten unique CVEs for report convenience
    seen = set()
    flat = []
    for match in offline.get("matches") or []:
        for cve in match.get("cves") or []:
            cid = cve.get("cve_id")
            if not cid or cid in seen:
                continue
            seen.add(cid)
            row = dict(cve)
            row["matched_vendor"] = match.get("vendor")
            row["matched_patterns"] = match.get("matched_patterns")
            flat.append(row)
    if online_result and online_result.get("ok"):
        for cve in online_result.get("cves") or []:
            cid = cve.get("cve_id")
            if not cid or cid in seen:
                continue
            seen.add(cid)
            flat.append(cve)

    return {
        "query": {"vendor": vendor, "model": model, "title": title, "online": online},
        "offline": offline,
        "online": online_result,
        "cves": flat[: max(1, int(limit))],
        "search_links": {
            "nvd": nvd_search_url(keyword or (vendor or "router")),
            "exploit_db": exploitdb_search_url(keyword or (vendor or "router")),
        },
        "disclaimer": (
            "Intelligence links only. No exploit payloads are fetched or executed. "
            "Verify firmware/version before drawing conclusions. Authorized use only."
        ),
        "generated_at": _now_iso(),
    }
