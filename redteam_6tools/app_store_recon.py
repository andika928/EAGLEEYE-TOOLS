#!/usr/bin/env python3
"""Passive Apple App Store metadata reconnaissance.

This module never downloads an IPA and never contacts an app backend. It
accepts only canonical HTTPS apps.apple.com application URLs, extracts the
numeric Apple track ID, and queries Apple's public lookup endpoint.
"""
from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone


APPLE_HOSTS = {"apps.apple.com"}
APP_ID_RE = re.compile(r"/id(?P<app_id>[0-9]{5,20})(?:[/?#]|$)")
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def parse_app_store_url(value: str) -> tuple[str, str]:
    """Return ``(app_id, country)`` or raise ValueError for unsafe input."""
    parsed = urllib.parse.urlsplit((value or "").strip())
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in APPLE_HOSTS:
        raise ValueError("Use a canonical HTTPS apps.apple.com application URL")
    if parsed.username or parsed.password or parsed.port:
        raise ValueError("Credentials and custom ports are not allowed")
    match = APP_ID_RE.search(parsed.path)
    if not match:
        raise ValueError("App Store URL does not contain a numeric application ID")
    first_path = next((part for part in parsed.path.split("/") if part), "us").lower()
    country = first_path if re.fullmatch(r"[a-z]{2}", first_path) else "us"
    return match.group("app_id"), country


def _age_days(iso_value: str | None) -> int | None:
    if not iso_value:
        return None
    try:
        released = datetime.fromisoformat(iso_value.replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - released.astimezone(timezone.utc)).days)
    except (ValueError, TypeError):
        return None


def analyze_record(source_url: str, record: dict) -> dict:
    """Normalize public metadata and attach an explicit coverage matrix."""
    version_age = _age_days(record.get("currentVersionReleaseDate"))
    return {
        "tool": "app_store_recon",
        "mode": "passive_metadata_only",
        "target": source_url,
        "app_id": str(record.get("trackId") or ""),
        "name": record.get("trackName"),
        "developer": record.get("artistName") or record.get("sellerName"),
        "bundle_id": record.get("bundleId"),
        "version": record.get("version"),
        "release_date": record.get("currentVersionReleaseDate"),
        "version_age_days": version_age,
        "minimum_os": record.get("minimumOsVersion"),
        "file_size_bytes": int(record.get("fileSizeBytes") or 0),
        "content_rating": record.get("contentAdvisoryRating"),
        "genres": record.get("genres") or [],
        "languages": record.get("languageCodesISO2A") or [],
        "features": record.get("features") or [],
        "supported_devices_count": len(record.get("supportedDevices") or []),
        "seller_url": record.get("sellerUrl"),
        "store_url": record.get("trackViewUrl") or source_url,
        "artwork_url": record.get("artworkUrl100"),
        "release_notes": record.get("releaseNotes"),
        "observations": [
            {
                "status": "observed",
                "title": "Public store identity and release metadata",
                "detail": "Collected from Apple's public lookup service; this is not a vulnerability finding.",
            }
        ],
        "coverage": [
            {"area": "Store identity and current version", "status": "observed", "requires": "App Store URL"},
            {"area": "Info.plist, URL schemes and ATS", "status": "not_tested", "requires": "Authorized IPA"},
            {"area": "Entitlements and code signing", "status": "not_tested", "requires": "Authorized IPA"},
            {"area": "Embedded endpoints and secret candidates", "status": "not_tested", "requires": "Authorized IPA"},
            {"area": "Runtime traffic, TLS pinning and authentication", "status": "not_tested", "requires": "Authorized test account and instrumented build/device"},
            {"area": "Local storage, Keychain and jailbreak defenses", "status": "not_tested", "requires": "Authorized installed build and test device"},
        ],
        "limitations": [
            "No IPA was downloaded or inspected.",
            "No requests were sent to the application's backend.",
            "No vulnerability or absence-of-vulnerability conclusion can be made from store metadata.",
        ],
    }


def run(source_url: str, opener=None) -> dict:
    app_id, country = parse_app_store_url(source_url)
    lookup_url = "https://itunes.apple.com/lookup?" + urllib.parse.urlencode({
        "id": app_id,
        "country": country,
        "entity": "software",
    })
    request = urllib.request.Request(
        lookup_url,
        headers={"Accept": "application/json", "User-Agent": "ReconGuard-Mobile/1.0"},
    )
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(request, timeout=10) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except Exception as exc:
        return {"tool": "app_store_recon", "target": source_url, "error": f"Apple metadata lookup failed: {exc}"}
    if len(raw) > MAX_RESPONSE_BYTES:
        return {"tool": "app_store_recon", "target": source_url, "error": "Apple metadata response exceeded the safety limit"}
    try:
        payload = json.loads(raw.decode("utf-8"))
        records = payload.get("results") or []
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as exc:
        return {"tool": "app_store_recon", "target": source_url, "error": f"Invalid Apple metadata response: {exc}"}
    if not records:
        return {"tool": "app_store_recon", "target": source_url, "error": f"No App Store record found for ID {app_id}"}
    return analyze_record(source_url, records[0])
