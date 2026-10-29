"""Restricted dashboard bridge for the local Go ``ipatools`` binary."""
from __future__ import annotations

import json
import os
import re
import subprocess
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOWNLOAD_DIR = (ROOT / "mobile_downloads").resolve()
BUNDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{2,254}$")


def binary_path() -> Path:
    configured = os.environ.get("RECONGUARD_IPATOOLS", "").strip()
    if configured:
        candidate = Path(configured).expanduser().resolve()
    else:
        candidate = (ROOT / "bin" / ("ipatools.exe" if os.name == "nt" else "ipatools")).resolve()
    if not candidate.is_file():
        raise FileNotFoundError("ipatools binary is not built; run the build steps in ipatools/README.md")
    return candidate


def _run(args: list[str], timeout: int) -> dict:
    binary = binary_path()
    completed = subprocess.run(
        [str(binary), *args],
        cwd=str(ROOT),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        shell=False,
    )
    output = completed.stdout.strip()
    try:
        payload = json.loads(output) if output else {}
    except json.JSONDecodeError:
        payload = {"ok": False, "error": "ipatools returned invalid JSON"}
    if completed.returncode != 0 and not payload.get("error"):
        payload["error"] = (completed.stderr or "ipatools command failed")[-2000:]
    payload["return_code"] = completed.returncode
    return payload


def status() -> dict:
    try:
        return _run(["status"], timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "command": "status", "error": str(exc)}


def download(*, app_id: str = "", bundle_id: str = "", make_zip: bool = True,
             authorized: bool = False, analyze: bool = True) -> dict:
    if not authorized:
        raise ValueError("Explicit authorization confirmation is required")
    app_id = str(app_id or "").strip()
    bundle_id = str(bundle_id or "").strip()
    if bool(app_id) == bool(bundle_id):
        raise ValueError("Provide exactly one App Store app ID or bundle identifier")
    if app_id and (not app_id.isdigit() or not 5 <= len(app_id) <= 20):
        raise ValueError("App Store app ID must be numeric")
    if bundle_id and not BUNDLE_RE.fullmatch(bundle_id):
        raise ValueError("Invalid bundle identifier")

    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    label = app_id or bundle_id
    safe_label = re.sub(r"[^A-Za-z0-9.-]", "_", label)[:120]
    output = (DOWNLOAD_DIR / f"{safe_label}-{uuid.uuid4().hex[:8]}.ipa").resolve()
    if DOWNLOAD_DIR not in output.parents:
        raise ValueError("Invalid output path")

    args = ["download", "--output", str(output), "--authorized"]
    args.extend(["--app-id", app_id] if app_id else ["--bundle-id", bundle_id])
    if make_zip:
        args.append("--zip")
    result = _run(args, timeout=46 * 60)
    if result.get("ok"):
        result["artifact"] = output.name
        result["artifact_url"] = f"/api/mobile/artifacts/{output.name}"
        if result.get("zip_output"):
            zip_name = Path(result["zip_output"]).name
            result["zip_artifact"] = zip_name
            result["zip_artifact_url"] = f"/api/mobile/artifacts/{zip_name}"
        if analyze:
            from redteam_6tools import ipa_recon
            result["static_analysis"] = ipa_recon.run(str(output))
    return result


def resolve_artifact(name: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.(?:ipa|zip)", name or "", re.IGNORECASE):
        raise ValueError("Invalid artifact name")
    path = (DOWNLOAD_DIR / name).resolve()
    if DOWNLOAD_DIR not in path.parents or not path.is_file():
        raise FileNotFoundError("Artifact not found")
    return path
