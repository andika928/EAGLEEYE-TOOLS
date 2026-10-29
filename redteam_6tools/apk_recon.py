#!/usr/bin/env python3
"""Tool 10 - Android APK static recon (authorized targets only).

Parses the binary AndroidManifest.xml (AXML) to extract, reliably and without
external tools:
  - package / versionCode / versionName / minSdk / targetSdk
  - declared permissions
  - exported components (activity/service/receiver/provider)
  - deep links (intent-filter scheme://host/path)
  - application flags (allowBackup / debuggable / networkSecurityConfig)

It also extracts embedded URLs and hardcoded-secret candidates from the dex
bytecode. Run only on apps you own or are authorized to test.
"""
import argparse
import re
import struct
import sys
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Binary Android XML (AXML) parsing
# ---------------------------------------------------------------------------
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

URL_RE = re.compile(rb'https?://[^\s"\'<>\\]{5,}')
SECRET_RE = re.compile(
    rb'(?i)\b(api[_-]?key|secret|client[_-]?secret|token|password|access[_-]?key)\b'
    rb'[^A-Za-z0-9]{0,3}[A-Za-z0-9_\-./+=]{8,}'
)


def _strings(blob, min_len=4):
    """Extract printable ASCII runs from raw bytes (fallback recon)."""
    out = []
    cur = bytearray()
    for b in blob:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(bytes(cur))
    return out


def _parse_string_pool(data, off):
    """Parse a RES_STRING_POOL_TYPE chunk. Returns (pool, next_offset)."""
    ctype, _hsize, csize = struct.unpack_from("<HHI", data, off)
    if ctype != RES_STRING_POOL_TYPE:
        raise ValueError("string pool expected")
    count, _style_count, flags = struct.unpack_from("<III", data, off + 8)
    sstart, _stylestart = struct.unpack_from("<II", data, off + 20)
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from("<" + "I" * count, data, off + 28) if count else ()
    base = off + sstart
    pool = []
    for i in range(count):
        p = base + offsets[i]
        if utf8:
            b0 = data[p]
            if b0 & 0x80:
                length = ((b0 & 0x7F) << 8) | data[p + 1]
                p += 2
            else:
                length = b0
                p += 1
            s = data[p:p + length].decode("utf-8", errors="replace")
        else:
            length = struct.unpack_from("<H", data, p)[0]
            p += 2
            s = data[p:p + length * 2].decode("utf-16-le", errors="replace")
        pool.append(s)
    return pool, off + csize


def _parse_axml(data):
    """Return (string_pool, events) or None if not a binary XML."""
    if len(data) < 8:
        return None
    ctype, hsize, csize = struct.unpack_from("<HHI", data, 0)
    if ctype != RES_XML_TYPE:
        return None

    pool = None
    events = []
    off = hsize
    end = min(csize, len(data))
    while off + 8 <= end:
        t, _hs, cs = struct.unpack_from("<HHI", data, off)
        if cs < 8:
            break
        if t == RES_STRING_POOL_TYPE:
            pool, _ = _parse_string_pool(data, off)
        elif t == RES_XML_START_ELEMENT_TYPE:
            if pool is None:
                break
            _line, _comment, _ns, name_idx = struct.unpack_from("<IIII", data, off + 8)
            attr_start, attr_size, attr_count, _id_idx, _cls_idx, _sty_idx = \
                struct.unpack_from("<HHHHHH", data, off + 24)
            ename = pool[name_idx] if name_idx != 0xFFFFFFFF else ""
            attrs = {}
            a = off + attr_start
            for _ in range(attr_count):
                ans, aname, araw = struct.unpack_from("<III", data, a)
                _tsize, _tres0, ttype = struct.unpack_from("<HBB", data, a + 12)
                tdata = struct.unpack_from("<I", data, a + 16)[0]
                aname_s = pool[aname] if aname != 0xFFFFFFFF and aname < len(pool) else ""
                val = None
                if ttype == TYPE_STRING and tdata < len(pool):
                    val = pool[tdata]
                elif ttype == TYPE_INT_BOOLEAN:
                    val = (tdata != 0)
                elif ttype in (TYPE_INT_DEC, TYPE_INT_HEX):
                    val = tdata
                elif araw != 0xFFFFFFFF and araw < len(pool):
                    val = pool[araw]
                attrs[aname_s] = val
                a += attr_size
            events.append(("start", ename, attrs))
        elif t == RES_XML_END_ELEMENT_TYPE:
            _line, _comment, _ns, name_idx = struct.unpack_from("<IIII", data, off + 8)
            ename = pool[name_idx] if pool and name_idx != 0xFFFFFFFF and name_idx < len(pool) else ""
            events.append(("end", ename))
        off += cs
    return pool, events


def _extract_manifest(events):
    """Walk events and return (manifest, permissions, components, app_attrs)."""
    manifest = {}
    permissions = []
    components = []
    app_attrs = {}
    comp = None
    cur_filter = None

    for kind, name, *rest in events:
        if kind == "start":
            attrs = rest[0]
            if name == "manifest":
                manifest = attrs
            elif name == "uses-permission":
                if attrs.get("name"):
                    permissions.append(attrs["name"])
            elif name in ("activity", "activity-alias", "service", "receiver", "provider"):
                comp = {
                    "type": name,
                    "name": attrs.get("name"),
                    "exported": attrs.get("exported"),
                    "permission": attrs.get("permission"),
                    "intent_filters": [],
                }
                components.append(comp)
                cur_filter = None
            elif name == "intent-filter":
                if comp is not None:
                    cur_filter = {"actions": [], "categories": [], "data": []}
                    comp["intent_filters"].append(cur_filter)
            elif name == "action":
                if cur_filter is not None and attrs.get("name"):
                    cur_filter["actions"].append(attrs["name"])
            elif name == "category":
                if cur_filter is not None and attrs.get("name"):
                    cur_filter["categories"].append(attrs["name"])
            elif name == "data":
                if cur_filter is not None:
                    cur_filter["data"].append({
                        "scheme": attrs.get("scheme"),
                        "host": attrs.get("host"),
                        "path": attrs.get("path"),
                        "pathPrefix": attrs.get("pathPrefix"),
                        "pathPattern": attrs.get("pathPattern"),
                    })
            elif name == "application":
                app_attrs = attrs
        elif kind == "end":
            if name == "intent-filter":
                cur_filter = None
            elif name in ("activity", "activity-alias", "service", "receiver", "provider"):
                comp = None

    return manifest, permissions, components, app_attrs


def run(apk_path, max_urls=200, max_secrets=100):
    apk = Path(apk_path)
    if not apk.is_file():
        return {"tool": "apk_recon", "target": str(apk),
                "error": f"file not found: {apk_path}"}

    try:
        z = zipfile.ZipFile(apk)
    except (zipfile.BadZipFile, OSError) as exc:
        return {"tool": "apk_recon", "target": str(apk),
                "error": f"not a valid APK (zip): {exc}"}

    with z:
        names = z.namelist()
        manifest_blob = z.read("AndroidManifest.xml") if "AndroidManifest.xml" in names else b""
        dex_blob = bytearray()
        dex_count = 0
        for n in names:
            if n.startswith("classes") and n.endswith(".dex"):
                dex_count += 1
                dex_blob += z.read(n)

    # 1) authoritative manifest parsing
    manifest_info = {}
    permissions = []
    components = []
    app_attrs = {}
    axml_error = None
    events = _parse_axml(manifest_blob)
    if events is not None:
        manifest_info, permissions, components, app_attrs = _extract_manifest(events[1])
    else:
        axml_error = "binary AndroidManifest.xml not parsed (AXML header not found)"
        # fallback: string scan for permissions
        perms = set()
        for s in _strings(manifest_blob):
            for m in re.finditer(rb'android\.permission\.[A-Za-z_]+', s):
                perms.add(m.group().decode())
        permissions = sorted(perms)

    # exported components + deep links
    exported_components = []
    deep_links = set()
    for c in components:
        has_if = len(c["intent_filters"]) > 0
        explicit = c["exported"]
        is_exported = explicit if explicit is not None else has_if
        if is_exported:
            exported_components.append({
                "type": c["type"],
                "name": c["name"],
                "explicit": explicit is not None,
            })
        for f in c["intent_filters"]:
            for d in f["data"]:
                if d.get("scheme"):
                    s = d["scheme"]
                    if d.get("host"):
                        s += "://" + d["host"]
                        for pk in ("path", "pathPrefix", "pathPattern"):
                            if d.get(pk):
                                s += d[pk]
                                break
                    deep_links.add(s)

    # 2) dex strings -> URLs and secrets
    dex_strs = _strings(bytes(dex_blob))
    urls = set()
    for s in dex_strs:
        for m in URL_RE.finditer(s):
            urls.add(m.group().decode().rstrip('.,;)]}'))
    secrets = set()
    for s in dex_strs:
        for m in SECRET_RE.finditer(s):
            secrets.add(m.group().decode())

    return {
        "tool": "apk_recon",
        "target": str(apk),
        "file_size": apk.stat().st_size,
        "zip_entries": len(names),
        "dex_count": dex_count,
        "package": manifest_info.get("package"),
        "version_code": manifest_info.get("versionCode"),
        "version_name": manifest_info.get("versionName"),
        "min_sdk": manifest_info.get("minSdkVersion"),
        "target_sdk": manifest_info.get("targetSdkVersion"),
        "application": {
            "allow_backup": app_attrs.get("allowBackup"),
            "debuggable": app_attrs.get("debuggable"),
            "network_security_config": app_attrs.get("networkSecurityConfig"),
        },
        "permissions": permissions,
        "exported_components": exported_components,
        "component_count": len(components),
        "deep_links": sorted(deep_links),
        "urls": sorted(urls)[:max_urls],
        "secret_candidates": sorted(secrets)[:max_secrets],
        "axml_error": axml_error,
    }


def main():
    print("=" * 62)
    print("  APK Recon  v2.0")
    print("=" * 62)

    ap = argparse.ArgumentParser(description="static recon of a local Android APK")
    ap.add_argument("apk", help="path to the .apk file")
    ap.add_argument("--max-urls", type=int, default=200)
    ap.add_argument("--max-secrets", type=int, default=100)
    args = ap.parse_args()

    result = run(args.apk, args.max_urls, args.max_secrets)

    if result.get("error"):
        print(f"[!] {result['error']}")
        return 1

    print(f"[*] target  : {result['target']}")
    print(f"[*] package : {result['package'] or '(unknown)'}")
    print(f"[*] version : code={result['version_code']} name={result['version_name']} "
          f"minSdk={result['min_sdk']} targetSdk={result['target_sdk']}")
    print(f"[*] size    : {result['file_size']} bytes, {result['zip_entries']} entries, "
          f"{result['dex_count']} dex file(s)")

    if result.get("axml_error"):
        print(f"[!] {result['axml_error']} (fell back to string scan)")

    print(f"\n[=] Permissions ({len(result['permissions'])})")
    for p in result["permissions"]:
        print(f"  - {p}")

    print(f"\n[=] Exported components ({len(result['exported_components'])}) "
          f"of {result['component_count']} components")
    for c in result["exported_components"]:
        tag = "explicit" if c["explicit"] else "implied (intent-filter)"
        print(f"  - {c['type']} {c['name']}  [{tag}]")

    print(f"\n[=] Deep links ({len(result['deep_links'])})")
    for d in result["deep_links"]:
        print(f"  - {d}")

    print(f"\n[=] Embedded URLs ({len(result['urls'])})")
    for u in result["urls"]:
        print(f"  - {u}")

    print(f"\n[=] Secret candidates ({len(result['secret_candidates'])})")
    for s in result["secret_candidates"]:
        print(f"  - {s}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
