#!/usr/bin/env python3
"""Package existing verifier assets, without a hosted server or remote requests."""
from pathlib import Path
import hashlib
import json
import re
import zipfile

root = Path(__file__).resolve().parents[1]
out = root / "dist/verifier"
out.mkdir(parents=True, exist_ok=True)
page = (root / "web/apostille.html").read_text()
values = {"CONNECT": "'none'", "LANG": "en", "TITLE": "Apostille — Offline verifier",
          "MODE": "verify", "ASSETS": "./", "ASSET_VERSION": "",
          "CANONICAL": "https://ifandonlyif.io/apostille/verify", "OFFLINE": "true",
          "SITE_NAV_ASSETS": "", "SITE_NAV": ""}
for key, value in values.items():
    page = page.replace("{{" + key + "}}", value)
if re.search(r"\{\{[^}]+\}\}", page):
    raise RuntimeError("unknown HTML placeholder: update verifier packaging")
assets = {"index.html": page.encode()}
for name in ("apostille.css", "apostille-page.mjs", "apostille-core.mjs", "apostille-json.mjs",
             "apostille-http.mjs", "apostille-erc8004.mjs", "apostille-messages.mjs", "apostille-0.1.schema.json"):
    assets[name] = (root / "web" / name).read_bytes()
for name, source in {"LICENSE": "LICENSE", "core-0.1.md": "docs/apostille/spec/core-0.1.md",
                     "erc8004-binding-0.1.md": "docs/apostille/spec/erc8004-binding-0.1.md",
                     "test-vectors.json": "testdata/apostille/core-0.1.json"}.items():
    assets[name] = (root / source).read_bytes()
assets["README.txt"] = b"""Apostille Core 0.1 offline verifier (alpha)
Serve this folder: python3 -m http.server 8080 --bind 127.0.0.1
Open http://127.0.0.1:8080/ ; file:// is unsupported.
Only local assets are loaded. No API/RPC/key/status/telemetry requests.
Issuer trust requires independent exact issuer/key pins.
Synthetic fixture keys must never be trusted for real documents.
ERC-8004 evidence is historical issuer-checked ownership, not current ownership.
This browser package does not verify ZK; use the experimental local Go/CLI profile.
"""
checksums = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(assets.items())}
assets["SHA256SUMS.json"] = (json.dumps(checksums, indent=2) + "\n").encode()
archive = root / "dist/apostille-offline-verifier-0.1.zip"
with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
    for name, data in sorted(assets.items()):
        (out / name).write_bytes(data)
        info = zipfile.ZipInfo(name, date_time=(2026, 9, 14, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        z.writestr(info, data)
print(f"PASS: {len(assets)} local assets, sha256 {hashlib.sha256(archive.read_bytes()).hexdigest()}")
