"""Write-safety gate.

Every transmit must pass `check(handle)` -> ALLOW. Default posture is DENY. A characteristic
becomes writable-by-the-harness only when it is on the explicit allowlist. We also hard-deny
anything whose name/UUID pattern-matches config / calibration / limit / direction / reset /
DFU / OTA, so an accidental allowlist entry can't override a dangerous class.

Populate the lists from the GATT dump during Phase 0 (see `classify`).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# Substrings (case-insensitive) in a char name that mean "never write here".
DANGER_NAME_PATTERNS = [
    r"dfu", r"ota", r"boot", r"firmware", r"upgrade",
    r"config", r"calib", r"limit", r"endpoint", r"travel",
    r"direction", r"reverse", r"reset", r"factory", r"erase",
    r"key", r"auth", r"pair", r"bond", r"password", r"secret",
]

# UUIDs known to be dangerous (Nordic DFU service + Secure DFU).
DANGER_UUIDS = {
    "0000fe59-0000-1000-8000-00805f9b34fb",  # Nordic DFU service
    "8ec90003-f315-4f60-9fb8-838830daea50",  # Nordic Secure DFU control point
}

_DANGER_RE = re.compile("|".join(DANGER_NAME_PATTERNS), re.IGNORECASE)


def _rules_path(data_dir: Path) -> Path:
    return data_dir / "safety_rules.json"


def load_rules(data_dir: Path) -> dict:
    p = _rules_path(data_dir)
    if p.exists():
        return json.loads(p.read_text())
    return {"allow": [], "deny": []}  # lists of integer handles


def save_rules(data_dir: Path, rules: dict) -> None:
    _rules_path(data_dir).write_text(json.dumps(rules, indent=2))


def classify(gatt_dump: dict) -> dict:
    """Suggest allow/deny from a GATT dump. Writable + not-dangerous -> allow candidate."""
    allow, deny = [], []
    for svc in gatt_dump.get("services", []):
        svc_uuid = svc["uuid"].lower()
        for ch in svc["characteristics"]:
            writable = any(p in ch["properties"] for p in ("write", "write-without-response"))
            name = (ch.get("name") or "")
            dangerous = (
                svc_uuid in DANGER_UUIDS
                or ch["uuid"].lower() in DANGER_UUIDS
                or bool(_DANGER_RE.search(name))
                or bool(_DANGER_RE.search(ch["uuid"]))
            )
            if dangerous:
                deny.append({"handle": ch["handle"], "uuid": ch["uuid"], "name": name})
            elif writable:
                allow.append({"handle": ch["handle"], "uuid": ch["uuid"], "name": name})
    return {"allow_candidates": allow, "deny": deny}


def check(data_dir: Path, handle: int) -> tuple[str, str]:
    """Return (verdict, reason). verdict in {ALLOW, DENY}."""
    rules = load_rules(data_dir)
    if handle in rules.get("deny", []):
        return "DENY", "handle is on explicit denylist"
    if handle in rules.get("allow", []):
        return "ALLOW", "handle is on explicit allowlist"
    return "DENY", "handle not on allowlist (default-deny)"
