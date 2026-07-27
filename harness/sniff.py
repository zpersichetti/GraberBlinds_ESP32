"""Sniff layer — bridges the nRF Sniffer (via Wireshark's tshark CLI) into structured
records Claude can analyze.

Why tshark and not raw pcap parsing: tshark already dissects the BLE stack (ATT, SMP, LL
control) that the nRF Sniffer wraps, so we get decoded handles/opcodes/values for free.

Two modes:
  * live(): stream from the nRF Sniffer extcap interface, append JSONL as packets arrive.
  * decode(): re-run the same extraction over a saved .pcapng (batch / re-analysis).

Correlation: `mark` (in cli.py) writes timestamped action labels to action_log.jsonl.
`join()` matches each mark to the ATT writes that follow it, and diffs repeated same-label
actions so we can tell a STATIC replayable command from one carrying a rolling counter.

IMPORTANT on opcodes: use the FULL btatt.opcode byte, not btatt.opcode.method. Write Request
(0x12) and Write Command (0x52) share the same 6-bit method (0x12); only the full byte
distinguishes them.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Iterator

# Full ATT opcodes we care about.
ATT_OPCODES = {
    "0x0a": "Read Request",
    "0x0b": "Read Response",
    "0x12": "Write Request",
    "0x13": "Write Response",
    "0x52": "Write Command",
    "0x1b": "Handle Value Notification",
    "0x1d": "Handle Value Indication",
    "0xd2": "Signed Write Command",
}
WRITE_OPCODES = {"0x12", "0x52", "0xd2"}
NOTIFY_OPCODES = {"0x1b", "0x1d"}

# LL control PDUs that signal link encryption is being set up.
ENC_CONTROL_OPCODES = {"0x03", "0x04", "0x05", "0x06"}  # ENC_REQ/RSP, START_ENC_REQ/RSP

# tshark field order (tab-separated). Keep in sync with _parse_line().
FIELDS = [
    "frame.time_epoch",
    "btatt.handle",
    "btatt.opcode",
    "btatt.value",
    "btsmp.opcode",
    "btle.control_opcode",
]

# Only emit frames that carry ATT, SMP (pairing), or LL control (encryption setup).
DISPLAY_FILTER = "btatt || btsmp || btle.control_opcode"


def tshark_bin() -> str:
    """Locate tshark. On Windows it may not be on PATH; fall back to the default install."""
    found = shutil.which("tshark")
    if found:
        return found
    for cand in (
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        "/usr/bin/tshark",
    ):
        if Path(cand).exists():
            return cand
    raise FileNotFoundError(
        "tshark not found. Install Wireshark and/or add its folder to PATH."
    )


def list_interfaces() -> str:
    """`tshark -D` — find the exact nRF Sniffer interface name/number."""
    return subprocess.run([tshark_bin(), "-D"], capture_output=True, text=True).stdout


def extcap_config(iface: str) -> str:
    """`tshark -i <iface> --extcap-config` — shows the sniffer's options, including the
    device-follow selector name for THIS version. Use it to learn the right --device flag."""
    return subprocess.run(
        [tshark_bin(), "-i", iface, "--extcap-config"], capture_output=True, text=True
    ).stdout


def _base_cmd(iface: str, extcap_args: list[str] | None) -> list[str]:
    cmd = [tshark_bin(), "-i", iface, "-l", "-Y", DISPLAY_FILTER, "-T", "fields",
           "-E", "separator=/t", "-E", "occurrence=a"]
    for f in FIELDS:
        cmd += ["-e", f]
    if extcap_args:
        cmd += extcap_args
    return cmd


def _parse_line(line: str) -> dict | None:
    parts = line.rstrip("\n").split("\t")
    if len(parts) < len(FIELDS):
        parts += [""] * (len(FIELDS) - len(parts))
    t, handle, opcode, value, smp, ctrl = parts[:len(FIELDS)]
    if not any((handle, opcode, smp, ctrl)):
        return None
    opcode = opcode.split(",")[0].lower() if opcode else ""
    rec = {
        "t": float(t) if t else None,
        "handle": handle.split(",")[0] if handle else None,
        "opcode": opcode or None,
        "opcode_name": ATT_OPCODES.get(opcode),
        "value": (value.split(",")[0].replace(":", "") if value else None),
        "is_write": opcode in WRITE_OPCODES,
        "is_notify": opcode in NOTIFY_OPCODES,
        "smp": smp or None,
        "ctrl": ctrl.split(",")[0].lower() if ctrl else None,
    }
    rec["enc_setup"] = rec["ctrl"] in ENC_CONTROL_OPCODES if rec["ctrl"] else False
    return rec


def live(iface: str, out_jsonl: Path, extcap_args: list[str] | None = None
         ) -> Iterator[dict]:
    """Stream from the sniffer, append each relevant record to out_jsonl, and yield it so
    the CLI can print live. Blocks until interrupted."""
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    cmd = _base_cmd(iface, extcap_args)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, bufsize=1)
    try:
        with out_jsonl.open("a") as fh:
            for line in proc.stdout:  # type: ignore[union-attr]
                rec = _parse_line(line)
                if rec is None:
                    continue
                fh.write(json.dumps(rec) + "\n")
                fh.flush()
                yield rec
    finally:
        proc.terminate()


def decode(pcapng: Path, out_jsonl: Path) -> list[dict]:
    """Extract the same records from a saved capture."""
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    cmd = [tshark_bin(), "-r", str(pcapng), "-Y", DISPLAY_FILTER, "-T", "fields",
           "-E", "separator=/t", "-E", "occurrence=a"]
    for f in FIELDS:
        cmd += ["-e", f]
    res = subprocess.run(cmd, capture_output=True, text=True)
    recs = [r for line in res.stdout.splitlines() if (r := _parse_line(line))]
    with out_jsonl.open("w") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")
    return recs


# ------------------------------------------------------------------ correlation
def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def detect_security(records: list[dict]) -> dict:
    """Did we see pairing (SMP) or link-encryption setup? If so, ATT after that point may
    be undecryptable unless the pairing was captured from the start."""
    smp = [r for r in records if r.get("smp")]
    enc = [r for r in records if r.get("enc_setup")]
    # An empty capture must NOT read as "clear to replay" — absence of evidence here is not
    # evidence of absence, and this verdict gates whether we transmit at all.
    if not records:
        return {
            "saw_pairing_smp": False,
            "saw_encryption_setup": False,
            "inconclusive": True,
            "note": ("INCONCLUSIVE — zero ATT/SMP/LL-control records in this capture. This "
                     "says nothing about link security; it usually means no connection was "
                     "active while sniffing (advertising only). Drive the blind with the app "
                     "while capturing, then re-analyze."),
        }
    return {
        "saw_pairing_smp": bool(smp),
        "saw_encryption_setup": bool(enc),
        "inconclusive": False,
        "note": ("Encrypted/bonded link likely — to decode ATT you must capture a FRESH "
                 "pairing from the start (unbond in the app, then re-pair while sniffing)."
                 if (smp or enc) else
                 "No pairing/encryption seen — ATT writes should be readable and replayable."),
    }


def join(records: list[dict], marks: list[dict], window_s: float = 4.0) -> list[dict]:
    """For each action mark, collect the ATT writes within `window_s` after it."""
    writes = [r for r in records if r.get("is_write") and r.get("t") is not None]
    out = []
    for m in marks:
        t0 = m["t"]
        hits = [w for w in writes if t0 <= w["t"] <= t0 + window_s]
        out.append({"label": m["label"], "t": t0,
                    "writes": [{"handle": w["handle"], "value": w["value"],
                                "opcode_name": w["opcode_name"]} for w in hits]})
    return out


def summarize(joined: list[dict]) -> dict:
    """Group by label and flag STATIC (same payload every rep) vs VARYING (rolling counter /
    encryption). Static commands are safe to replay from the harness."""
    by_label: dict[str, list[dict]] = {}
    for j in joined:
        for w in j["writes"]:
            by_label.setdefault(j["label"], []).append(w)
    result = {}
    for label, ws in by_label.items():
        # signature = (handle, value) per write; compare across repetitions
        sigs = {(w["handle"], w["value"]) for w in ws}
        handles = {w["handle"] for w in ws}
        result[label] = {
            "count": len(ws),
            "handles": sorted(handles),
            "distinct_payloads": sorted({w["value"] for w in ws if w["value"]}),
            "static": len(sigs) == 1 and len(ws) > 1,
            "verdict": ("STATIC — replayable" if len(sigs) == 1 and len(ws) > 1
                        else "VARYING — rolling counter or encrypted; do not blind-replay"
                        if len(ws) > 1 else "single sample — repeat the action to classify"),
        }
    return result
