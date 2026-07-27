"""Command-line surface. Claude Code drives everything through these commands so every
action is reproducible and logged. Read-only/recon commands are pre-approved; anything that
transmits (`write`, `map-batch`) requires operator approval per CLAUDE.md.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer

from . import ble, capture, loop, safety

app = typer.Typer(add_completion=False, help="Graber/Brel BLE mapping harness")
DATA = Path(__file__).resolve().parent.parent / "data"


def _hex(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", "").replace("0x", ""))


def _dump(obj) -> None:
    typer.echo(json.dumps(obj, indent=2))


# ------------------------------------------------------------------- recon (safe)
@app.command()
def scan(timeout: float = 8.0):
    """List nearby BLE devices (strongest RSSI first). Zero writes."""
    _dump(asyncio.run(ble.scan(timeout)))


@app.command()
def enum(address: str, out: str = str(DATA / "gatt_dump.json")):
    """Enumerate full GATT and write it to disk. Zero writes."""
    dump = asyncio.run(ble.enumerate_gatt(address))
    Path(out).write_text(json.dumps(dump, indent=2))
    _dump(dump)


@app.command(name="read-all")
def read_all(address: str):
    """Read every readable characteristic. Zero writes."""
    _dump(asyncio.run(ble.read_all(address)))


@app.command()
def sub(address: str, duration: float = 20.0,
        uuid: list[str] = typer.Option(None, help="Restrict to these char UUIDs")):
    """Subscribe to notify/indicate chars to find the position-feedback oracle."""
    events: list[dict] = []
    asyncio.run(ble.subscribe(address, uuid or None, duration, events.append))
    _dump(events)


@app.command()
def pair(address: str):
    """Attempt OS-level pairing/bonding (Linux/Windows; implicit on macOS)."""
    _dump(asyncio.run(ble.pair(address)))


@app.command()
def snapshot(source: str):
    """Grab one camera frame + a settle reading. Camera source = webcam index or RTSP URL."""
    frame = capture.grab(source)
    p = capture.save_frame(frame, DATA / "runs" / "snapshot.png")
    pos = capture.estimate_position(DATA, frame)
    _dump({"frame": str(p), "estimated_position": pos})


@app.command()
def calibrate(source: str, which: str,
              roi: str = typer.Option(..., help="x,y,w,h of the window region")):
    """Save an 'open' or 'closed' reference frame for camera position estimates."""
    x, y, w, h = (int(v) for v in roi.split(","))
    _dump(capture.save_calibration(DATA, source, (x, y, w, h), which))


# ------------------------------------------------------------------- safety (safe)
safety_app = typer.Typer(help="Inspect and edit the write allow/deny lists")
app.add_typer(safety_app, name="safety")


@safety_app.command("classify")
def safety_classify(dump: str = str(DATA / "gatt_dump.json")):
    """Suggest allow/deny from a GATT dump. Does NOT auto-apply."""
    _dump(safety.classify(json.loads(Path(dump).read_text())))


@safety_app.command("check")
def safety_check(handle: int):
    """Gate check for a single handle. Prints ALLOW or DENY."""
    verdict, reason = safety.check(DATA, handle)
    typer.echo(f"{verdict}: {reason}")


@safety_app.command("allow")
def safety_allow(handle: int):
    """Add a handle to the allowlist (operator action)."""
    rules = safety.load_rules(DATA)
    rules.setdefault("allow", [])
    if handle not in rules["allow"]:
        rules["allow"].append(handle)
    rules["deny"] = [h for h in rules.get("deny", []) if h != handle]
    safety.save_rules(DATA, rules)
    _dump(rules)


@safety_app.command("deny")
def safety_deny(handle: int):
    """Add a handle to the denylist (operator action)."""
    rules = safety.load_rules(DATA)
    rules.setdefault("deny", [])
    if handle not in rules["deny"]:
        rules["deny"].append(handle)
    rules["allow"] = [h for h in rules.get("allow", []) if h != handle]
    safety.save_rules(DATA, rules)
    _dump(rules)


# --------------------------------------------------------------- transmit (gated)
@app.command()
def write(address: str, handle: int, payload: str,
          no_response: bool = typer.Option(False, help="Use write-without-response"),
          camera: str = typer.Option(None, help="Camera source for capture")):
    """Single gated write with capture. REQUIRES the handle to be on the allowlist."""
    verdict, reason = safety.check(DATA, handle)
    if verdict != "ALLOW":
        typer.echo(f"BLOCKED {verdict}: {reason}")
        raise typer.Exit(code=2)
    summary = asyncio.run(loop.map_batch(
        DATA, address, [(handle, _hex(payload))],
        camera=camera, notify_uuids=None, do_pair=False, response=not no_response))
    _dump(summary)


@app.command(name="map-batch")
def map_batch(address: str,
              payload: list[str] = typer.Option(..., help="handle:hex, repeatable"),
              camera: str = typer.Option(None),
              notify_uuid: list[str] = typer.Option(None),
              do_pair: bool = typer.Option(False),
              no_response: bool = typer.Option(False),
              burst: bool = typer.Option(False, help="Send writes back-to-back, single settle "
                                         "after the last (for target+execute goto commands)")):
    """Gated batch of writes in one session. Format each --payload as HANDLE:HEX."""
    parsed = []
    for item in payload:
        h, hx = item.split(":", 1)
        parsed.append((int(h), _hex(hx)))
    summary = asyncio.run(loop.map_batch(
        DATA, address, parsed, camera=camera,
        notify_uuids=notify_uuid or None, do_pair=do_pair, response=not no_response,
        burst=burst))
    _dump(summary)


# ---------------------------------------------------------------- action marking
ACTION_LOG = DATA / "action_log.jsonl"
SNIFF_JSONL = DATA / "sniff" / "live.jsonl"


@app.command()
def mark(label: str):
    """Timestamp an action you just performed (e.g. `harness mark open`). Claude joins
    these to the sniffed ATT writes by time. Run this right BEFORE you tap the app."""
    import time
    ACTION_LOG.parent.mkdir(parents=True, exist_ok=True)
    rec = {"t": time.time(), "label": label}
    with ACTION_LOG.open("a") as fh:
        fh.write(json.dumps(rec) + "\n")
    _dump(rec)


# -------------------------------------------------------------------- sniff (safe)
sniff_app = typer.Typer(help="Capture/decode BLE traffic via the nRF Sniffer + tshark")
app.add_typer(sniff_app, name="sniff")


@sniff_app.command("interfaces")
def sniff_interfaces():
    """List tshark interfaces — find the exact nRF Sniffer name."""
    from . import sniff
    typer.echo(sniff.list_interfaces())


@sniff_app.command("config")
def sniff_config(iface: str):
    """Show the nRF Sniffer extcap options for your version (incl. the device-follow arg)."""
    from . import sniff
    typer.echo(sniff.extcap_config(iface))


@sniff_app.command("live")
def sniff_live(iface: str,
               extcap_arg: list[str] = typer.Option(
                   None, help="Raw extcap args to follow one device, e.g. --extcap-arg "
                              "--device --extcap-arg '14:2D:41:DD:0E:5C'. Confirm the exact "
                              "flag name with `sniff config`.")):
    """Stream live from the sniffer to data/sniff/live.jsonl, printing writes as they arrive.
    Ctrl-C to stop. Zero transmit — capture only."""
    from . import sniff
    typer.echo(f"[live] -> {SNIFF_JSONL}  (Ctrl-C to stop)")
    try:
        for rec in sniff.live(iface, SNIFF_JSONL, extcap_arg or None):
            if rec.get("is_write"):
                typer.echo(f"WRITE  handle={rec['handle']}  value={rec['value']}  "
                           f"({rec['opcode_name']})")
            elif rec.get("is_notify"):
                typer.echo(f"NOTIFY handle={rec['handle']}  value={rec['value']}")
            elif rec.get("smp"):
                typer.echo(f"** SMP pairing packet (smp opcode {rec['smp']}) **")
            elif rec.get("enc_setup"):
                typer.echo(f"** link encryption setup (ctrl {rec['ctrl']}) **")
    except KeyboardInterrupt:
        typer.echo("\n[live] stopped")


@sniff_app.command("follow")
def sniff_follow(target: str,
                 port: str = typer.Option("COM5", help="Sniffer serial port"),
                 out: str = typer.Option(str(DATA / "sniff" / "follow.pcap")),
                 duration: float = typer.Option(None, help="Seconds; omit to run until Ctrl-C"),
                 random_addr: bool = typer.Option(False, help="Target uses a random address")):
    """Follow ONE device headlessly and capture its connection traffic (incl. ATT).

    The extcap cannot do this from the CLI and `nrfutil --follow` only follows advertising;
    this drives Nordic's SnifferAPI directly. Zero transmit — capture only."""
    from . import sniff_follow as sf
    stats = sf.follow(port, target, Path(out), duration=duration, random_addr=random_addr)
    _dump(stats)


@sniff_app.command("decode")
def sniff_decode(pcapng: str,
                 out: str = str(DATA / "sniff" / "decoded.jsonl")):
    """Decode a saved .pcapng to structured JSONL (batch / re-analysis)."""
    from . import sniff
    recs = sniff.decode(Path(pcapng), Path(out))
    _dump({"records": len(recs), "out": out,
           "security": sniff.detect_security(recs)})


@sniff_app.command("analyze")
def sniff_analyze(records: str = str(SNIFF_JSONL),
                  window: float = 4.0):
    """Join action marks to sniffed writes and classify each action STATIC vs VARYING."""
    from . import sniff
    recs = sniff.load_jsonl(Path(records))
    marks = sniff.load_jsonl(ACTION_LOG)
    joined = sniff.join(recs, marks, window_s=window)
    _dump({
        "security": sniff.detect_security(recs),
        "actions": sniff.summarize(joined),
        "detail": joined,
    })


if __name__ == "__main__":
    app()
