"""Headless device-following capture, driving Nordic's SnifferAPI directly.

Why this exists: the nRF Sniffer extcap CANNOT follow a device from the command line.
Its `--device` argument is declared but never read, and device selection normally arrives
over Wireshark's extcap control channel (control_loop -> handle_control_command ->
follow_device). Nordic confirm this on DevZone: following a device "is not something you
can input in the commandline arguments" and requires driving the Sniffer API yourself.

`nrfutil ble-sniffer sniff --follow` is NOT an alternative — it follows a device's
ADVERTISING only. When the target connects and stops advertising, the capture goes silent
and no connection/ATT packets are recorded. Verified twice against this motor.

Following via the API captures advertisements, scan requests/responses, CONNECT_IND and
the connection packets themselves — which is where the ATT writes live.

Output is a libpcap file with the Nordic BLE link type, byte-identical in format to what
the Wireshark extcap writes, so `harness sniff decode` reads it unchanged.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# The SnifferAPI ships with the Wireshark extcap, not on pip. Locate it.
_EXTCAP_CANDIDATES = [
    Path(os.environ.get("APPDATA", "")) / "Wireshark" / "extcap",
    Path.home() / ".config" / "wireshark" / "extcap",
    Path("/usr/lib/x86_64-linux-gnu/wireshark/extcap"),
]


def _import_sniffer_api():
    for base in _EXTCAP_CANDIDATES:
        if (base / "SnifferAPI").is_dir():
            sys.path.insert(0, str(base))
            from SnifferAPI import Devices, Pcap, Sniffer  # noqa: PLC0415
            return Sniffer, Devices, Pcap, base
    raise FileNotFoundError(
        "SnifferAPI not found. It ships with the nRF Sniffer Wireshark extcap; "
        f"looked in: {[str(p) for p in _EXTCAP_CANDIDATES]}"
    )


def parse_addr(mac: str, random: bool = False) -> list[int]:
    """'14:2D:41:DD:0E:60' -> [0x14,0x2d,0x41,0xdd,0x0e,0x60, addr_type].

    The trailing element is the address type: 0 = public, 1 = random. Getting this wrong
    means the sniffer never matches the target and silently follows nothing.
    """
    parts = [int(b, 16) for b in mac.replace("-", ":").split(":")]
    if len(parts) != 6:
        raise ValueError(f"expected 6 hex octets, got {mac!r}")
    return parts + [1 if random else 0]


def follow(port: str, target_mac: str, out_pcap: Path, duration: float | None = None,
           random_addr: bool = False, baudrate: int | None = None,
           on_status=print) -> dict:
    """Follow `target_mac` and write every captured packet to `out_pcap`.

    Blocks until `duration` elapses (or forever if None) / KeyboardInterrupt.
    """
    Sniffer, Devices, Pcap, base = _import_sniffer_api()
    out_pcap.parent.mkdir(parents=True, exist_ok=True)

    stats = {"packets": 0, "following": False, "target": target_mac}
    fh = out_pcap.open("wb")
    fh.write(Pcap.get_global_header())
    fh.flush()

    def new_packet(notification):
        packet = notification.msg["packet"]
        blob = bytes([packet.boardId] + packet.getList())
        fh.write(Pcap.create_packet(blob, packet.time))
        fh.flush()          # flush so the file is analyzable while still capturing
        stats["packets"] += 1

    sniffer = Sniffer.Sniffer(port, baudrate) if baudrate else Sniffer.Sniffer(port)
    sniffer.subscribe("NEW_BLE_PACKET", new_packet)
    sniffer.setAdvHopSequence([37, 38, 39])
    # Protocol v3 matches the modern firmware; mirrors the extcap's own version mapping.
    sniffer.setSupportedProtocolVersion(3)
    sniffer.start()
    on_status(f"[follow] sniffer started on {port}")

    # Scan briefly so the firmware has the target in its device table before we follow it.
    sniffer.scan(True, False, False)
    on_status("[follow] scanning for target...")
    time.sleep(3)

    device = Devices.Device(address=parse_addr(target_mac, random_addr),
                            name='""', RSSI=0)
    sniffer.follow(device, False, False, False)
    time.sleep(0.2)
    stats["following"] = True
    on_status(f"[follow] now following {target_mac} -> {out_pcap}")

    t0 = time.time()
    try:
        while duration is None or (time.time() - t0) < duration:
            time.sleep(1.0)
    except KeyboardInterrupt:
        on_status("\n[follow] interrupted")
    finally:
        try:
            sniffer.doExit()
        except Exception:  # noqa: BLE001
            pass
        fh.close()
        stats["elapsed"] = round(time.time() - t0, 1)
        on_status(f"[follow] wrote {stats['packets']} packets to {out_pcap}")
    return stats
