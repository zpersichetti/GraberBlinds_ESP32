"""BLE layer built on bleak.

Design: atomic operations (scan/enum/read-all/sub/pair) each open and close their own
connection so they are stateless and auditable. The mapping loop uses `GattSession`, which
holds one connection open across a batch of writes so notifications and timing stay coherent.

Handle vs UUID: bleak accepts a characteristic's integer handle, its UUID string, or a
BleakGATTCharacteristic object anywhere a char specifier is expected. We key on the integer
handle everywhere because it is unambiguous per device (UUIDs can repeat across services).
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Callable

from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic

# 0x2901 Characteristic User Description — often carries a human-readable name.
CUD_UUID = "00002901-0000-1000-8000-00805f9b34fb"


# --------------------------------------------------------------------------- scan
async def scan(timeout: float = 8.0) -> list[dict]:
    """Return advertising devices sorted by RSSI (strongest first)."""
    found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    rows = []
    for address, (device, adv) in found.items():
        rows.append(
            {
                "address": address,
                "name": device.name or adv.local_name or "",
                "rssi": adv.rssi,
                "service_uuids": list(adv.service_uuids or []),
                "manufacturer": {str(k): v.hex() for k, v in (adv.manufacturer_data or {}).items()},
            }
        )
    rows.sort(key=lambda r: r["rssi"], reverse=True)
    return rows


# ----------------------------------------------------------------------- enumerate
async def enumerate_gatt(address: str, connect_timeout: float = 20.0) -> dict:
    """Full GATT tree: services -> characteristics -> descriptors, with names/props."""
    async with BleakClient(address, timeout=connect_timeout) as client:
        services = []
        for svc in client.services:
            chars = []
            for ch in svc.characteristics:
                descs = []
                cud_name = None
                for d in ch.descriptors:
                    entry = {"uuid": d.uuid, "handle": d.handle}
                    if d.uuid.lower() == CUD_UUID:
                        try:
                            raw = await client.read_gatt_descriptor(d.handle)
                            cud_name = bytes(raw).decode("utf-8", "replace")
                            entry["value"] = cud_name
                        except Exception as e:  # noqa: BLE001
                            entry["error"] = repr(e)
                    descs.append(entry)
                chars.append(
                    {
                        "uuid": ch.uuid,
                        "handle": ch.handle,
                        "name": cud_name or ch.description,
                        "properties": list(ch.properties),
                        "descriptors": descs,
                    }
                )
            services.append({"uuid": svc.uuid, "handle": svc.handle,
                             "description": svc.description, "characteristics": chars})
        return {"address": address, "services": services}


async def read_all(address: str, connect_timeout: float = 20.0) -> dict:
    """Read every readable characteristic. Never writes."""
    out = {}
    async with BleakClient(address, timeout=connect_timeout) as client:
        for svc in client.services:
            for ch in svc.characteristics:
                if "read" not in ch.properties:
                    continue
                try:
                    val = await client.read_gatt_char(ch.handle)
                    out[ch.handle] = {"uuid": ch.uuid, "hex": bytes(val).hex(),
                                      "len": len(val)}
                except Exception as e:  # noqa: BLE001
                    out[ch.handle] = {"uuid": ch.uuid, "error": repr(e)}
    return out


# --------------------------------------------------------------------------- pair
async def pair(address: str, connect_timeout: float = 20.0) -> dict:
    """Attempt OS-level pairing/bonding. No-op/raises on macOS CoreBluetooth."""
    async with BleakClient(address, timeout=connect_timeout) as client:
        try:
            # bleak >=3.0 returns None from pair(); older versions returned a bool. Treat
            # "did not raise" as success, otherwise a successful pair reports paired=False
            # and the Phase 1 viability gate reads backwards.
            ok = await client.pair()
            return {"paired": True if ok is None else bool(ok),
                    "backend": type(client._backend).__name__}
        except NotImplementedError:
            return {"paired": None,
                    "note": "This backend has no explicit pair(); on macOS pairing "
                            "happens implicitly when an encrypted characteristic is accessed."}


# ------------------------------------------------------------------------ subscribe
def _handle_of(sender) -> int:
    """bleak notify callbacks pass a BleakGATTCharacteristic (new) or int (old)."""
    return getattr(sender, "handle", sender)


async def subscribe(address: str, uuids: list[str] | None, duration: float,
                    on_event: Callable[[dict], None], connect_timeout: float = 20.0) -> None:
    """Subscribe to given notify/indicate chars (or ALL if uuids is None) for `duration`s."""
    async with BleakClient(address, timeout=connect_timeout) as client:
        targets = []
        for svc in client.services:
            for ch in svc.characteristics:
                notif = "notify" in ch.properties or "indicate" in ch.properties
                if not notif:
                    continue
                if uuids is None or ch.uuid.lower() in {u.lower() for u in uuids}:
                    targets.append(ch)

        def cb(sender, data: bytearray):
            on_event({"t": time.time(), "handle": _handle_of(sender),
                      "hex": bytes(data).hex()})

        for ch in targets:
            await client.start_notify(ch.handle, cb)
        try:
            await asyncio.sleep(duration)
        finally:
            for ch in targets:
                try:
                    await client.stop_notify(ch.handle)
                except Exception:  # noqa: BLE001
                    pass


# -------------------------------------------------------------- persistent session
@dataclass
class GattSession:
    """One held-open connection for a mapping batch.

    Captures all notifications into `events` with timestamps so the loop can read the
    feedback oracle around each write. Use as an async context manager.
    """
    address: str
    notify_uuids: list[str] | None = None
    do_pair: bool = False
    connect_timeout: float = 20.0
    _client: BleakClient | None = field(default=None, init=False)
    events: list[dict] = field(default_factory=list, init=False)
    skipped_notifies: list[dict] = field(default_factory=list, init=False)

    async def __aenter__(self) -> "GattSession":
        self._client = BleakClient(self.address, timeout=self.connect_timeout)
        await self._client.connect()
        if self.do_pair:
            try:
                await self._client.pair()
            except NotImplementedError:
                pass
        for svc in self._client.services:
            for ch in svc.characteristics:
                if "notify" not in ch.properties and "indicate" not in ch.properties:
                    continue
                if self.notify_uuids is None or ch.uuid.lower() in {
                    u.lower() for u in self.notify_uuids
                }:
                    # A single un-subscribable char (e.g. GATT Service Changed 0x0002,
                    # which WinRT refuses without bonding) must not abort the whole session.
                    # Skip it and keep the oracle subscriptions that do work.
                    try:
                        await self._client.start_notify(ch.handle, self._on_notify)
                    except Exception as e:  # noqa: BLE001
                        self.skipped_notifies.append({"handle": ch.handle,
                                                      "uuid": ch.uuid, "error": repr(e)})
        return self

    async def __aexit__(self, *exc):
        if self._client is not None:
            try:
                await self._client.disconnect()
            finally:
                self._client = None

    def _on_notify(self, sender, data: bytearray):
        self.events.append({"t": time.time(), "handle": _handle_of(sender),
                            "hex": bytes(data).hex()})

    def events_since(self, t0: float) -> list[dict]:
        return [e for e in self.events if e["t"] >= t0]

    def _resolve(self, handle: int) -> BleakGATTCharacteristic:
        """Map an ATT VALUE handle (what the sniffer shows, what safety gates on) to the
        bleak characteristic object. bleak 3.x keys chars by their DECLARATION handle, i.e.
        value_handle - 1, and refuses a bare int value-handle. Prefer an exact match, then
        the declaration-handle (handle-1) match; require it to be unambiguous."""
        chars = [c for svc in self._client.services for c in svc.characteristics]
        exact = [c for c in chars if c.handle == handle]
        if len(exact) == 1:
            return exact[0]
        decl = [c for c in chars if c.handle == handle - 1]
        if len(decl) == 1:
            return decl[0]
        raise ValueError(f"cannot uniquely resolve value handle {handle} "
                         f"(exact={len(exact)}, decl={len(decl)})")

    async def write(self, handle: int, data: bytes, response: bool = True) -> None:
        assert self._client is not None
        ch = self._resolve(handle)
        await self._client.write_gatt_char(ch, data, response=response)

    async def read(self, handle: int) -> bytes:
        assert self._client is not None
        return bytes(await self._client.read_gatt_char(handle))
