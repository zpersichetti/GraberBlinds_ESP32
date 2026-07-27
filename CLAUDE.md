# CLAUDE.md — Graber/Brel BLE mapping harness

You are driving a controlled reverse-engineering loop against a **physical blind motor**.
Writes to the wrong characteristic can mis-set travel limits, reverse direction, wipe
calibration, or trigger DFU/OTA and **brick the motor**. Move deliberately.

## Non-negotiable safety rules
1. **Never** write to a handle unless `harness safety check <handle>` returns `ALLOW`.
   The denylist covers anything that looks like config / calibration / travel-limit /
   direction / reset / DFU / OTA. When unsure, treat as deny and ask me.
2. In Phase 3, **propose each new payload (handle + hex + hypothesis) and wait for my
   approval** until a value range is confirmed safe. After a range is verified, you may
   batch *within that range only*.
3. Every write goes through `harness write ... --capture` or `harness map-batch` so it is
   logged. No ad-hoc `bleak` scripts that bypass logging.
4. Keep the reset procedure ready: **Graber — hold the motor's program button ~7s until
   the shade jogs.** If behavior goes wrong, stop and tell me before continuing.

## Workflow (do not skip phases)
- **Phase 0 — Recon, zero writes.** `scan` → confirm MAC → `enum` → `read-all` →
  `sub` on every notify/indicate char to find the position-feedback oracle. Commit the
  GATT dump and classify handles into allow/deny.
- **Phase 1 — Viability gate.** Pair if needed, write ONE obvious payload to the likeliest
  command char, watch notifications + camera. Moves → continue. Nothing → app-layer auth;
  stop and we pivot to sniffing the pairing with the DK. Do not build the full loop before
  this passes.
- **Phase 2 — Lock the oracle.** If a notify char reports position, characterize its byte
  layout and make it primary feedback (camera = cross-check). Else `calibrate` the camera
  (open/closed reference frames + ROI).
- **Phase 3 — Systematic mapping (allowlist only).** For each candidate: record pre-state →
  write → wait-for-settle → post-state → delta. Hypothesis-driven, not brute force
  (open/close/stop are usually single opcodes; position-target is usually one byte 0–100 or
  0–0xFF).
- **Phase 4 — Validate.** Fill `notes/protocol.md`. Command a target %, confirm the oracle
  agrees within tolerance.

## Environment notes
- Central: host BT adapter (or USB-BT500) via bleak. Sniffer DK is a **separate** tool for
  the pairing capture / on-air ground truth, not used by this harness.
- macOS has no explicit BLE pairing (CoreBluetooth pairs implicitly on encrypted access);
  Linux/BlueZ and Windows/WinRT support `harness pair`.
- Camera source is a UniFi Protect RTSP URL or a local webcam index.

## Pre-approved shell commands (safe to run without asking)
- `python -m harness scan ...`
- `python -m harness enum ...`
- `python -m harness read-all ...`
- `python -m harness sub ...`
- `python -m harness snapshot ...`
- `python -m harness safety ...`
- `python -m harness calibrate ...`
- `python -m harness pair ...`
- `python -m harness sniff ...` (passive tshark capture — receives only, never transmits)
- `python -m harness mark ...` (appends a local timestamp to data/action_log.jsonl)

## Requires my approval before running
- `python -m harness write ...`
- `python -m harness map-batch ...`
(Any command that transmits to the motor.)
