# HANDOFF — Graber/Brel BLE mapping (read this first)

You are Claude Code, picking up a live BLE reverse-engineering project. This file is your
orientation. Read `CLAUDE.md` next — it holds the safety rules you must follow.

## Goal
Map the BLE command protocol of a **Graber/Brel motorized blind motor**, then reproduce it
from this PC (as BLE central) with **no phone** — so the desktop can command the blind and,
later, run a closed-loop mapping harness against a camera/notify oracle.

## Where things stand (current session)
- Hardware: **nRF52840 DK (PCA10056)** flashed with nRF Sniffer firmware v4.1.1, working.
  It shows in Wireshark as "nRF Sniffer for Bluetooth LE COM5" and captures fine.
- Sniffer install was the **nrfutil** path (`nrfutil ble-sniffer`), not the old ZIP.
- The DK is the **sniffer** (passive capture). The **central** side (connect/pair/write)
  runs on this machine's own Bluetooth via `bleak` in the harness.
- Target motor MAC (from prior work): `14:2D:41:DD:0E:5C`. Confirm by scanning.
- We are in the **known-plaintext capture** phase: drive the blind with the phone app while
  sniffing, one action at a time, and map physical action -> ATT write bytes.

## The immediate workflow (live)
Two terminals.

Terminal A — capture (you or I run this; it only reads, never transmits):
```
python -m harness sniff interfaces            # find the exact sniffer iface name
python -m harness sniff config "<iface>"      # (once) learn the device-follow extcap arg
python -m harness sniff live "<iface>"        # streams to data/sniff/live.jsonl
```
Terminal B — I drive the blind + annotate. Right BEFORE each app tap:
```
python -m harness mark open
python -m harness mark stop
python -m harness mark close
python -m harness mark goto50
```
Repeat the whole open/stop/close/goto sequence **2–3 times** — repetition is how we tell a
static replayable command from a rolling-counter/encrypted one.

Then analyze:
```
/map-live          # slash command: runs sniff analyze + updates notes/protocol.md
```

## Your job when I say "analyze"
Run `python -m harness sniff analyze` and:
1. **Check security first.** If pairing (SMP) or encryption setup appears, tell me the link
   is encrypted and that we must capture a FRESH pairing from the start (I unbond in the
   app, re-pair while sniffing). Don't interpret ciphertext as commands.
2. If clear, map each action: label -> handle -> payload -> STATIC/VARYING verdict.
3. Flag any NOTIFY characteristic whose values track position — that's the feedback oracle.
4. Update `notes/protocol.md`.
5. Propose the first replay test, but **do not transmit** — see the safety rule below.

## Hard safety rules (full version in CLAUDE.md)
- **Never run a transmit command yourself** (`harness write`, `harness map-batch`). Propose
  the handle + payload + hypothesis and wait for my explicit go-ahead.
- A handle is only writable after I `safety allow <handle>`; default is deny.
- Never write to config/calibration/travel-limit/direction/reset/DFU/OTA handles.
- Graber reset if something goes wrong: hold the motor's program button ~7s until it jogs.

## Map of the code
- `harness/sniff.py` — tshark bridge: live/decode, security detection, mark correlation.
- `harness/ble.py` — bleak central: scan/enum/read/notify/pair + GattSession for replay.
- `harness/capture.py` — camera oracle (fallback if no position notify char).
- `harness/safety.py` — the write allow/deny gate.
- `harness/loop.py` — the write->settle->capture->record replay loop.
- `harness/cli.py` — every command above.
- `notes/protocol.md` — the living map you keep updating.
- `.claude/commands/map-live.md` — the `/map-live` analysis routine.

## Setup checks before first run
- `tshark --version` (bundled with Wireshark; add `C:\Program Files\Wireshark` to PATH if missing).
- `pip install -e .` in this folder.
- `python -m harness sniff interfaces` should list the nRF Sniffer.

## Open question to resolve THIS session
Is the Graber link encrypted? The first clean capture answers it and decides everything:
unencrypted -> we replay bytes and move to phone-less control fast; encrypted -> we pivot to
capturing a fresh pairing before anything else.
