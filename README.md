# GraberBlinds_ESP32

Control **Graber / Brel motorized blinds** (the `RRBZ_*` BLE motors, including **top-down /
bottom-up** shades) from **Home Assistant** via an **ESP32** running ESPHome — **no phone app,
no hub, no cloud**. Includes the reverse-engineering harness used to map the BLE protocol.

> Reverse-engineered from a Graber TDBU blind. Works because the motor's BLE command channel
> is **unencrypted** — commands are plaintext ATT writes guarded only by a per-device numeric
> token. Your motors may differ; verify before trusting.

## What works

- **Phone-less control** from an ESP32 over BLE (validated on hardware).
- **Independent per-rail position sliders** — a **Bottom** and a **Middle** cover per blind,
  each a 0–100 slider. See the coupling note below.
- **Passive position feedback** — each motor broadcasts both rail positions in its BLE
  advertising, so Home Assistant sees position **without holding a connection**.
- **Multi-blind** — one ESP32 bridges several motors; commands connect on-demand (~a few
  seconds each) so your phone app still works.

### Rail coupling (important)

The motor only holds **one rail at an arbitrary position at a time** — moving one rail forces
the other to a default:

- Moving the **Bottom** rail sends the **top/middle to 100** (bottom-up mode).
- Moving the **Middle** rail sends the **bottom to 0** (top-down mode).

So each slider works fully on its own rail; just expect the *other* rail to ride to its
extreme. True "floating band" (both rails at arbitrary mid positions) was not achievable with
the commands mapped so far.

## How it works (protocol summary)

Full details in [`notes/protocol.md`](notes/protocol.md). In brief:

- Link is **unencrypted** (no pairing/bonding). Each connection must first write a **per-device
  7-digit ASCII token** to a command characteristic (app-layer auth).
- Two custom BLE services, one per rail. Movement is a **goto**: write a target % (0–100) to
  the rail's target characteristic, then write `0x14` to that rail's execute characteristic.
- The execute is **coupled**: it moves the selected rail to its target and forces the *other*
  rail to a default (bottom→0, top→100). The four presets are chosen to use that coupling.
- Position is in the advertising **manufacturer data**: `44 [ctr] [bottom%] [top%] 00 ce 14 56`.

## Repo layout

| Path | What |
|------|------|
| `esphome/graber-blinds.yaml` | ESPHome config — 3 blinds, Bottom + Middle position sliders + 2 position sensors each |
| `esphome/secrets.yaml.example` | Template for WiFi / API key / AP password |
| `notes/protocol.md` | The reverse-engineered protocol map |
| `harness/` | Python tooling used to sniff & map the protocol (bleak + nRF Sniffer/tshark) |
| `CLAUDE.md`, `HANDOFF.md` | Working notes / safety rules from the RE session |

## Setup (ESPHome)

1. **Hardware:** any ESP32 (developed on a Seeed XIAO ESP32-S3). Place it within BLE range of
   the blinds. On boards with an external antenna (e.g. XIAO), **plug the antenna in**.
2. **Secrets:** copy `esphome/secrets.yaml.example` → `secrets.yaml` and fill in your 2.4 GHz
   WiFi, an ESPHome `api_key`, and an `ap_password`.
3. **Your MACs + tokens:** in `esphome/graber-blinds.yaml`, set each `mac_address` to your
   blind's, and replace the **placeholder auth-token bytes** with your captured token (below).
4. **Flash** with ESPHome, add the device in Home Assistant. You get preset buttons + position
   sensors per blind.

### Capturing your per-device token

The auth token is unique per motor and **not** in this repo (redacted). To get yours, sniff the
official app driving that blind once and read the ASCII write to characteristic
`5b026510-...`. The `harness/` tools do this with an nRF Sniffer dongle + Wireshark/tshark:
follow the blind, drive it in the app, and read the token from the captured ATT write. See
`notes/protocol.md` and `HANDOFF.md`.

## Safety

Writing to unknown BLE characteristics on a real motor can mis-set travel limits or brick it.
The harness ships a default-deny write gate; only ever write to characteristics you've
verified. This is unofficial and unaffiliated with Graber/Brel/Springs Window Fashions. Use at
your own risk.

## Status / roadmap

- [x] Protocol mapped, phone-less control, passive position, multi-blind
- [x] Per-rail position sliders (Bottom + Middle), 0–100
- [~] Floating band (both rails at arbitrary mid positions): the exec codes `0x14`/`0x16`/`0x18`
      each force the partner rail to a default; controlled tests could not hold both. May be a
      hard limit of the motor, or an un-cracked command sequence.
- [ ] Faster commands (persistent-connection option)
