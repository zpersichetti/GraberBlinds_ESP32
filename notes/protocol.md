# Graber/Brel motor — BLE protocol map (living document)

## Device
- Address (MAC): `14:2D:41:DD:0E:60` (public) — confirmed target, RSSI ~-55 dBm
- Advertised name / service UUIDs: `RRBZ_DD0E60`
- Requires pairing/bonding? **NO** — capture showed zero SMP, zero encryption setup. Link is plaintext ATT.
- Requires app-layer key/handshake? **YES** — an ASCII token `REDACTED` (hex `REDACTED`)
  is written to the command char 3× immediately after connect, before any movement command.
  This is app-layer auth, not BLE encryption. Likely required for replay.

> HANDOFF.md lists `14:2D:41:DD:0E:5C` as the target. That is a DIFFERENT blind — real and
> advertising, but not the one being driven. Following it produced a silent capture. Five
> RRBZ units are in range; always confirm the address in the sniffer's Device dropdown.

### Other RRBZ units in range (do not target)
| address | name | adv byte3 |
|---------|------|-----------|
| 14:2d:41:dd:0e:5c | RRBZ_DD0E5C | 0x64 |
| 14:2d:41:dd:0e:e7 | RRBZ_DD0EE7 | 0x63 |
| 14:2d:41:dd:17:3f | RRBZ_DD173F | 0x00 |
| 40:30:59:6a:84:5c | RRBZ_6A845C | 0x64 |

### Advertising payload (passive, no connection needed)
Manufacturer data, 8 bytes: `46 CC 64 PP 00 ce 14 56`
- byte0 `0x46`, bytes5-7 `ce 14 56` — constant across all units
- byte1 `CC` — rolling counter (60 distinct values / 263 s)
- byte2 `0x64` — constant
- byte3 `PP` — differs per unit (0x64=100, 0x63=99, 0x00=0). Position candidate, but it did
  NOT change across ~670 CRC-valid samples while a blind was driven, so it may be a
  configured value rather than live state. UNCONFIRMED — retest against a known movement.
- Names arrive in `ADV_IND` (not scan response): 675 of 690 frames carried the name.

## Oracle — TDBU has TWO rails, each with its own position notify
- **Rail A** = handle **0x0021**, UUID `42b44499-24ff-f5a8-b34d-e1e99cedc1eb`. Full range
  confirmed 0x00–0x64 (0–100 %). Streams ~4 Hz during travel. Primary oracle.
- **Rail B** = handle **0x0089**, UUID (see char table). Observed 0x45–0x63 (69–99). Second
  rail's position. Moved independently of Rail A → confirms two-rail TDBU.
- Handle 0x002d (UUID `74a2f2aa-...`) = narrow 0x44–0x47, tracks loosely with activity —
  likely a status/target byte, NOT a position readout. Low priority.
- Camera fallback: not needed — two BLE position oracles present.

## Command characteristics (allowlist — all custom 128-bit UUIDs, no readable names)
| handle | UUID | props | verified role |
|--------|------|-------|---------------|
| 0x001d | 91863ab6-6cbe-d846-97c2-88401065025b | write | auth token + direction byte |
| 0x0085 | 7e8d2380-075d-9faf-8741-d42f1d5227bb | write | trigger/commit (always 0x12) |
| 0x0021 | 42b44499-24ff-f5a8-b34d-e1e99cedc1eb | notify | POSITION ORACLE (read-only) |

## Command payloads
### Confirmed (full-sweep evidence, multiple samples)
| purpose | handle | payload | evidence |
|---------|--------|---------|----------|
| auth        | 0x001d | REDACTED | ASCII "REDACTED", written right after every connect |
| Rail A close | 0x001d | 13 (+0x0085←12) | Rail A oracle 99→0, full sweep |
| Rail A open  | 0x001d | 12 (+0x0085←12) | Rail A oracle 0→100, full sweep |

### Rail B (middle rail) GOTO-POSITION — confirmed, 5 consistent samples
| purpose | writes (in order) | effect |
|---------|-------------------|--------|
| goto % (Rail B) | 0x008c ← \<target\> ; then 0x0085 ← 14 | oracle 0x0089 converges to \<target\> |

**Handle 0x008c = Rail B target position byte (0–100 decimal).** 0x0085←0x14 is the Rail-B
execute trigger (vs 0x0085←0x12 which executes Rail A). Confirmed: 0x54→84, 0x4f→79, 0x53→83,
0x5d→93 (hex target = decimal resulting position).

| purpose | write | effect | samples |
|---------|-------|--------|---------|
| STOP (Rail B) | 0x001d ← 10 | halted Rail B mid-travel (76→75, stopped) | 1 |

### Hypotheses still under-sampled (do NOT replay yet)
| purpose | writes | effect | note |
|---------|--------|--------|------|
| close both? | 0x001d←16 | Rail A 99→0 AND Rail B 99→69 | one opcode moved both rails (session6, 1 sample) |
| Rail B up (alt) | 0x008c←05, 0x0024←05, 0x0085←18 | Rail B 70→74 | session6; execute code 0x18 differs from 0x14 seen here — reconcile |

> Direction anchored on Rail A: 0x001d 0x13=close(→0), 0x12=open(→100), execute 0x0085←0x12.
> Rail B is goto-target: position byte on 0x008c, execute 0x0085←0x14. STOP = 0x001d←0x10.

> NOTE (public repo): per-device auth tokens are REDACTED. Each blind has its own 7-digit
> token; capture yours by sniffing the app driving that blind (see README / harness).

## Multi-blind — 3 target TDBU blinds (all structurally identical GATT, per-device auth token)
Protocol is identical across all three (verified: same 67 chars, same UUIDs, same handles,
same commands/presets). ONLY the auth token differs per blind. Tokens (ASCII, write to 0x001d):
| blind | MAC | token (ASCII) | token (hex) |
|-------|-----|---------------|-------------|
| RRBZ_DD0E60 | 14:2D:41:DD:0E:60 | REDACTED | REDACTED |
| RRBZ_DD0EE7 | 14:2D:41:DD:0E:E7 | REDACTED | REDACTED |
| RRBZ_DD0E5C | 14:2D:41:DD:0E:5C | REDACTED | REDACTED |
Confirmed per-device: 0E60's token acknowledged-but-ignored by 0EE7; 0EE7 uses a different token.
(Far blinds 173F, 6A845C are NOT ours — do not target.)

## ✅ v1 — TWO-STATE PRESET CONTROL CONFIRMED (2026-07-27)
The only two states this blind is used in map perfectly onto the 0x14 coupling defaults, so
each is a SINGLE confirmed command. No move-both opcode needed. Both verified on hardware:

| Preset | Bottom(A) | Middle(B) | Command (--burst) |
|--------|-----------|-----------|-------------------|
| CLOSED | 50 | 100 | auth ; 0x0024←32 ; 0x001d←14   (A→50, B auto-defaults 100) |
| OPEN   | 0  | 50  | auth ; 0x008c←32 ; 0x0085←14   (B→50, A auto-defaults 0)  |

harness commands:
- CLOSED: `map-batch <MAC> --payload 29:REDACTED --payload 36:32 --payload 29:14 --burst`
- OPEN:   `map-batch <MAC> --payload 29:REDACTED --payload 140:32 --payload 133:14 --burst`
(50 = 0x32; tune the middle/bottom target byte to taste.)

## ✅ PHONE-LESS CONTROL CONFIRMED (2026-07-27)
Commanded Rail B from the PC (bleak, no phone) with:
`map-batch 14:2D:41:DD:0E:60 --payload 29:REDACTED --payload 140:58 --payload 133:14 --burst`
Blind moved 93 → 88, verified independently by the sniffer (advertising byte3 and oracle 0x0089
both read 0x58=88). Link unencrypted, no bonding. Auth token required per connection.

Key gotchas that made it work:
- **--burst is mandatory** for goto: target (0x008c) and execute (0x0085←0x14) must be sent
  back-to-back. A settle between them neutralises the command (motor latches target at execute).
- **bleak handle offset**: bleak keys chars by DECLARATION handle = (ATT value handle − 1).
  Write by resolving the value handle → char object (GattSession._resolve handles this).
- **Passive position oracle**: the blind broadcasts position in advertising manufacturer data
  byte3 (`44 CC 00 PP 00 ce 14 56`, PP = 0–100). No connection needed just to READ position.
- bleak could not subscribe to the notify oracle (Access-Denied class, like Service Changed),
  so confirm movement via the sniffer / advertising byte3, not bleak notifications.

## Rail A goto — SOLVED (2026-07-27), with a critical caveat
- **Rail A target register = 0x0024** (0–100). Confirmed: wrote 0x0024=20 → Rail A moved 0→20.
- **Position is broadcast passively**: adv manuf data `[status] [ctr] [RailA%] [RailB%] 00 ce 14 56`
  — **byte2 = Rail A, byte3 = Rail B**. Read either rail with no connection.
- **The 0x14 execute HANDLE selects which rail honors its target; the OTHER rail is forced to
  a fixed default (Rail A→0, Rail B→100).** Fits ALL 5 tests:
  - `0x0085 ← 14` → Rail B to 0x008c target, **Rail A → 0**.
  - `0x001d ← 14` → Rail A to 0x0024 target, **Rail B → 100**.
- Setting both target registers does NOT hold both — the non-selected rail still snaps to its
  default (event3: set both, B ignored 70→100; final: set both, A ignored 30→0).

### Single-rail goto (with 0x14) — the other rail WILL move to its default
```
0x001d ← REDACTED ; 0x0024 ← <A%> ; 0x001d ← 14   # A→target, B→100
0x001d ← REDACTED ; 0x008c ← <B%> ; 0x0085 ← 14   # B→target, A→0
```  (--burst)

> STILL UNKNOWN: how to position BOTH rails independently in one shot. 0x14 can't. Session6
> showed execute values 0x16 and 0x18 that appeared to move both rails — likely the "move both
> to their targets" opcode. Need a clean capture of the app setting both rails to different
> non-default positions to confirm 0x16/0x18 semantics.

### Table of 0x0085 execute values seen (command/opcode byte)
- 0x12 = Rail A open/close direction execute (continuous, with 0x001d direction byte)
- 0x14 = goto selected rail to target (other rail → default)
- 0x16, 0x18 = move-both variants (UNCONFIRMED)

## Next captures needed to finish the map
1. **Isolated Rail B only**, repeated 2–3×, nothing else — to lock 0x0085←18 + the 0x0024/0x008c
   setup and confirm it's STATIC.
2. **A goto-% / set-position action** (drag to a specific %) — to find whether a target byte
   exists and where. None captured yet.
3. **Stop mid-travel** — to isolate the stop opcode (0x14 is a candidate).

## Denylisted (do NOT write)
| handle | UUID | name | why |
|--------|------|------|-----|

## Open questions / next experiments
-
