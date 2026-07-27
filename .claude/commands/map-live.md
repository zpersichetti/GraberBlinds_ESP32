Analyze the current BLE sniff session and update the protocol map.

Steps:
1. Run `python -m harness sniff analyze` and read the JSON.
2. First check `security`: if `saw_pairing_smp` or `saw_encryption_setup` is true, STOP and
   tell me the link is encrypted — we need to capture a fresh pairing from the start
   (I unbond in the app, then re-pair while `sniff live` is running). Do not try to
   interpret ATT payloads as commands in that case.
3. If unencrypted, go through each action in `actions`:
   - Report: label -> handle(s) -> payload(s) -> verdict (STATIC / VARYING / single sample).
   - For STATIC actions, that (handle, payload) is a confirmed replayable command.
   - For VARYING, flag it — likely a rolling counter or encryption; do not add to the
     replay set.
   - For single-sample, tell me to repeat the action so we can classify it.
4. Look at NOTIFY records in `data/sniff/live.jsonl`: if a characteristic reports changing
   values that track blind position, call it out as the feedback oracle candidate and note
   its handle — we may not need the camera.
5. Update `notes/protocol.md`: fill the command table (purpose / handle / payload), the
   oracle section, and move any config/DFU-looking handles into the denylist section.
6. End with the concrete next step: which handle to `safety allow` and which payload to
   replay first via `map-batch` to prove phone-less control — but do NOT run any transmit
   command yourself; wait for my go-ahead per CLAUDE.md.
