"""The mapping loop: for each candidate payload, record pre-state, write, wait for the
motor to settle, record post-state, and persist a full run record (payloads, notify events,
camera frames, position deltas) so the command->behavior map is fully reconstructable.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from . import capture, safety
from .ble import GattSession


def _run_dir(data_dir: Path) -> Path:
    d = data_dir / "runs" / time.strftime("%Y%m%d-%H%M%S")
    d.mkdir(parents=True, exist_ok=True)
    return d


async def map_batch(
    data_dir: Path,
    address: str,
    payloads: list[tuple[int, bytes]],
    camera: str | int | None,
    notify_uuids: list[str] | None,
    do_pair: bool,
    response: bool = True,
    settle_timeout: float = 30.0,
    burst: bool = False,
) -> dict:
    """Run a batch of (handle, payload) writes in one held-open session.

    Safety: every handle is gated by safety.check BEFORE the session opens. Any DENY aborts
    the whole batch — we do not transmit a partial, unreviewed sequence.

    burst=True sends the whole sequence back-to-back (only ~0.15 s between writes) and does a
    single settle window after the LAST write, capturing all notifications from the first
    write onward. Needed for multi-write commands like goto (target register + execute
    trigger): a motor latches the target only at the execute, so a long dwell between them
    neutralises the command. The default (burst=False) keeps a settle after every write,
    which is right for one-write-at-a-time opcode mapping.
    """
    for handle, _ in payloads:
        verdict, reason = safety.check(data_dir, handle)
        if verdict != "ALLOW":
            raise PermissionError(f"handle {handle}: {verdict} ({reason})")

    rd = _run_dir(data_dir)
    records = []

    async with GattSession(address, notify_uuids=notify_uuids, do_pair=do_pair) as sess:
        for i, (handle, payload) in enumerate(payloads):
            step = rd / f"{i:03d}"
            step.mkdir(exist_ok=True)

            # pre-state
            pre_frame_path = None
            pre_pos = None
            if camera is not None:
                pf = capture.grab(camera)
                pre_frame_path = capture.save_frame(pf, step / "pre.png")
                pre_pos = capture.estimate_position(data_dir, pf)
            t_write = time.time()

            # transmit
            await sess.write(handle, payload, response=response)

            # settle. In burst mode, only the LAST write gets the full settle; the earlier
            # writes are spaced by a tiny delay so target+execute stay together.
            is_last = i == len(payloads) - 1
            settle = None
            if burst and not is_last:
                time.sleep(0.15)
            elif camera is not None:
                settle = capture.wait_for_settle(camera, timeout=settle_timeout)
            else:
                time.sleep(min(8.0, settle_timeout))

            # post-state
            post_frame_path = None
            post_pos = None
            if camera is not None:
                qf = capture.grab(camera)
                post_frame_path = capture.save_frame(qf, step / "post.png")
                post_pos = capture.estimate_position(data_dir, qf)

            events = sess.events_since(t_write)

            rec = {
                "index": i,
                "handle": handle,
                "payload_hex": payload.hex(),
                "response": response,
                "t_write": t_write,
                "notify_events": events,
                "settle": settle,
                "pre_pos": pre_pos,
                "post_pos": post_pos,
                "pos_delta": (None if pre_pos is None or post_pos is None
                              else round(post_pos - pre_pos, 1)),
                "pre_frame": str(pre_frame_path) if pre_frame_path else None,
                "post_frame": str(post_frame_path) if post_frame_path else None,
            }
            records.append(rec)
            (step / "record.json").write_text(json.dumps(rec, indent=2))

            # append to the master jsonl log
            with (data_dir / "runs" / "log.jsonl").open("a") as fh:
                fh.write(json.dumps({"run": rd.name, **rec}) + "\n")

    summary = {"run": rd.name, "count": len(records), "records": records}
    (rd / "summary.json").write_text(json.dumps(summary, indent=2))
    return summary
