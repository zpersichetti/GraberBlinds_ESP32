"""Camera oracle.

The *primary* oracle should be a BLE notify characteristic if the motor exposes position
feedback (bidirectional Brel/Motionblinds usually do). The camera is the fallback / cross
-check. Nothing here overpromises: position estimation requires calibration (an ROI plus an
'open' and 'closed' reference frame). Without calibration, `estimate_position` returns None
and you rely on the saved frame (Claude vision can judge it) plus settle detection.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import cv2
import numpy as np


def _open(source: str | int) -> cv2.VideoCapture:
    """source: webcam index (int-like string) or an RTSP/HTTP URL (UniFi Protect)."""
    if isinstance(source, str) and source.isdigit():
        source = int(source)
    cap = cv2.VideoCapture(source)
    if not cap.isOpened():
        raise RuntimeError(f"Could not open camera source: {source!r}")
    return cap


def grab(source: str | int, warmup: int = 3) -> np.ndarray:
    """Grab a single frame, discarding a few for exposure/keyframe settling."""
    cap = _open(source)
    try:
        frame = None
        for _ in range(max(1, warmup)):
            ok, frame = cap.read()
            if not ok:
                raise RuntimeError("Frame read failed")
        return frame
    finally:
        cap.release()


def save_frame(frame: np.ndarray, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    cv2.imwrite(str(path), frame)
    return path


def _mae(a: np.ndarray, b: np.ndarray) -> float:
    a = cv2.cvtColor(a, cv2.COLOR_BGR2GRAY).astype(np.float32)
    b = cv2.cvtColor(b, cv2.COLOR_BGR2GRAY).astype(np.float32)
    if a.shape != b.shape:
        b = cv2.resize(b, (a.shape[1], a.shape[0]))
    return float(np.mean(np.abs(a - b)))


def wait_for_settle(source: str | int, poll: float = 0.4, mae_thresh: float = 2.0,
                    stable_needed: int = 3, timeout: float = 30.0) -> dict:
    """Block until consecutive frames stop changing (motor stopped moving)."""
    cap = _open(source)
    try:
        ok, prev = cap.read()
        if not ok:
            raise RuntimeError("Frame read failed")
        stable = 0
        t0 = time.time()
        last_mae = None
        while time.time() - t0 < timeout:
            time.sleep(poll)
            ok, cur = cap.read()
            if not ok:
                continue
            last_mae = _mae(prev, cur)
            prev = cur
            stable = stable + 1 if last_mae < mae_thresh else 0
            if stable >= stable_needed:
                return {"settled": True, "elapsed": time.time() - t0, "last_mae": last_mae}
        return {"settled": False, "elapsed": time.time() - t0, "last_mae": last_mae}
    finally:
        cap.release()


# ------------------------------------------------------------------- calibration
def _cal_path(data_dir: Path) -> Path:
    return data_dir / "camera_calibration.json"


def save_calibration(data_dir: Path, source: str | int, roi: tuple[int, int, int, int],
                     which: str) -> dict:
    """Capture an 'open' or 'closed' reference frame + ROI. Call once for each."""
    assert which in {"open", "closed"}
    frame = grab(source)
    ref_path = data_dir / f"ref_{which}.png"
    save_frame(frame, ref_path)
    cal_file = _cal_path(data_dir)
    cal = json.loads(cal_file.read_text()) if cal_file.exists() else {}
    cal["roi"] = list(roi)
    cal[f"ref_{which}"] = str(ref_path)
    cal_file.write_text(json.dumps(cal, indent=2))
    return cal


def _crop(frame: np.ndarray, roi) -> np.ndarray:
    x, y, w, h = roi
    return frame[y:y + h, x:x + w]


def estimate_position(data_dir: Path, frame: np.ndarray) -> float | None:
    """0 = fully open, 100 = fully closed, via distance to the two reference frames.

    Returns None if calibration is missing — caller should defer to the saved frame /
    the BLE notify oracle instead.
    """
    cal_file = _cal_path(data_dir)
    if not cal_file.exists():
        return None
    cal = json.loads(cal_file.read_text())
    if not all(k in cal for k in ("roi", "ref_open", "ref_closed")):
        return None
    roi = cal["roi"]
    ref_open = cv2.imread(cal["ref_open"])
    ref_closed = cv2.imread(cal["ref_closed"])
    cur = _crop(frame, roi)
    d_open = _mae(cur, _crop(ref_open, roi))
    d_closed = _mae(cur, _crop(ref_closed, roi))
    if d_open + d_closed == 0:
        return 0.0
    return round(100.0 * d_open / (d_open + d_closed), 1)
