#!/usr/bin/env python3

import json
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

# import docker
import requests

WEBHOOK_URL     = os.environ.get("DISCORD_WEBHOOK_URL", "")
PROJECT_NAME    = os.environ.get("PROJECT_NAME", "tatou-2026")
DRY_RUN         = os.environ.get("DRY_RUN", "").lower() in ("1", "true")

# Detection thresholds
BRUTE_WINDOW      = int(os.environ.get("BRUTE_WINDOW",      "60"))
BRUTE_THRESHOLD   = int(os.environ.get("BRUTE_THRESHOLD",   "5"))
UPLOAD_WINDOW     = int(os.environ.get("UPLOAD_WINDOW",     "60"))
UPLOAD_THRESHOLD  = int(os.environ.get("UPLOAD_THRESHOLD",  "3"))
ERROR_WINDOW      = int(os.environ.get("ERROR_WINDOW",      "30"))
ERROR_THRESHOLD   = int(os.environ.get("ERROR_THRESHOLD",   "10"))
ALERT_COOLDOWN    = int(os.environ.get("ALERT_COOLDOWN",    "300"))

# Discord embed colours
RED    = 0xFF4444
ORANGE = 0xFF8C00
YELLOW = 0xFFD700

# ── Sliding-window state ──────────────────────────────────────────────────────
_windows:   dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(deque))
_cooldowns: dict[str, float]            = {}

def _prune(q: deque, window: float, now: float) -> None:
    while q and q[0] < now - window:
        q.popleft()

def _cooldown_ok(key: str, now: float) -> bool:
    if now - _cooldowns.get(key, 0) >= ALERT_COOLDOWN:
        _cooldowns[key] = now
        return True
    return False

# ── Alert dispatch ────────────────────────────────────────────────────────────
def _send(title: str, description: str, color: int, fields: dict) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    print(f"[ALERT] {title} | {description}", flush=True)

    if DRY_RUN:
        return

    if WEBHOOK_URL:
        _discord(title, description, color, fields, ts)

    # if SLACK_URL:
    #     _slack(title, description, fields)


def _discord(title, description, color, fields, ts):
    embed = {
        "title": title,
        "description": description,
        "color": color,
        "fields": [
            {"name": k, "value": f"`{str(v)[:200]}`", "inline": True}
            for k, v in fields.items()
        ],
        "footer": {"text": "Tatou SIEM Monitor"},
        "timestamp": ts,
    }
    try:
        r = requests.post(WEBHOOK_URL, json={"embeds": [embed]}, timeout=5)
        r.raise_for_status()
    except Exception as e:
        print(f"[DISCORD ERROR] {e}", flush=True)


# ── Detection rules ───────────────────────────────────────────────────────────
def _on_login_fail(rec: dict, now: float) -> None:
    ip = rec.get("ip", "unknown")
    q  = _windows["login_fail"][ip]
    q.append(now)
    _prune(q, BRUTE_WINDOW, now)
    print(f"[MONITOR] login_fail ip={ip} count={len(q)}/{BRUTE_THRESHOLD}", flush=True)

    if len(q) >= BRUTE_THRESHOLD and _cooldown_ok(f"brute:{ip}", now):
        _send(
            "Brute Force Failed Login Detected",
            f"**{len(q)} failed logins** from `{ip}` in {BRUTE_WINDOW}s",
            RED,
            {"IP": ip, "Attempts": len(q), "Email targeted": rec.get("email", "N/A")},
        )


def _on_login_ok(rec: dict, now: float) -> None:
    """Alert if a login succeeds shortly after repeated failures — possible credential win."""
    ip = rec.get("ip", "unknown")
    q  = _windows["login_fail"][ip]
    _prune(q, BRUTE_WINDOW * 2, now)

    if len(q) >= 3 and _cooldown_ok(f"success_after_fail:{ip}", now):
        _send(
            "Login Success After Several Failures",
            f"`{ip}` logged in successfully after **{len(q)} prior failures**.\n"
            "Possible successful brute force.",
            RED,
            {"IP": ip, "Prior failures": len(q), "User": rec.get("login", "N/A")},
        )


def _on_upload_reject(rec: dict, now: float) -> None:
    ip     = rec.get("ip", "unknown")
    reason = rec.get("reason", "unknown")
    q      = _windows["upload_reject"][ip]
    q.append(now)
    _prune(q, UPLOAD_WINDOW, now)
    print(f"[MONITOR] upload_reject ip={ip} reason={reason} count={len(q)}/{UPLOAD_THRESHOLD}", flush=True)

    if len(q) >= UPLOAD_THRESHOLD and _cooldown_ok(f"upload:{ip}", now):
        _send(
            "Rejected Upload Activity",
            f"**{len(q)} rejected uploads** from `{ip}` in {UPLOAD_WINDOW}s",
            ORANGE,
            {"IP": ip, "Rejections": len(q), "Last reason": reason},
        )

def _on_delete_document(rec: dict, now: float) -> None:
    user = rec.get("user", "N/A")
    user_name = rec.get("user_name", "N/A")
    ip = rec.get("ip", "unknown")
    doc_id = rec.get("doc_id", "N/A")
    # Optional: alert if someone deletes a document
    if _cooldown_ok("file_deleted: true", now):
        _send(
            "Document Deleted",
            f"User `{user_name}` - `{user}` deleted document ID `{doc_id}` from `{ip}`.",
            YELLOW,
            {"User ID": user, "User Name": user_name, "IP": ip, "Document ID": doc_id},
        )

def _on_unauthorized_access(rec: dict, now: float) -> None:
    status = int(rec.get("status", 0))
    if status in (401, 403):
        ip = rec.get("ip", "unknown")
        q = _windows["unauthorized"][ip]
        q.append(now)
        _prune(q, BRUTE_WINDOW, now)

        if len(q) >= 5 and _cooldown_ok(f"unauth:{ip}", now):
            _send(
                "Excessive Unauthorized Access",
                f"**{len(q)} unauthorized (401/403) requests** from `{ip}` in {BRUTE_WINDOW}s",
                ORANGE,
                {"IP": ip, "Count": len(q), "Last Path": rec.get("path", "N/A")}
)

def _on_wm_read_fail(rec: dict, now: float) -> None:
    user = rec.get("user", "N/A")
    ip   = rec.get("ip",   "unknown")
    print(f"[MONITOR] wm_read_fail user={user}", flush=True)

    if _cooldown_ok(f"wm_fail:{user}", now):
        _send(
            "Watermark Read Failure",
            "A watermark read attempt failed — possible tampered document or method probing.",
            YELLOW,
            {"User ID": user, "IP": ip,
             "Method": rec.get("method", "N/A"),
             "Error": str(rec.get("error", "N/A"))[:120]},
        )


def _on_http_access(rec: dict, now: float) -> None:
    """Handle http_access logs: sensitive endpoint access notifications and error storm detection."""
    try:
        status = int(rec.get("status", 0))
    except (TypeError, ValueError):
        status = 0

    ip = rec.get("ip") or rec.get("remote_addr") or "unknown"
    path = rec.get("path", "")

    # 1. Sensitive Endpoint Notifications (Successful requests: status < 400)
    if path.startswith("/api/rmap") and status < 400:
        if _cooldown_ok(f"rmap:{ip}:{path}", now):
            _send(
                "Rmap Accessed",
                f"Accessed Rmap `{path}` from `{ip}`.",
                YELLOW,
                {"IP": ip, "Rmap Path": path},
            )
        return

    if path.startswith("/api/delete-document/") and status < 400:
        user = rec.get("user", "N/A")
        user_name = rec.get("user_name", "N/A")
        doc_id = path.rstrip("/").split("/")[-1]

        if _cooldown_ok(f"delete_doc:{user}:{doc_id}", now):
            _send(
                "Document Deleted",
                f"User `{user_name}` (ID: `{user}`) deleted document ID `{doc_id}` from `{ip}`.",
                YELLOW,
                {"User ID": user, "User Name": user_name, "IP": ip, "Document ID": doc_id},
            )
        return

    # 2. HTTP Error Storm / Scanning Detection (status >= 400)
    if status >= 400:
        q = _windows["errors"][ip]
        q.append(now)
        _prune(q, ERROR_WINDOW, now)

        if len(q) >= ERROR_THRESHOLD and _cooldown_ok(f"errors:{ip}", now):
            _send(
                "Possible Scanning Detected",
                f"**{len(q)} HTTP errors** from `{ip}` in {ERROR_WINDOW}s",
                ORANGE,
                {"IP": ip, "Errors": len(q),
                 "Last path": path,
                 "Last status": status},
            )



HANDLERS = {
    "login_fail":    _on_login_fail,
    "login_ok":      _on_login_ok,
    "upload_reject": _on_upload_reject,
    "wm_read_fail":  _on_wm_read_fail,
    "http_access":   _on_http_access,
    "delete_doc":    _on_delete_document,
    "unauth":        _on_unauthorized_access,
}

# File-based Log Reader
LOG_FILE_PATH = os.environ.get("LOG_FILE_PATH", "/app/storage/server.log")

def process_line(raw: str) -> None:
    raw = raw.strip()
    if not raw.startswith("{"):
        return
    try:
        rec = json.loads(raw)
    except json.JSONDecodeError:
        return
    handler = HANDLERS.get(rec.get("msg", ""))
    if handler:
        handler(rec, time.time())


def tail_log_file(filepath: str) -> None:
    """Continuously tail server.log like 'tail -f'."""
    while not os.path.exists(filepath):
        print(f"[MONITOR] Waiting for log file at {filepath}...", flush=True)
        time.sleep(3)

    print(f"[MONITOR] Tailing log stream at {filepath}", flush=True)

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        # Move to the end of existing logs on startup so old logs aren't re-processed
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if line:
                process_line(line)
            else:
                # No new line yet, pause briefly before checking again
                time.sleep(0.5)


def run() -> None:
    print(f"[MONITOR] Starting Tatou SIEM Engine — project={PROJECT_NAME}", flush=True)
    #print(f"[MONITOR] GitHub Pages: {'✅ enabled' if (GITHUB_TOKEN and GITHUB_REPO) else '❌ disabled'}", flush=True)
    #print(f"[MONITOR] Telegram:     {'✅ enabled' if (TELEGRAM_TOKEN and TELEGRAM_CHAT) else '❌ disabled'}", flush=True)
    print(f"[MONITOR] Discord webhook: {'configured' if WEBHOOK_URL else 'NOT SET'}", flush=True)
    if DRY_RUN:
        print("[MONITOR] DRY_RUN=1 — alerts printed only, not sent", flush=True)


    # Main thread tails the log file continuously
    tail_log_file(LOG_FILE_PATH)


if __name__ == "__main__":
    time.sleep(5)  # Wait for server startup
    run()
