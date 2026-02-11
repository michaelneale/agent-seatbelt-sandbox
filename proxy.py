#!/usr/bin/env python3
"""
Transparent CONNECT proxy with logging and live kill-switch.

Default: allow everything through, log all connections.
Drop a domain into blocked.txt (one per line) to block it in real time.
The proxy re-reads blocked.txt on every connection, so edits take effect immediately.

Usage:
    python3 proxy.py [--port 18080] [--blocked blocked.txt] [--log connections.log]
"""

import argparse
import datetime
import io
import json
import os
import select
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from pathlib import Path
from typing import Optional, Set


def load_blocked(path: Path) -> Set[str]:
    """Load blocked domains from file. Returns empty set if file doesn't exist."""
    if not path.exists():
        return set()
    lines = path.read_text().splitlines()
    return {line.strip().lower() for line in lines if line.strip() and not line.startswith("#")}


def matches_blocked(host: str, blocked: set[str]) -> bool:
    """Check if host matches any blocked domain (exact or wildcard suffix)."""
    host = host.lower()
    if host in blocked:
        return True
    # Check wildcard: if "evil.com" is blocked, also block "sub.evil.com"
    parts = host.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in blocked:
            return True
    return False


class TTLCache:
    """Thread-safe in-memory cache with per-entry TTL."""

    def __init__(self, ttl_seconds: int = 3600):
        self.ttl = ttl_seconds
        self._cache: dict[str, tuple[bool, float]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[bool]:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            value, ts = entry
            if time.monotonic() - ts > self.ttl:
                del self._cache[key]
                return None
            return value

    def put(self, key: str, value: bool):
        with self._lock:
            self._cache[key] = (value, time.monotonic())


def evaluate_ld_flag(client_id: str, username: str, domain: str) -> Optional[dict]:
    """Call LD client-side evalx API. Returns flag dict with value/variation/version, or None on error."""
    url = f"https://clientsdk.launchdarkly.com/sdk/evalx/{client_id}/context"
    context = {
        "kind": "user",
        "key": domain,
        "username": username,
    }
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(context).encode("utf-8"),
            method="REPORT",
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=5)
        flags = json.loads(resp.read())
        flag = flags.get("egress-allowlist")
        if flag is None or "value" not in flag:
            return None
        return flag
    except Exception:
        return None


def send_ld_event(client_id: str, username: str, domain: str, flag: dict):
    """Send index + summary events to LD analytics (fire-and-forget in background thread)."""
    def _send():
        import uuid
        url = f"https://events.launchdarkly.com/events/bulk/{client_id}"
        ts = int(time.time() * 1000)
        events = [
            {
                "kind": "index",
                "creationDate": ts,
                "context": {
                    "kind": "user",
                    "key": domain,
                    "username": username,
                },
            },
            {
                "kind": "summary",
                "startDate": ts - 60000,
                "endDate": ts,
                "features": {
                    "egress-allowlist": {
                        "default": False,
                        "contextKinds": ["user"],
                        "counters": [
                            {
                                "variation": flag.get("variation"),
                                "version": flag.get("version", flag.get("flagVersion")),
                                "value": flag.get("value"),
                                "count": 1,
                            }
                        ],
                    }
                },
            },
        ]
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(events).encode("utf-8"),
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-LaunchDarkly-Event-Schema": "4",
                    "X-LaunchDarkly-Payload-ID": str(uuid.uuid4()),
                },
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass  # fire-and-forget
    t = threading.Thread(target=_send, daemon=True)
    t.start()


def timestamp() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


class ProxyHandler(BaseHTTPRequestHandler):
    """HTTP CONNECT proxy that logs and optionally blocks by domain."""

    blocked_path = None  # type: Path
    log_file = None      # type: Optional[io.TextIOWrapper]
    ld_client_id = None  # type: Optional[str]
    ld_username = None   # type: Optional[str]
    ld_cache = None      # type: Optional[TTLCache]

    def _log(self, action: str, method: str, target: str, extra: str = ""):
        ts = timestamp()
        line = f"[{ts}] {action:7s} {method:7s} {target}"
        if extra:
            line += f"  ({extra})"

        # Terminal output with color
        colors = {
            "ALLOW":  "\033[32m",   # green
            "BLOCK":  "\033[31m",   # red
            "ERROR":  "\033[33m",   # yellow
            "LD:OK":  "\033[36m",   # cyan
            "LD:BLK": "\033[31m",   # red
            "LD:HIT": "\033[34m",   # blue
            "LD:ERR": "\033[33m",   # yellow
        }
        color = colors.get(action, "")
        reset = "\033[0m" if color else ""
        print(f"{color}{line}{reset}", file=sys.stderr, flush=True)

        # File log (no color)
        if self.log_file:
            print(line, file=self.log_file, flush=True)

    def _is_blocked(self, host: str) -> bool:
        # Layer 1: local blocklist (fast, no network)
        blocked = load_blocked(self.blocked_path)
        if matches_blocked(host, blocked):
            return True

        # Layer 2: LaunchDarkly (if configured)
        if self.ld_client_id and self.ld_cache is not None:
            domain = host.lower()
            cached = self.ld_cache.get(domain)
            if cached is not None:
                self._log("LD:HIT", "CACHE", host, "allow" if cached else "deny")
                return not cached  # LD returns true=allow, _is_blocked returns true=block

            flag = evaluate_ld_flag(self.ld_client_id, self.ld_username, domain)
            if flag is not None:
                allowed = flag["value"]
                self.ld_cache.put(domain, allowed)
                action = "LD:OK" if allowed else "LD:BLK"
                self._log(action, "EVAL", host)
                send_ld_event(self.ld_client_id, self.ld_username, domain, flag)
                return not allowed
            else:
                # LD unreachable — default allow
                self._log("LD:ERR", "EVAL", host, "defaulting to allow")
                return False

        return False

    def do_CONNECT(self):
        """Handle HTTPS tunneling via CONNECT method."""
        host, _, port = self.path.partition(":")
        port = port or "443"

        if self._is_blocked(host):
            self._log("BLOCK", "CONNECT", self.path)
            self.send_error(403, f"Blocked by proxy: {host}")
            return

        self._log("ALLOW", "CONNECT", self.path)

        try:
            remote = socket.create_connection((host, int(port)), timeout=15)
        except Exception as e:
            self._log("ERROR", "CONNECT", self.path, str(e))
            self.send_error(502, f"Cannot reach {host}:{port}")
            return

        self.send_response(200, "Connection established")
        self.end_headers()

        # Tunnel bidirectionally
        client_conn = self.connection
        client_conn.setblocking(False)
        remote.setblocking(False)

        try:
            while True:
                readable, _, errs = select.select(
                    [client_conn, remote], [], [client_conn, remote], 60
                )
                if errs or not readable:
                    break
                for sock in readable:
                    other = remote if sock is client_conn else client_conn
                    try:
                        data = sock.recv(65536)
                        if not data:
                            return
                        other.sendall(data)
                    except (BlockingIOError, ConnectionResetError):
                        pass
                    except Exception:
                        return
        finally:
            remote.close()

    def do_GET(self):
        self._proxy_http("GET")

    def do_POST(self):
        self._proxy_http("POST")

    def do_PUT(self):
        self._proxy_http("PUT")

    def do_DELETE(self):
        self._proxy_http("DELETE")

    def do_HEAD(self):
        self._proxy_http("HEAD")

    def _proxy_http(self, method: str):
        """Handle plain HTTP proxy requests (non-CONNECT)."""
        # Extract host from absolute URL
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.path)
            host = parsed.hostname or ""
        except Exception:
            host = ""

        if host and self._is_blocked(host):
            self._log("BLOCK", method, self.path)
            self.send_error(403, f"Blocked by proxy: {host}")
            return

        self._log("ALLOW", method, self.path[:120])

        try:
            # Read request body if present
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length else None

            req = urllib.request.Request(self.path, data=body, method=method)
            # Forward headers (skip hop-by-hop)
            skip = {"host", "proxy-connection", "proxy-authorization", "connection"}
            for key, val in self.headers.items():
                if key.lower() not in skip:
                    req.add_header(key, val)

            resp = urllib.request.urlopen(req, timeout=30)
            self.send_response(resp.status)
            for key, val in resp.headers.items():
                if key.lower() not in ("transfer-encoding",):
                    self.send_header(key, val)
            self.end_headers()
            self.wfile.write(resp.read())
        except urllib.error.HTTPError as e:
            self.send_error(e.code, str(e.reason))
        except Exception as e:
            self._log("ERROR", method, self.path[:120], str(e))
            self.send_error(502, str(e))

    def log_message(self, format, *args):
        pass  # We do our own logging


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle each request in a new thread so CONNECT tunnels don't block new connections."""
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description="Transparent logging proxy with live kill-switch")
    parser.add_argument("--port", type=int, default=18080, help="Listen port (default: 18080)")
    parser.add_argument("--blocked", default="blocked.txt", help="Blocked domains file (default: blocked.txt)")
    parser.add_argument("--log", default=None, help="Log file path (default: stderr only)")
    parser.add_argument("--ld-client-id", default=None,
                        help="LaunchDarkly client-side ID (or set LAUNCHDARKLY_CLIENT_ID)")
    args = parser.parse_args()

    blocked_path = Path(args.blocked).resolve()
    log_file = open(args.log, "a") if args.log else None
    ld_client_id = args.ld_client_id or os.environ.get("LAUNCHDARKLY_CLIENT_ID")
    ld_username = subprocess.check_output(["whoami"]).decode().strip()

    # Inject config into handler class
    ProxyHandler.blocked_path = blocked_path
    ProxyHandler.log_file = log_file
    ProxyHandler.ld_client_id = ld_client_id
    ProxyHandler.ld_username = ld_username
    ProxyHandler.ld_cache = TTLCache(ttl_seconds=3600) if ld_client_id else None

    server = ThreadingHTTPServer(("127.0.0.1", args.port), ProxyHandler)

    print(f"Proxy listening on 127.0.0.1:{args.port}", file=sys.stderr)
    print(f"Blocked domains file: {blocked_path}", file=sys.stderr)
    if blocked_path.exists():
        blocked = load_blocked(blocked_path)
        if blocked:
            print(f"Currently blocked: {', '.join(sorted(blocked))}", file=sys.stderr)
        else:
            print("Blocked file exists but is empty — allowing everything", file=sys.stderr)
    else:
        print("No blocked file — allowing everything (create it to block domains)", file=sys.stderr)
    if ld_client_id:
        print(f"LaunchDarkly: enabled (user={ld_username}, flag=egress-allowlist)", file=sys.stderr)
        print(f"Cache TTL: 3600s", file=sys.stderr)
    else:
        print("LaunchDarkly: not configured (set LAUNCHDARKLY_CLIENT_ID to enable)", file=sys.stderr)
    print("", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down proxy.", file=sys.stderr)
    finally:
        server.server_close()
        if log_file:
            log_file.close()


if __name__ == "__main__":
    main()
