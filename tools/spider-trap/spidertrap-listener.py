#!/usr/bin/env python3
"""Receives spider trap webhook POSTs and canary token callbacks.
Writes structured JSON to log file for Wazuh ingestion."""
import json
import os
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone

LOG_FILE = "/var/log/carefortress-spidertrap.log"

CANARY_PATTERN = re.compile(r'^(repo|int)-([a-zA-Z0-9]+)\.carefortress\.dev$', re.IGNORECASE)

class WebhookHandler(BaseHTTPRequestHandler):

    def _get_canary_match(self):
        host = self.headers.get('Host', '')
        return CANARY_PATTERN.match(host)

    def _log_entry(self, entry):
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()

    def _handle_canary_callback(self, match, method):
        token_type = match.group(1)
        token_id = match.group(2)
        type_map = {"repo": "git_clone", "int": "dns_config"}
        entry = {
            "received_ts": datetime.now(timezone.utc).isoformat(),
            "source": "canary_callback",
            "event_type": "CANARY_TOKEN_TRIGGERED",
            "canary_type": type_map.get(token_type, token_type),
            "token_id": token_id,
            "callback_ip": self.headers.get("CF-Connecting-IP", self.client_address[0]),
            "user_agent": self.headers.get("User-Agent", "unknown"),
            "method": method,
            "path": self.path,
            "host": self.headers.get("Host", ""),
            "country": self.headers.get("CF-IPCountry", "unknown"),
            "ray_id": self.headers.get("CF-Ray", "unknown"),
        }
        self._log_entry(entry)
        if token_type == "repo":
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"fatal: repository not found\n")
        else:
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"connection refused\n")

    def do_GET(self):
        canary = self._get_canary_match()
        if canary:
            self._handle_canary_callback(canary, "GET")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_POST(self):
        canary = self._get_canary_match()
        if canary:
            self._handle_canary_callback(canary, "POST")
            return
        length = int(self.headers.get('Content-Length', 0))
        if length > 65536:
            self.send_response(413)
            self.end_headers()
            return
        body = self.rfile.read(length)
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = {"raw": body.decode(errors="replace")}
        entry = {
            "received_ts": datetime.now(timezone.utc).isoformat(),
            "source": "spidertrap",
            "data": data
        }
        self._log_entry(entry)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    server = HTTPServer(("127.0.0.1", 8088), WebhookHandler)
    print(f"Listening on 127.0.0.1:8088, logging to {LOG_FILE}")
    server.serve_forever()
