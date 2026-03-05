"""
backend_server.py — Lightweight internal HTTP backend.

This process is called by the API container.  It runs in a separate container
on port 8000 (not exposed externally) and provides direct Python-level access
to the factsheet generation pipeline, avoiding process-fork overhead.

Endpoints
---------
GET  /health              — liveness
POST /generate-factsheet  — JSON body: {"compose": {...}, "overrides": {...}}
"""

from __future__ import annotations
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

# Ensure project root is on the path when running directly
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from factsheet.factsheet_generator import generate_factsheet
from backend.logger import setup_logger

logger = setup_logger("backend")

HOST = os.getenv("BACKEND_HOST", "0.0.0.0")
PORT = int(os.getenv("BACKEND_PORT", "8000"))
DATA_DIR = os.getenv(
    "DATA_DIR",
    os.path.join(os.path.dirname(__file__), "..", "data"),
)


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        logger.info(fmt, *args)

    def _send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    # ------------------------------------------------------------------
    def do_GET(self):
        if self.path == "/health":
            self._send_json({"status": "ok"})
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        if self.path == "/generate-factsheet":
            self._handle_generate()
        else:
            self._send_json({"error": "Not found"}, 404)

    # ------------------------------------------------------------------
    def _handle_generate(self):
        try:
            body = self._read_json_body()
        except Exception as exc:
            self._send_json({"error": f"Invalid JSON body: {exc}"}, 400)
            return

        compose = body.get("compose")
        overrides = body.get("overrides") or {}

        if not isinstance(compose, dict) or "services" not in compose:
            self._send_json(
                {"error": "Missing or invalid 'compose' key in request body."}, 400
            )
            return

        t0 = time.perf_counter()
        try:
            factsheet = generate_factsheet(compose, overrides=overrides, data_dir=DATA_DIR)
        except Exception as exc:
            logger.exception("Factsheet generation error")
            self._send_json({"error": str(exc)}, 500)
            return

        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.info(
            "Generated factsheet  services=%d  duration_ms=%.1f",
            len(factsheet),
            elapsed_ms,
        )
        self._send_json(factsheet)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run() -> None:
    server = HTTPServer((HOST, PORT), RequestHandler)
    logger.info("Backend listening on %s:%d", HOST, PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Backend shutting down")


if __name__ == "__main__":
    run()
