"""
utils.py — Shared Flask helpers.
"""

from __future__ import annotations
import json
from flask import Request, Response


def pretty_json_response(data, status: int = 200) -> Response:
    """Return a Flask :class:`Response` with pretty-printed JSON body."""
    body = json.dumps(data, indent=2, ensure_ascii=False)
    return Response(body, status=status, mimetype="application/json")


def parse_overrides(request: Request) -> tuple[dict, str | None]:
    """
    Extract assumption-state overrides from a Flask request.

    Checks (in order):
    1. ``request.files["overrides"]`` — an uploaded ``.conf``, ``.ini``, ``.json``,
       or ``.yaml`` file (e.g. ``-F "overrides=@assumptions.conf"``).
    2. ``request.form["overrides"]`` — an inline JSON string
       (e.g. ``-F 'overrides={"NET":"Satisfied"}'``).

    Conf / ini format: ``KEY=Value`` lines; ``#`` comments and blank lines ignored.
    JSON format: ``{"KEY": "Value", ...}``.

    :returns: ``(overrides_dict, error_message)`` — on success the error is ``None``.
    """
    raw: str | None = None

    # --- file upload path ---
    if "overrides" in request.files:
        raw = request.files["overrides"].read().decode("utf-8", errors="replace")
    # --- inline string path ---
    elif "overrides" in request.form:
        raw = request.form["overrides"]

    if not raw or not raw.strip():
        return {}, None

    # Try conf/ini (KEY=Value) — detected by absence of a leading '{' after stripping
    stripped = raw.lstrip()
    if not stripped.startswith("{") and not stripped.startswith("["):
        result: dict[str, str] = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                result[k.strip()] = v.strip()
        return result, None

    # Try JSON
    try:
        return json.loads(raw), None
    except json.JSONDecodeError:
        return {}, (
            "Invalid 'overrides' value: expected a JSON object "
            '(e.g. \'{"NET":"Satisfied"}\') or a KEY=Value .conf file.'
        )
