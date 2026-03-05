"""
utils.py — Shared Flask helpers.
"""

from __future__ import annotations
import json
from flask import Response


def pretty_json_response(data, status: int = 200) -> Response:
    """Return a Flask :class:`Response` with pretty-printed JSON body."""
    body = json.dumps(data, indent=2, ensure_ascii=False)
    return Response(body, status=status, mimetype="application/json")
