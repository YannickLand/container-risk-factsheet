"""
Tests for api/utils.py — parse_overrides() and pretty_json_response().
"""

from __future__ import annotations
import io
import json

import pytest
from werkzeug.datastructures import FileStorage, ImmutableMultiDict
from werkzeug.test import EnvironBuilder

from api.utils import parse_overrides, pretty_json_response


# ---------------------------------------------------------------------------
# Helpers — build minimal Flask Request objects
# ---------------------------------------------------------------------------

def _form_request(overrides_value: str):
    """Simulate a request where overrides is sent as a plain form string."""
    from flask import Flask, Request

    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="POST",
        data={"overrides": overrides_value},
        content_type="multipart/form-data",
    ):
        from flask import request as flask_req
        return flask_req._get_current_object()  # pyright: ignore[reportAttributeAccessIssue]


def _file_request(content: bytes, filename: str = "overrides.conf"):
    """Simulate a request where overrides is sent as a file upload."""
    from flask import Flask

    app = Flask(__name__)
    storage = FileStorage(
        stream=io.BytesIO(content),
        filename=filename,
        name="overrides",
    )
    with app.test_request_context(
        "/",
        method="POST",
        data={"overrides": storage},
        content_type="multipart/form-data",
    ):
        from flask import request as flask_req
        return flask_req._get_current_object()  # pyright: ignore[reportAttributeAccessIssue]


def _empty_request():
    """Simulate a request with no overrides field at all."""
    from flask import Flask

    app = Flask(__name__)
    with app.test_request_context("/", method="POST", data={}, content_type="multipart/form-data"):
        from flask import request as flask_req
        return flask_req._get_current_object()  # pyright: ignore[reportAttributeAccessIssue]


# ---------------------------------------------------------------------------
# No overrides
# ---------------------------------------------------------------------------

def test_no_overrides_returns_empty():
    req = _empty_request()
    result, err = parse_overrides(req)
    assert result == {}
    assert err is None


def test_empty_string_returns_empty():
    req = _form_request("")
    result, err = parse_overrides(req)
    assert result == {}
    assert err is None


def test_whitespace_only_returns_empty():
    req = _form_request("   \n  ")
    result, err = parse_overrides(req)
    assert result == {}
    assert err is None


# ---------------------------------------------------------------------------
# Inline JSON via form field
# ---------------------------------------------------------------------------

def test_inline_json_object():
    req = _form_request('{"NET": "Satisfied", "IMG": "Dissatisfied"}')
    result, err = parse_overrides(req)
    assert err is None
    assert result == {"NET": "Satisfied", "IMG": "Dissatisfied"}


def test_inline_json_invalid_returns_error():
    req = _form_request('{"bad json":}')
    result, err = parse_overrides(req)
    assert result == {}
    assert err is not None
    assert "overrides" in err.lower() or "json" in err.lower()


# ---------------------------------------------------------------------------
# Conf format via form field
# ---------------------------------------------------------------------------

def test_conf_format_basic():
    conf = "IMG=Satisfied\nRTS=Dissatisfied\n"
    req = _form_request(conf)
    result, err = parse_overrides(req)
    assert err is None
    assert result == {"IMG": "Satisfied", "RTS": "Dissatisfied"}


def test_conf_format_ignores_comments_and_blanks():
    conf = "# comment\n\nNET=Satisfied\n# another\nAUTH=Unknown\n"
    req = _form_request(conf)
    result, err = parse_overrides(req)
    assert err is None
    assert result == {"NET": "Satisfied", "AUTH": "Unknown"}


def test_conf_format_strips_whitespace():
    conf = " IMG = Satisfied \n RTS = Dissatisfied \n"
    req = _form_request(conf)
    result, err = parse_overrides(req)
    assert err is None
    assert result == {"IMG": "Satisfied", "RTS": "Dissatisfied"}


def test_conf_format_skips_lines_without_equals():
    conf = "IMG=Satisfied\nno_equals_here\nRTS=Unknown\n"
    req = _form_request(conf)
    result, err = parse_overrides(req)
    assert err is None
    assert "IMG" in result
    assert "RTS" in result
    assert "no_equals_here" not in result


# ---------------------------------------------------------------------------
# File upload path
# ---------------------------------------------------------------------------

def test_file_upload_conf():
    content = b"NET=Satisfied\nIMG=Satisfied\n"
    req = _file_request(content, filename="assumptions.conf")
    result, err = parse_overrides(req)
    assert err is None
    assert result == {"NET": "Satisfied", "IMG": "Satisfied"}


def test_file_upload_json():
    content = json.dumps({"NET": "Satisfied"}).encode()
    req = _file_request(content, filename="overrides.json")
    result, err = parse_overrides(req)
    assert err is None
    assert result == {"NET": "Satisfied"}


def test_file_upload_empty():
    req = _file_request(b"", filename="empty.conf")
    result, err = parse_overrides(req)
    assert result == {}
    assert err is None


def test_file_upload_conf_with_comments():
    content = b"# Full hardened scenario\nIMG=Satisfied\n# network\nNET=Satisfied\n"
    req = _file_request(content, filename="assumptions.conf")
    result, err = parse_overrides(req)
    assert err is None
    assert result == {"IMG": "Satisfied", "NET": "Satisfied"}


# ---------------------------------------------------------------------------
# pretty_json_response
# ---------------------------------------------------------------------------

def test_pretty_json_response_default_200():
    from flask import Flask
    app = Flask(__name__)
    with app.app_context():
        resp = pretty_json_response({"ok": True})
    assert resp.status_code == 200
    assert resp.content_type == "application/json"
    data = json.loads(resp.get_data(as_text=True))
    assert data == {"ok": True}


def test_pretty_json_response_custom_status():
    from flask import Flask
    app = Flask(__name__)
    with app.app_context():
        resp = pretty_json_response({"error": "bad"}, 400)
    assert resp.status_code == 400
