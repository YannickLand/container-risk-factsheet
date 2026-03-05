"""
api_server.py — Flask REST API for container-risk-factsheet.

Endpoints
---------
GET  /api/v1/health              — liveness check
GET  /api/v1/version             — version info
POST /api/v1/generate-factsheet  — generate factsheet (multipart: compose_file)
POST /api/v1/extract-traits      — extract traits only (multipart: compose_file)
"""

from __future__ import annotations
import time

from flask import Blueprint, Flask, request
from flask_cors import CORS

from api.config import FLASK_CONFIG, LOGGING_CONFIG
from api.factsheet_service import (
    generate_factsheet_from_upload,
)
from api.logger import log_factsheet_generation, log_request_info, setup_logger
from api.utils import pretty_json_response
from api.versioning import API_VERSION, get_version_info

logger = setup_logger("api")

# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------

api_v1 = Blueprint("api_v1", __name__, url_prefix="/api/v1")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@api_v1.route("/health", methods=["GET"])
def health():
    """Liveness check."""
    return pretty_json_response({"status": "ok"})


@api_v1.route("/version", methods=["GET"])
def version():
    """Return API version details."""
    return pretty_json_response(get_version_info())


@api_v1.route("/generate-factsheet", methods=["POST"])
def generate_factsheet_endpoint():
    """
    Generate a security factsheet from an uploaded Docker Compose file.

    Request (multipart/form-data):
      - compose_file: The docker-compose.yml file (required)
      - overrides:    JSON string with assumption-state overrides (optional)
                      e.g. {"NET_1": "Satisfied", "AUTH_2": "Dissatisfied"}

    Response (application/json):
      - Per-service factsheet dict.
    """
    log_request_info(logger, request)

    if "compose_file" not in request.files:
        return pretty_json_response(
            {"error": "Missing 'compose_file' in multipart form data."}, 400
        )

    file = request.files["compose_file"]
    content: bytes = file.read()
    if not content:
        return pretty_json_response({"error": "Uploaded file is empty."}, 400)

    # Optional overrides
    overrides: dict = {}
    overrides_raw = request.form.get("overrides")
    if overrides_raw:
        import json as _json
        try:
            overrides = _json.loads(overrides_raw)
        except Exception:
            return pretty_json_response(
                {"error": "Invalid JSON in 'overrides' field."}, 400
            )

    t0 = time.perf_counter()
    try:
        factsheet = generate_factsheet_from_upload(content, overrides=overrides)
    except ValueError as exc:
        return pretty_json_response({"error": str(exc)}, 400)
    except Exception as exc:
        logger.exception("Factsheet generation failed")
        return pretty_json_response(
            {"error": f"Factsheet generation failed: {exc}"}, 500
        )

    elapsed_ms = (time.perf_counter() - t0) * 1000
    log_factsheet_generation(logger, len(factsheet), elapsed_ms)
    return pretty_json_response(factsheet)


@api_v1.route("/extract-traits", methods=["POST"])
def extract_traits_endpoint():
    """
    Extract deployment traits from an uploaded Docker Compose file.

    Request (multipart/form-data):
      - compose_file: The docker-compose.yml file (required)

    Response (application/json):
      - {"service_name": [<trait>, ...], ...}
    """
    log_request_info(logger, request)

    if "compose_file" not in request.files:
        return pretty_json_response(
            {"error": "Missing 'compose_file' in multipart form data."}, 400
        )

    file = request.files["compose_file"]
    content: bytes = file.read()
    if not content:
        return pretty_json_response({"error": "Uploaded file is empty."}, 400)

    import io
    import yaml
    from factsheet.compose_normalizer import normalize_compose
    from factsheet.trait_extractor import extract_all_traits

    try:
        compose = yaml.safe_load(io.BytesIO(content))
    except Exception as exc:
        return pretty_json_response({"error": f"Invalid YAML: {exc}"}, 400)

    normalised = normalize_compose(compose)
    traits = extract_all_traits(normalised)
    return pretty_json_response(traits)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app)

    app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True

    app.register_blueprint(api_v1)

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = create_app()
    app.run(
        host=FLASK_CONFIG["HOST"],
        port=FLASK_CONFIG["PORT"],
        debug=FLASK_CONFIG["DEBUG"],
    )
