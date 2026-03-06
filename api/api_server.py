"""
api_server.py — Flask REST API for container-risk-factsheet.

Endpoints
---------
GET  /api/v1/health                    — liveness check
GET  /api/v1/version                   — version info
POST /api/v1/generate-factsheet        — generate factsheet (multipart: compose_file)
POST /api/v1/extract-traits            — extract traits only (multipart: compose_file)
POST /api/v1/generate-treatment-report — generate risk treatment report (multipart: compose_file)
"""

from __future__ import annotations
import time

from flasgger import Swagger, swag_from
from flask import Blueprint, Flask, request
from flask_cors import CORS

from api.config import FLASK_CONFIG, LOGGING_CONFIG
from api.factsheet_service import (
    generate_factsheet_from_upload,
    generate_treatment_report_from_upload,
)
from api.logger import log_factsheet_generation, log_request_info, setup_logger
from api.utils import parse_overrides, pretty_json_response
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
@swag_from("swagger_specs/health.yml")
def health():
    """Liveness check."""
    return pretty_json_response({"status": "ok"})


@api_v1.route("/version", methods=["GET"])
@swag_from("swagger_specs/version.yml")
def version():
    """Return API version details."""
    return pretty_json_response(get_version_info())


@api_v1.route("/generate-factsheet", methods=["POST"])
@swag_from("swagger_specs/generate_factsheet.yml")
def generate_factsheet_endpoint():
    """
    Generate a security factsheet from an uploaded Docker Compose file.

    Request (multipart/form-data):
      - compose_file:  The docker-compose.yml file (required)
      - overrides:     JSON string with assumption-state overrides (optional)
                       e.g. {"NET-1": "Satisfied", "IMG": "Satisfied"}
      - dockerfile_0:  Dockerfile for the first service (optional)
      - dockerfile_1:  Dockerfile for the second service (optional)
      - ...

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

    # Optional overrides (JSON string or uploaded .conf/.json/.yaml file)
    overrides, ov_err = parse_overrides(request)
    if ov_err:
        return pretty_json_response({"error": ov_err}, 400)

    # Optional Dockerfiles (dockerfile_0, dockerfile_1, ...)
    dockerfiles: list[str] = []
    i = 0
    while f"dockerfile_{i}" in request.files:
        df_bytes = request.files[f"dockerfile_{i}"].read()
        if df_bytes:
            dockerfiles.append(df_bytes.decode("utf-8", errors="replace"))
        i += 1

    t0 = time.perf_counter()
    try:
        factsheet = generate_factsheet_from_upload(
            content, overrides=overrides, dockerfiles=dockerfiles or None
        )
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
@swag_from("swagger_specs/extract_traits.yml")
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


@api_v1.route("/generate-treatment-report", methods=["POST"])
@swag_from("swagger_specs/generate_treatment_report.yml")
def generate_treatment_report_endpoint():
    """
    Generate a risk treatment report from an uploaded Docker Compose file.

    Runs the full factsheet pipeline and extracts treatment actions grouped
    by risk level (Critical → High → Moderate → Low).

    Request (multipart/form-data):
      - compose_file:  The docker-compose.yml file (required)
      - overrides:     JSON string with assumption-state overrides (optional)
      - dockerfile_0:  Dockerfile for the first service (optional)
      - ...

    Response (application/json):
      - Per-service treatment report dict.
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

    overrides, ov_err = parse_overrides(request)
    if ov_err:
        return pretty_json_response({"error": ov_err}, 400)

    dockerfiles: list[str] = []
    i = 0
    while f"dockerfile_{i}" in request.files:
        df_bytes = request.files[f"dockerfile_{i}"].read()
        if df_bytes:
            dockerfiles.append(df_bytes.decode("utf-8", errors="replace"))
        i += 1

    try:
        report = generate_treatment_report_from_upload(
            content, overrides=overrides, dockerfiles=dockerfiles or None
        )
    except ValueError as exc:
        return pretty_json_response({"error": str(exc)}, 400)
    except Exception as exc:
        logger.exception("Treatment report generation failed")
        return pretty_json_response(
            {"error": f"Treatment report generation failed: {exc}"}, 500
        )

    return pretty_json_response(report)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app)

    app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True

    # Swagger / Flasgger
    swagger_template = {
        "swagger": "2.0",
        "info": {
            "title": "Container Risk Factsheet API",
            "description": (
                "Generate security risk factsheets from Docker Compose files using the "
                "CSRO ontology. Analyse deployment traits, evaluate security assumptions, "
                "match context scenarios, and identify possible attack actions."
            ),
            "version": API_VERSION,
            "contact": {
                "url": "https://github.com/YannickLand/container-risk-factsheet",
            },
            "license": {
                "name": "MIT",
                "url": "https://opensource.org/licenses/MIT",
            },
        },
        "basePath": "/",
        "schemes": ["http", "https"],
        "consumes": ["multipart/form-data"],
        "produces": ["application/json"],
        "tags": [
            {"name": "Health", "description": "Service health and version"},
            {"name": "Factsheet", "description": "Generate security risk factsheets"},
            {"name": "Traits", "description": "Extract deployment traits"},
            {"name": "Treatment", "description": "Risk treatment reports"},
        ],
    }
    swagger_config = {
        "headers": [],
        "specs": [
            {
                "endpoint": "apispec",
                "route": "/swagger.json",
                "rule_filter": lambda rule: True,
                "model_filter": lambda tag: True,
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/api/docs",
    }
    Swagger(app, config=swagger_config, template=swagger_template)

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
