---
name: add-api-endpoint
description: Add a new REST API endpoint to this Flask project. USE FOR: implementing new /api/v1/... routes, creating the matching flasgger YAML spec, registering the route in api_server.py, and writing pytest tests. Covers the full pattern used in this codebase — pretty_json_response, parse_overrides, multipart form input, swagger spec, test file.
argument-hint: "[HTTP method and path, e.g. 'POST /api/v1/analyze-config']"
---

# Add a New API Endpoint

## Project layout

| Concern | Location |
|---|---|
| Endpoint functions | `api/api_server.py` |
| Swagger / flasgger specs | `api/swagger_specs/<endpoint-name>.yml` |
| Shared helpers | `api/utils.py` |
| Tests | `tests/test_<module>.py` |

## Step 1 — Create the swagger spec

Create `api/swagger_specs/<endpoint-name>.yml` **before** writing the endpoint
(flasgger loads specs at import time):

```yaml
tags:
  - Factsheet
summary: One-line description of what this endpoint does.
consumes:
  - multipart/form-data
parameters:
  - name: compose_file
    in: formData
    type: file
    required: true
    description: Docker Compose file to analyse.
  - name: overrides
    in: formData
    type: string
    required: false
    description: |
      Assumption-state overrides. Two formats accepted:
      - Inline JSON string: `{"NET":"Satisfied","IMG":"Satisfied"}`
      - Upload a `.conf` / `.ini` file: `-F "overrides=@assumptions.conf"`
        Each line: `KEY=Value`; lines starting with `#` are treated as comments.
responses:
  200:
    description: Success — returns the result as JSON.
  400:
    description: Bad request — missing required field or malformed input.
  500:
    description: Internal error during processing.
```

## Step 2 — Register the route in `api/api_server.py`

Add the import of the swagger decorator and implement the function:

```python
@app.route("/api/v1/<endpoint-name>", methods=["POST"])
@swag_from("swagger_specs/<endpoint-name>.yml")
def <endpoint_name>_endpoint():
    # --- required input ---
    compose_raw = request.files.get("compose_file")
    if compose_raw is None:
        return pretty_json_response({"error": "Missing required field: compose_file"}, 400)
    compose_content = compose_raw.read().decode("utf-8", errors="replace")

    # --- optional overrides (JSON string or .conf file upload) ---
    overrides, ov_err = parse_overrides(request)
    if ov_err:
        return pretty_json_response({"error": ov_err}, 400)

    # --- optional dockerfile uploads ---
    dockerfiles: dict[str, str] = {}
    for key, fobj in request.files.items():
        if key.startswith("dockerfile_"):
            dockerfiles[key] = fobj.read().decode("utf-8", errors="replace")

    # --- business logic ---
    try:
        result = your_service_function(compose_content, overrides, dockerfiles)
    except Exception as exc:
        return pretty_json_response({"error": str(exc)}, 500)

    return pretty_json_response(result)
```

## Step 3 — Write tests in `tests/test_<module>.py`

Follow the patterns in `tests/test_api_utils.py` and use the Flask test client:

```python
import io
import json
import pytest
from api.api_server import app

@pytest.fixture()
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c

def test_happy_path(client):
    compose = b"version: '3'\nservices:\n  web:\n    image: nginx\n"
    resp = client.post(
        "/api/v1/<endpoint-name>",
        data={"compose_file": (io.BytesIO(compose), "docker-compose.yml")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert "expected_key" in data

def test_missing_compose_file_returns_400(client):
    resp = client.post("/api/v1/<endpoint-name>", data={}, content_type="multipart/form-data")
    assert resp.status_code == 400
    assert "error" in json.loads(resp.data)

def test_conf_overrides(client):
    compose = b"version: '3'\nservices:\n  web:\n    image: nginx\n"
    conf = b"NET=Satisfied\nIMG=Satisfied\n"
    resp = client.post(
        "/api/v1/<endpoint-name>",
        data={
            "compose_file": (io.BytesIO(compose), "docker-compose.yml"),
            "overrides": (io.BytesIO(conf), "assumptions.conf"),
        },
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
```

## Rules

- Always use `pretty_json_response()` — never `jsonify()` or `flask.Response()` directly
- Always use `parse_overrides(request)` for the `overrides` field — never inline `json.loads(request.form.get(...))`
- Return `{"error": "..."}` with an appropriate 4xx status for all validation failures
- Keep dockerfile parsing consistent: iterate `request.files` for keys starting with `dockerfile_`
- The swagger spec file must exist before the module is imported (flasgger loads at startup)
