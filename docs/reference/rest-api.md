# REST API Reference

Base URL: `http://localhost:5004`  
Interactive docs (Swagger UI): `http://localhost:5004/api/docs`

All request bodies use `multipart/form-data`.  All responses are `application/json`.

---

## Endpoints

### `GET /api/v1/health`

Liveness check.

**Response 200:**
```json
{ "status": "ok" }
```

---

### `GET /api/v1/version`

Returns the installed package version and API version.

**Response 200:**
```json
{
  "api_version": "1.0.0",
  "package_version": "1.0.0"
}
```

---

### `POST /api/v1/generate-factsheet`

Generate a security risk factsheet from an uploaded Docker Compose file.

**Request fields (multipart/form-data):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `compose_file` | file | Yes | `docker-compose.yml` |
| `overrides` | string | No | JSON string of assumption-state overrides |
| `dockerfile_0` | file | No | Dockerfile for the first service |
| `dockerfile_1` | file | No | Dockerfile for the second service |
| `dockerfile_N` | file | No | Dockerfile for the Nth service (positional) |

**Response 200:** Per-service factsheet dict (JSON-LD, CSRO ontology)

**Response 400:** `{"error": "<reason>"}` — missing or invalid input

**Response 500:** `{"error": "<reason>"}` — pipeline failure

**Example:**
```bash
curl -X POST http://localhost:5004/api/v1/generate-factsheet \
  -F "compose_file=@docker-compose.yml" \
  -F 'overrides={"NET-1":"Satisfied"}' \
  -F "dockerfile_0=@Dockerfile"
```

---

### `POST /api/v1/extract-traits`

Extract deployment traits from an uploaded Docker Compose file without running the full factsheet pipeline.

**Request fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `compose_file` | file | Yes | `docker-compose.yml` |

**Response 200:**
```json
{
  "service_name": [
    {
      "id": "publicly_exposed",
      "name": "Service is publicly exposed",
      "source": "compose"
    }
  ]
}
```

**Example:**
```bash
curl -X POST http://localhost:5004/api/v1/extract-traits \
  -F "compose_file=@docker-compose.yml"
```

---

### `POST /api/v1/generate-treatment-report`

Run the full factsheet pipeline and return a prioritised risk treatment report grouped by risk level.

**Request fields:** Same as `generate-factsheet` (`compose_file`, `overrides`, `dockerfile_0`, …)

**Response 200:**
```json
{
  "service_name": {
    "summary": {
      "Critical": 2,
      "High": 1,
      "Moderate": 3,
      "Low": 0,
      "Unknown": 0
    },
    "treatments_by_level": {
      "Critical": [ { "@id": "csro:T_...", "rdfs:label": "..." } ]
    },
    "all_treatments": [...]
  }
}
```

**Example:**
```bash
curl -X POST http://localhost:5004/api/v1/generate-treatment-report \
  -F "compose_file=@docker-compose.yml"
```

---

## Error responses

All error responses follow the same schema:

```json
{ "error": "Human-readable description of the problem." }
```

| HTTP status | When |
|-------------|------|
| 400 | Missing required field, empty file, invalid JSON in `overrides` |
| 500 | Internal pipeline failure |

---

## Starting the server

**Docker Compose (recommended):**
```bash
docker compose up
```

**Direct Python:**
```bash
python -m api.api_server
# or
flask --app api.api_server:create_app run --port 5004
```
