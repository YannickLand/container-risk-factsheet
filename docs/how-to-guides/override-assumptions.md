# How to Override Assumption States

**Goal:** Mark one or more CSRO security assumptions as `Satisfied` (or `Dissatisfied` / `Unknown`) without changing the Compose file, so the factsheet reflects your environment's actual security posture.

---

## When to use this

The tool infers assumption states automatically from what it can observe in the Compose file (traits). Some controls cannot be detected from Compose alone — for example, a private container registry policy enforced at the CI level, or a network firewall applied outside the cluster. Overrides let you record those controls.

---

## Override format

Overrides are supplied as a JSON object.  Keys identify assumptions; values are one of `"Satisfied"`, `"Dissatisfied"`, or `"Unknown"` (case-insensitive).

```json
{
  "NET-1": "Satisfied",
  "IMG": "Satisfied",
  "AUTH-3": "Dissatisfied"
}
```

### Key formats accepted

| Format | Example | Matches |
|--------|---------|---------|
| Bare code with dash | `NET-1` | Assumption `NET-1` |
| Bare code with underscore | `NET_1` | Assumption `NET-1` |
| Full IRI | `csro:NET_1` | Assumption `NET-1` |
| Category wildcard | `NET` | All `NET-*` assumptions |

### Assumption categories

| Category | Topic |
|----------|-------|
| `NET` | Network exposure and TLS |
| `IMG` | Container image provenance |
| `RTS` | Runtime security settings |
| `AUTH` | Authentication and access control |
| `MON` | Logging and monitoring |
| `CRM` | Credential management |
| `SCM` | Software configuration management |
| `HIS` | Host isolation |
| `CIC` | CI/CD pipeline controls |

---

## CLI — inline JSON string

```bash
factsheet generate-factsheet example/docker-compose.yml \
  --overrides '{"NET-1": "Satisfied", "IMG": "Satisfied"}' \
  --pretty
```

## CLI — `.conf` file (recommended for large override sets)

The tool accepts a `.conf` file with `KEY=Value` lines and `#` comments — the
format used by `example/assumptions.conf`:

```ini
# example/assumptions.conf
IMG=Satisfied
RTS=Satisfied
NET=Satisfied
AUTH=Satisfied
MON=Satisfied
CRM=Satisfied
```

```bash
factsheet generate-factsheet example/docker-compose.yml \
  --overrides example/assumptions.conf \
  --pretty
```

This sets all assumptions in the `IMG`, `RTS`, `NET`, `AUTH`, `MON`, and `CRM`
categories to `Satisfied`, leaving `SCM`, `HIS`, and `CIC` as their inferred
state — matching a *hardened* deployment scenario.

## CLI — JSON file

Save your overrides to a JSON file if you prefer:

```json
{
  "NET-1":  "Satisfied",
  "NET-2":  "Satisfied",
  "IMG":    "Satisfied",
  "AUTH-3": "Dissatisfied"
}
```

```bash
factsheet generate-factsheet example/docker-compose.yml \
  --overrides overrides.json \
  --pretty
```

## REST API

Pass the `overrides` field as a JSON string in the multipart form.  The REST API
does not support `.conf` files directly — convert to JSON first:

```bash
curl -X POST http://localhost:5004/api/v1/generate-factsheet \
  -F "compose_file=@example/docker-compose.yml" \
  -F 'overrides={"IMG":"Satisfied","RTS":"Satisfied","NET":"Satisfied"}'
```

---

## Verifying the effect

Look at `ContainerSecurityAssumptionStates` in the output.  An overridden assumption will show `"state": "Satisfied"` (or whatever you set) regardless of what the trait extractor detected.

Priority rule: **explicit override always wins** over the automatically inferred state.
