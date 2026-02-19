# FHIR R6 MCP Agent-First Showcase

## Project Overview
An **R6-only, agent-first FHIR server showcase** built on Python Flask with a Node.js MCP orchestrator.
Demonstrates a minimal FHIR R6 surface with agent tool orchestration via Model Context Protocol (MCP).
Version 0.5.0 — 100 tests passing.

## Architecture
```
┌─────────────────────────────────────────────────┐
│  Flask App (Python)                              │
│  ├── /r6/fhir/* — R6 REST facade (Blueprint)    │
│  ├── /r6/fhir/health — Liveness probe           │
│  ├── /r6/fhir/oauth/* — OAuth 2.1 + SMART       │
│  ├── / — Landing page                            │
│  └── /r6-dashboard — Interactive demo dashboard  │
├─────────────────────────────────────────────────┤
│  MCP Server (Node.js)                            │
│  ├── Streamable HTTP + SSE transports            │
│  ├── 6 tools: context.get, fhir.read/search/     │
│  │   validate, fhir.propose_write/commit_write   │
│  └── Session management + CORS deny-by-default   │
├─────────────────────────────────────────────────┤
│  Database: SQLite (dev) / PostgreSQL (prod)      │
│  Cache: Redis (rate limiting + sessions)         │
└─────────────────────────────────────────────────┘
```

## Key Directories
```
/                         Main Flask app (main.py, app.py, models.py)
/r6/                      R6 Python modules (routes, models, validator, oauth, stepup, audit, redaction, health_compliance, context_builder, rate_limit, agent_client)
/services/agent-orchestrator/  Node.js MCP server (TypeScript)
/templates/               Jinja2 templates (base.html, index.html, r6_dashboard.html)
/static/css/              Dashboard styles (r6-dashboard.css)
/static/js/               Dashboard JavaScript (r6-dashboard.js)
/tests/                   Python tests (conftest.py, test_r6_routes.py, test_r6_dashboard.py, test_context_builder.py)
/.github/workflows/       CI configuration (ci.yml)
/.claude/rules/           Claude Code rules (build.md, security.md)
/.mcp/                    MCP server manifest (server.json)
```

## Build & Run Commands
```bash
# Install Python dependencies
uv sync

# Run Flask app (development)
python main.py

# Run tests (100 passing)
python -m pytest tests/ -v

# Docker Compose (full stack)
docker-compose up -d --build

# Agent orchestrator
cd services/agent-orchestrator && npm ci && npm test
```

## FHIR R6 Posture
- R6 is in **first full ballot** (v6.0.0-ballot3 / CI-build)
- Resources stored as **canonical JSON** with minimal envelope fields
- Validation via `$validate` endpoint
- Supported R6 resources: Patient, Encounter, Observation, Bundle, AuditEvent, Consent, OperationOutcome

## Agent Guardrails
- **Read tools** (no step-up): `context.get`, `fhir.read`, `fhir.search`, `fhir.validate`
- **Write tools** (require step-up token): `fhir.propose_write`, `fhir.commit_write`
- All reads and writes emit AuditEvent records
- Agent proposals must pass `$validate` before commit
- Human-in-the-loop required for clinical writes (X-Human-Confirmed header)

## Security Posture
- Mandatory X-Tenant-Id on all non-discovery endpoints
- HMAC-SHA256 step-up tokens (128-bit nonce)
- OAuth 2.1 with PKCE (S256 only) + SMART-on-FHIR v2
- PHI redaction on all read paths
- HIPAA Safe Harbor de-identification via `$deidentify`
- Append-only audit trail with tenant isolation
- ETag/If-Match concurrency control
- Medical disclaimer injection on clinical resources
- CORS deny-by-default on MCP orchestrator
- MCP session fixation prevention (server-generated IDs)

## Important Rules
- Never commit secrets or API keys
- R6 artifacts are versioned and pinnable
- Always emit AuditEvent for FHIR resource access
- Step-up authorization required for all write operations
- Run tests before committing: `python -m pytest tests/ -v`
