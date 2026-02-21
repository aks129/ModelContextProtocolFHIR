# FHIR R6 + MCP Guardrail Patterns

## Project Overview
A **reference implementation** of security and compliance patterns for AI agent access to
FHIR R6 data via Model Context Protocol (MCP). Version 0.7.0.

**What this is:** A pattern library showing how tenant isolation, step-up authorization,
audit trails, PHI redaction, and human-in-the-loop enforcement work together when an
AI agent accesses clinical data through MCP tools.

**What this is NOT:** A production FHIR server. Resources are stored as JSON blobs in SQLite.
Validation is structural only (required fields + value constraints, no StructureDefinition
conformance, no terminology binding). Search supports basic parameters but not chaining,
_include, _revinclude, or modifiers.

## Architecture
```
┌─────────────────────────────────────────────────┐
│  Flask App (Python)                              │
│  ├── /r6/fhir/* — R6 REST facade (Blueprint)    │
│  ├── /r6/fhir/health — Liveness probe           │
│  ├── /r6/fhir/oauth/* — OAuth 2.1 + SMART       │
│  ├── / — Landing page                            │
│  └── /r6-dashboard — Interactive dashboard       │
├─────────────────────────────────────────────────┤
│  MCP Server (Node.js + TypeScript)               │
│  ├── Streamable HTTP + SSE transports            │
│  ├── 10 tools with reasoning summaries           │
│  └── Session management + CORS deny-by-default   │
├─────────────────────────────────────────────────┤
│  Storage: JSON blobs in SQLite (dev)             │
│  Validation: Structural only (no StructureDef)   │
│  Search: patient, code, status, _lastUpdated,    │
│          _count, _sort, _summary                 │
│  Cache: Redis (rate limiting + sessions)         │
└─────────────────────────────────────────────────┘
```

## Key Directories
```
/                         Main Flask app (main.py, app.py, models.py)
/r6/                      R6 Python modules (routes, models, validator, oauth, stepup, audit, redaction, health_compliance, context_builder, rate_limit)
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

# Run tests
python -m pytest tests/ -v

# Docker Compose (full stack)
docker-compose up -d --build

# Agent orchestrator
cd services/agent-orchestrator && npm ci && npm test
```

## What's Actually R6-Specific
- **Permission** — R6 access control resource (separate from Consent). $evaluate operation.
- **SubscriptionTopic** — Restructured pub/sub (introduced R5, maturing R6). Storage + discovery only, no notification dispatch.
- **DeviceAlert** — ISO/IEEE 11073 device alarms (new in R6).
- **NutritionIntake** — Dietary consumption tracking (new in R6).
- **DeviceAssociation, NutritionProduct, Requirements, ActorDefinition** — Additional R6 resources (CRUD only).

## What's Standard FHIR (Not R6-Specific)
- **$stats** — Observation statistics (count/min/max/mean). Available since R4. Only supports valueQuantity.
- **$lastn** — Most recent observations per code. Available since R4. Sorted by storage order, not effectiveDateTime.
- **$validate** — Structural validation only. Falls back silently if external validator unavailable.
- **$deidentify** — HIPAA Safe Harbor. Custom operation, not part of FHIR spec.

## Search Capabilities (Honest)
Supported parameters: `patient` (reference), `code` (token), `status` (token), `_lastUpdated` (date with ge/le/gt/lt prefix), `_count` (1-200), `_sort` (_lastUpdated/-_lastUpdated), `_summary` (count).

**NOT supported:** chaining, _include, _revinclude, modifiers (:exact, :contains), composite search, date range on clinical dates, full-text search, quantity comparators.

## MCP Tools (10)
- **Read tools** (no step-up): `context.get`, `fhir.read`, `fhir.search`, `fhir.validate`, `fhir.stats`, `fhir.lastn`, `fhir.permission_evaluate`, `fhir.subscription_topics`
- **Write tools** (require step-up token): `fhir.propose_write`, `fhir.commit_write`
- Tools add `_mcp_summary` with reasoning, clinical context, and limitations
- `propose_write` identifies clinical types requiring human-in-the-loop
- `permission_evaluate` returns reasoning explaining why permit/deny

## Security Patterns (What's Real)
- **Tenant isolation** — Enforced at database layer on every query
- **Step-up tokens** — HMAC-SHA256 with 128-bit nonce for write authorization
- **OAuth 2.1 + PKCE** — S256 only, dynamic client registration, token revocation
- **PHI redaction** — Applied on all read paths (identifiers masked, addresses stripped)
- **Audit trail** — Append-only, database-level immutability enforcement
- **ETag/If-Match** — Concurrency control on updates
- **Human-in-the-loop** — Clinical writes require X-Human-Confirmed header (enforcement is header-based, not cryptographic)
- **Medical disclaimers** — Injected on clinical resource reads

## Known Limitations
- JSON blob storage — no indexed search fields, table scans for filtering
- Structural validation only — no StructureDefinition, cardinality, or binding checks
- SubscriptionTopic stored but notifications not dispatched
- Human-in-the-loop is a header flag, not cryptographic confirmation
- Context envelope tracks membership but consent_decision is always 'permit'
- No historical versioning (version_id increments but old versions not retrievable)
- De-identification at read time, not storage time

## Important Rules
- Never commit secrets or API keys
- Always emit AuditEvent for FHIR resource access
- Step-up authorization required for all write operations
- Run tests before committing: `python -m pytest tests/ -v`
