# FHIR R6 + MCP Guardrail Patterns

## Project Overview
A **reference implementation** of security and compliance patterns for AI agent access to
FHIR R6 data via Model Context Protocol (MCP). Version 0.8.0.

**What this is:** A pattern library showing how tenant isolation, step-up authorization,
audit trails, PHI redaction, and human-in-the-loop enforcement work together when an
AI agent accesses clinical data through MCP tools.

**What this is NOT:** A production FHIR server. In local mode, resources are stored as
JSON blobs in SQLite. In upstream proxy mode, real FHIR server data flows through the
guardrail stack. Validation is structural only (required fields + value constraints,
no StructureDefinition conformance, no terminology binding).

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
│  Data Source (configurable):                     │
│  ├── LOCAL: JSON blobs in SQLite (default)       │
│  └── UPSTREAM: Real FHIR server via httpx proxy  │
│       (HAPI, SMART Health IT, Epic, etc.)        │
│       Guardrails applied to upstream responses   │
├─────────────────────────────────────────────────┤
│  Guardrail Stack (always active):                │
│  ├── PHI redaction on all read paths             │
│  ├── Immutable audit trail                       │
│  ├── Step-up tokens for writes                   │
│  ├── Tenant isolation on every query             │
│  └── URL rewriting (upstream URLs never leak)    │
├─────────────────────────────────────────────────┤
│  Cache: Redis (rate limiting + sessions)         │
└─────────────────────────────────────────────────┘
```

### Upstream Proxy Flow
```
Client → MCP Server → Flask (guardrails) → Upstream FHIR Server
                           ↓
              redaction, audit, step-up,
              tenant isolation, disclaimers,
              URL rewriting
```

## Key Directories
```
/                         Main Flask app (main.py, app.py, models.py)
/r6/                      R6 Python modules (routes, models, validator, oauth, stepup, audit, redaction, health_compliance, context_builder, rate_limit, fhir_proxy)
/services/agent-orchestrator/  Node.js MCP server (TypeScript)
/templates/               Jinja2 templates (base.html, index.html, r6_dashboard.html)
/static/css/              Dashboard styles (r6-dashboard.css)
/static/js/               Dashboard JavaScript (r6-dashboard.js)
/tests/                   Python tests (conftest.py, test_r6_routes.py, test_r6_dashboard.py, test_context_builder.py, test_fhir_proxy.py)
/.github/workflows/       CI configuration (ci.yml)
/.claude/rules/           Claude Code rules (build.md, security.md)
/.mcp/                    MCP server manifest (server.json)
```

## Build & Run Commands
```bash
# Install Python dependencies
uv sync

# Run Flask app (development, local mode)
python main.py

# Run Flask app with upstream FHIR server
FHIR_UPSTREAM_URL=https://hapi.fhir.org/baseR4 python main.py

# Run tests
python -m pytest tests/ -v

# Docker Compose (full stack)
docker-compose up -d --build

# Docker Compose with upstream FHIR server
FHIR_UPSTREAM_URL=https://hapi.fhir.org/baseR4 docker-compose up -d --build

# Agent orchestrator
cd services/agent-orchestrator && npm ci && npm test
```

## Upstream FHIR Proxy (NEW in v0.8.0)
Connect to real FHIR servers while keeping the full guardrail stack active.

### Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `FHIR_UPSTREAM_URL` | (empty) | Upstream FHIR server base URL. When set, enables proxy mode. |
| `FHIR_UPSTREAM_TIMEOUT` | `15` | HTTP timeout for upstream requests (seconds) |
| `FHIR_LOCAL_BASE_URL` | (empty) | Local server URL for URL rewriting in responses |

### Tested Upstream Servers
| Server | URL | Auth |
|--------|-----|------|
| HAPI FHIR R4 | `https://hapi.fhir.org/baseR4` | None (open) |
| SMART Health IT | `https://r4.smarthealthit.org` | None (open) |
| HAPI FHIR R5 | `https://hapi.fhir.org/baseR5` | None (open) |
| Local HAPI | `http://localhost:8080/fhir` | None |
| Epic Sandbox | `https://open.epic.com/Interface/FHIR` | OAuth 2.0 |

### What the Proxy Does
- **Reads**: Fetched from upstream, then redacted + audited + disclaimers added
- **Searches**: Forwarded to upstream with all query params, results redacted per entry
- **Writes**: Validated locally first, then forwarded to upstream with step-up auth check
- **URL rewriting**: All upstream URLs in responses replaced with local proxy URLs
- **Health check**: `/r6/fhir/health` reports upstream connection status
- **Graceful fallback**: Network errors return proper OperationOutcome, not stack traces

### What the Proxy Does NOT Do
- No caching of upstream responses (every request hits the server)
- No SMART-on-FHIR auth forwarding to upstream (uses upstream's native auth model)
- No cross-version translation (R4 responses stay R4)
- Tenant isolation is enforced locally, not on the upstream server

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
In **local mode**: Supported parameters: `patient` (reference), `code` (token), `status` (token), `_lastUpdated` (date with ge/le/gt/lt prefix), `_count` (1-200), `_sort` (_lastUpdated/-_lastUpdated), `_summary` (count). NOT supported: chaining, _include, _revinclude, modifiers.

In **upstream proxy mode**: All query parameters forwarded to the upstream server. The upstream server's full search capabilities are available (chaining, _include, etc. if the upstream supports them).

## MCP Tools (10)
- **Read tools** (no step-up): `context.get`, `fhir.read`, `fhir.search`, `fhir.validate`, `fhir.stats`, `fhir.lastn`, `fhir.permission_evaluate`, `fhir.subscription_topics`
- **Write tools** (require step-up token): `fhir.propose_write`, `fhir.commit_write`
- Tools add `_mcp_summary` with reasoning, clinical context, and limitations
- `propose_write` identifies clinical types requiring human-in-the-loop
- `permission_evaluate` returns reasoning explaining why permit/deny

## Security Patterns (What's Real)
- **Tenant isolation** — Enforced at database layer on every query (local mode) or as a guardrail header (proxy mode)
- **Step-up tokens** — HMAC-SHA256 with 128-bit nonce for write authorization
- **OAuth 2.1 + PKCE** — S256 only, dynamic client registration, token revocation
- **PHI redaction** — Applied on all read paths including upstream responses (identifiers masked, addresses stripped)
- **Audit trail** — Append-only, database-level immutability enforcement. Logs upstream source when proxied.
- **ETag/If-Match** — Concurrency control on updates
- **Human-in-the-loop** — Clinical writes require X-Human-Confirmed header (enforcement is header-based, not cryptographic)
- **Medical disclaimers** — Injected on clinical resource reads (local and upstream)
- **URL rewriting** — Upstream server URLs never leak to clients

## Known Limitations
- Local mode: JSON blob storage — no indexed search fields, table scans for filtering
- Structural validation only — no StructureDefinition, cardinality, or binding checks
- SubscriptionTopic stored but notifications not dispatched
- Human-in-the-loop is a header flag, not cryptographic confirmation
- Context envelope tracks membership but consent_decision is always 'permit'
- No historical versioning (version_id increments but old versions not retrievable)
- De-identification at read time, not storage time
- Upstream proxy: no response caching, no cross-version translation

## Important Rules
- Never commit secrets or API keys
- Always emit AuditEvent for FHIR resource access
- Step-up authorization required for all write operations
- Run tests before committing: `python -m pytest tests/ -v`
