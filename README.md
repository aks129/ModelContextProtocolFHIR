# FHIR R6 Agent-First Showcase

An R6-only, agent-first FHIR server with MCP (Model Context Protocol) orchestration.
Built for conference demos, marketplace evaluation, and prototype validation.

**v0.5.0** | 100 tests | FHIR R6 v6.0.0-ballot3

## Features

**FHIR R6 REST API** at `/r6/fhir/*`
- CRUD operations for Patient, Encounter, Observation, Bundle, AuditEvent, Consent, OperationOutcome
- `$validate` for structural validation
- `$ingest-context` for patient-centric Bundle ingestion
- `$deidentify` for HIPAA Safe Harbor de-identification
- `$export` for audit trail export (NDJSON / FHIR Bundle)
- `_summary=count` search support
- ETag/If-Match concurrency control

**MCP Agent Orchestration** (Node.js at port 3001)
- 6 tools: `context.get`, `fhir.read`, `fhir.search`, `fhir.validate`, `fhir.propose_write`, `fhir.commit_write`
- Read/write tier separation with HMAC step-up authorization
- Streamable HTTP + SSE transports
- Protocol version negotiation
- Session fixation prevention
- CORS deny-by-default

**Security & Compliance**
- OAuth 2.1 with PKCE (S256) + SMART-on-FHIR v2 discovery
- Mandatory tenant isolation (X-Tenant-Id header)
- PHI redaction on all read paths
- Human-in-the-loop enforcement for clinical writes (HTTP 428)
- Medical disclaimer injection on clinical resources
- Append-only audit trail with tenant scoping
- 128-bit HMAC-SHA256 step-up tokens

**Interactive Dashboard** at `/r6-dashboard`
- Patient Explorer with PHI redaction visualization
- MCP Agent Tool Loop with all 6 tools
- Context Envelope Builder
- Side-by-side de-identification comparison
- Human-in-the-Loop enforcement demo
- OAuth 2.1 + PKCE full flow walkthrough
- Resource Validation ($validate)
- Live Audit Feed with NDJSON export
- "Run Full Demo" walkthrough mode

## Quick Start

```bash
# Install dependencies
uv sync

# Run in development mode
python main.py

# Open in browser
# Landing page: http://localhost:5000
# R6 Dashboard: http://localhost:5000/r6-dashboard
# FHIR API: http://localhost:5000/r6/fhir/metadata
```

## Vercel Deployment

```bash
# Install Vercel CLI
npm i -g vercel

# Login to Vercel
vercel login

# Deploy (creates new project)
vercel --prod

# Set environment variables (optional)
vercel env add STEP_UP_SECRET
vercel env add SESSION_SECRET
```

Vercel uses ephemeral SQLite in `/tmp` for the demo. For persistent data, set `SQLALCHEMY_DATABASE_URI` to a PostgreSQL connection string (e.g., Vercel Postgres, Neon, Supabase).

## Docker

```bash
docker-compose up -d --build

# Services:
# - fhir-r6-showcase (Flask, port 5000)
# - agent-orchestrator (Node.js MCP, port 3001)
# - redis (port 6379)
```

## Testing

```bash
# Run all tests (100 passing)
python -m pytest tests/ -v

# Agent orchestrator tests
cd services/agent-orchestrator && npm ci && npm test
```

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/r6/fhir/metadata` | GET | CapabilityStatement |
| `/r6/fhir/health` | GET | Liveness/readiness probe |
| `/r6/fhir/{type}` | POST | Create resource (requires step-up) |
| `/r6/fhir/{type}` | GET | Search resources |
| `/r6/fhir/{type}/{id}` | GET | Read resource (redacted) |
| `/r6/fhir/{type}/{id}` | PUT | Update resource (requires step-up) |
| `/r6/fhir/{type}/$validate` | POST | Validate resource |
| `/r6/fhir/Bundle/$ingest-context` | POST | Ingest Bundle + build context |
| `/r6/fhir/context/{id}` | GET | Retrieve context envelope |
| `/r6/fhir/{type}/{id}/$deidentify` | GET | Safe Harbor de-identification |
| `/r6/fhir/AuditEvent` | GET | Search audit events |
| `/r6/fhir/AuditEvent/$export` | GET | Export audit trail |
| `/r6/fhir/oauth/register` | POST | Dynamic client registration |
| `/r6/fhir/oauth/authorize` | GET | Authorization (PKCE) |
| `/r6/fhir/oauth/token` | POST | Token exchange |
| `/r6/fhir/oauth/revoke` | POST | Token revocation |
| `/r6/fhir/$import-stub` | POST | Cross-version import stub |

## Project Structure

```
main.py                     Flask app entry point
app.py                      Web UI routes (landing page, dashboard)
models.py                   SQLAlchemy db instance
api/
  index.py                  Vercel serverless entry point
vercel.json                 Vercel deployment config
requirements.txt            Python deps for Vercel
r6/
  routes.py                 R6 FHIR REST Blueprint
  models.py                 R6Resource, ContextEnvelope, AuditEventRecord
  validator.py              FHIR R6 structural validation
  oauth.py                  OAuth 2.1 + SMART-on-FHIR
  stepup.py                 HMAC step-up token management
  audit.py                  AuditEvent recording
  redaction.py              PHI redaction profiles
  health_compliance.py      Disclaimer, HITL, de-identification, audit export
  context_builder.py        Bundle ingestion + context envelopes
  rate_limit.py             Redis-backed rate limiting
  agent_client.py           Anthropic Claude API client
services/agent-orchestrator/
  src/index.ts              MCP server (Express + SSE)
  src/tools.ts              Tool definitions + executor
templates/
  base.html                 Base template (Bootstrap dark theme)
  index.html                Landing page
  r6_dashboard.html         Interactive R6 dashboard
static/
  css/r6-dashboard.css      Dashboard styles
  js/r6-dashboard.js        Dashboard JavaScript
tests/
  conftest.py               Pytest fixtures
  test_r6_routes.py         R6 route tests (69 tests)
  test_r6_dashboard.py      Dashboard + integration tests (31 tests)
  test_context_builder.py   Context builder unit tests (5 tests)
```

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SQLALCHEMY_DATABASE_URI` | Production | `sqlite:///mcp_server.db` | Database connection string |
| `STEP_UP_SECRET` | Production | (generated) | HMAC signing secret |
| `SESSION_SECRET` | No | (dev key) | Flask session secret |
| `LOG_LEVEL` | No | INFO/DEBUG | Logging level |
| `FLASK_ENV` | No | development | Environment mode |
| `DB_POOL_SIZE` | No | 10 | PostgreSQL connection pool |
| `REDIS_URL` | No | `redis://localhost:6379` | Redis connection |
| `ANTHROPIC_API_KEY` | No | — | Claude API key |

## License

MIT
