# FHIR MCP Server - R6 Agent-First Showcase

## Project Overview
This is an **R6-only, agent-first FHIR server showcase** built on a Python Flask application.
It demonstrates a minimal FHIR R6 surface with agent orchestration via MCP (Model Context Protocol).

## Architecture
- **Framework:** Python Flask with SQLAlchemy (SQLite for dev, Postgres for production)
- **R6 Surface:** Flask Blueprint at `/r6/fhir/*` — R6-only REST facade
- **Context Builder:** Ingests patient-centric Bundles, builds bounded context envelopes
- **Agent Orchestrator:** Node.js MCP server in `/services/agent-orchestrator/`
- **Claude Integration:** Anthropic API with 1M-token context support and prompt caching

## Key Directories
- `/` — Main Flask app (existing MCP bridge)
- `/r6/` — R6-specific Python modules (models, routes, validator, context builder)
- `/services/agent-orchestrator/` — Node.js MCP server for agent tool loops
- `/tests/` — Python tests
- `/.github/workflows/` — CI configuration
- `/.claude/rules/` — Modular Claude Code rules

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

## FHIR R6 Posture
- R6 is in **first full ballot** (v6.0.0-ballot3 / CI-build) — expect churn
- Resources stored as **canonical JSON** with minimal envelope fields
- Validation via `$validate` endpoint proxying to HL7 validator-wrapper
- Supported R6 resources: Patient, Encounter, Observation, Bundle, AuditEvent, Consent, OperationOutcome

## Agent Guardrails
- **Read tools** (no step-up): `context.get`, `fhir.read`, `fhir.search`
- **Write tools** (require step-up token): `fhir.propose_write`, `fhir.commit_write`
- All reads and writes emit AuditEvent records
- Agent proposals must pass `$validate` before commit

## Important Rules
- Never commit secrets or API keys
- R6 artifacts are versioned and pinnable — treat as updatable dependencies
- Always emit AuditEvent for FHIR resource access
- Step-up authorization required for all write operations
