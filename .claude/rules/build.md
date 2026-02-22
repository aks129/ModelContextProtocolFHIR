# Build Rules

## Python
- Use `uv sync` to install dependencies (pyproject.toml)
- Run tests with `python -m pytest tests/ -v`
- Flask app entry point: `main.py`
- R6 Blueprint registered in `main.py`

## Node.js (Agent Orchestrator)
- Located in `services/agent-orchestrator/`
- Use `npm ci` to install dependencies
- Run with `npm start`, test with `npm test`
- TypeScript compiled with `npx tsc`

## Docker
- `docker-compose up -d --build` for full stack
- Services: fhir-mcp-guardrails, redis, validator

## Testing
- Python: pytest with fixtures in tests/conftest.py
- Node.js: Jest for MCP server tests
- Always run tests before committing
