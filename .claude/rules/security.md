# Security Rules

- NEVER commit API keys, passwords, or secrets to the repository
- NEVER store PHI (Protected Health Information) in logs
- All FHIR resource access MUST emit an AuditEvent
- Write operations MUST require step-up authorization tokens
- Agent-proposed writes MUST pass $validate before commit
- Redaction profiles MUST strip free-text notes, full identifiers, and addresses
- Use HTTPS for all external FHIR server connections
- Validate all incoming JSON payloads against expected schemas
- Context envelopes expire after configurable TTL (default 30 minutes)
