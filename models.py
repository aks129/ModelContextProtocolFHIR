"""
Database initialization for the FHIR R6 MCP Showcase.

Provides the shared SQLAlchemy instance used by all R6 models.
R6-specific models (R6Resource, ContextEnvelope, AuditEventRecord)
are defined in r6/models.py.
"""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
