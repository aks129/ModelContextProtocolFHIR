"""
FHIR R6 MCP Showcase — Flask Application Entry Point.

Initializes the Flask app, database, and R6 FHIR Blueprint.
Run with: python main.py (development) or gunicorn main:app (production)
"""

import os
import logging
from flask import Flask
from models import db

# Configure logging from environment
log_level = os.environ.get('LOG_LEVEL', 'DEBUG' if os.environ.get('FLASK_ENV') == 'development' else 'INFO')
logging.basicConfig(level=getattr(logging, log_level.upper(), logging.INFO),
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET") or "a-development-secret-key"

# Configure database — require explicit URI in production
db_uri = os.environ.get("SQLALCHEMY_DATABASE_URI")
if not db_uri:
    if os.environ.get('FLASK_ENV') == 'production':
        raise RuntimeError(
            'SQLALCHEMY_DATABASE_URI environment variable is required in production. '
            'SQLite is not suitable for production use.'
        )
    db_uri = "sqlite:///mcp_server.db"

app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
logger.info("Database configured (URI not logged for security)")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Database connection pooling (PostgreSQL in production)
if 'postgresql' in db_uri or 'postgres' in db_uri:
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_size": int(os.environ.get("DB_POOL_SIZE", "10")),
        "pool_recycle": 3600,
        "pool_pre_ping": True,
    }

# Require STEP_UP_SECRET in production
if os.environ.get('FLASK_ENV') == 'production' and not os.environ.get('STEP_UP_SECRET'):
    raise RuntimeError(
        'STEP_UP_SECRET environment variable is required in production. '
        'Generate a secure random secret: python -c "import secrets; print(secrets.token_hex(32))"'
    )

# Initialize database
db.init_app(app)

with app.app_context():
    from r6.models import R6Resource, ContextEnvelope, ContextItem, AuditEventRecord
    db.create_all()
    logger.info("Database tables created (R6 models)")

# Register R6 FHIR Blueprint
from r6.routes import r6_blueprint
app.register_blueprint(r6_blueprint)
logger.info("R6 FHIR Blueprint registered at /r6/fhir")

# Import web UI routes
from app import *  # noqa: F401,F403,E402

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
