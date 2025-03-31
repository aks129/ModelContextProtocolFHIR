import os
import logging
from flask import Flask
from models import db

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create the Flask app
app = Flask(__name__)

# Configure the app
app.secret_key = os.environ.get("SESSION_SECRET") or "a-development-secret-key"

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the database with the app
db.init_app(app)

# Create database tables if they don't exist
with app.app_context():
    # Import models to ensure they're registered
    from models import FHIRServerConfig, RequestLog
    db.create_all()
    logger.info("Database tables created successfully")

# Import routes after initializing the app to avoid circular imports
from app import *

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
