from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

# Initialize SQLAlchemy without binding it to a specific app
db = SQLAlchemy()

class FHIRServerConfig(db.Model):
    """
    Database model for FHIR server configurations.
    Stores connection details for FHIR servers.
    """
    __tablename__ = 'fhir_server_configs'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, default="Default FHIR Server")
    base_url = db.Column(db.String(255), nullable=False)
    auth_type = db.Column(db.String(20), nullable=True)
    api_key = db.Column(db.String(255), nullable=True)
    username = db.Column(db.String(100), nullable=True)
    password = db.Column(db.String(100), nullable=True)
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __init__(self, base_url, auth_type=None, api_key=None, username=None, password=None, name=None, is_default=False):
        """
        Initialize a FHIR server configuration.
        
        Args:
            base_url (str): Base URL of the FHIR server
            auth_type (str): Authentication type (none, basic, token)
            api_key (str): API key for token authentication
            username (str): Username for basic authentication
            password (str): Password for basic authentication
            name (str): Friendly name for this server configuration
            is_default (bool): Whether this is the default configuration
        """
        self.base_url = base_url
        self.auth_type = auth_type
        self.api_key = api_key
        self.username = username
        self.password = password
        self.name = name or "Default FHIR Server"
        self.is_default = is_default
    
    def to_dict(self, include_sensitive=False):
        """
        Convert the configuration to a dictionary.
        
        Args:
            include_sensitive (bool): Whether to include sensitive data like API keys and passwords
            
        Returns:
            dict: Configuration as a dictionary
        """
        result = {
            'id': self.id,
            'base_url': self.base_url,
            'auth_type': self.auth_type,
            'name': self.name,
            'is_default': self.is_default,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        
        if include_sensitive:
            result.update({
                'api_key': self.api_key,
                'username': self.username,
                'password': self.password
            })
        
        return result

class RequestLog(db.Model):
    """
    Database model for logging FHIR API requests.
    """
    __tablename__ = 'request_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    method = db.Column(db.String(10), nullable=False)  # GET, POST, etc.
    resource_type = db.Column(db.String(50), nullable=True)  # Patient, Observation, etc.
    resource_id = db.Column(db.String(50), nullable=True)  # Resource ID if applicable
    query_params = db.Column(db.Text, nullable=True)  # JSON string of query parameters
    response_status = db.Column(db.Integer, nullable=True)  # HTTP status code
    error_message = db.Column(db.Text, nullable=True)  # Error message if any
    execution_time_ms = db.Column(db.Float, nullable=True)  # Request execution time in milliseconds
    server_config_id = db.Column(db.Integer, db.ForeignKey('fhir_server_configs.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with FHIRServerConfig
    server_config = db.relationship('FHIRServerConfig', backref=db.backref('request_logs', lazy=True))
