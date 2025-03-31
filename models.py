# Currently, this application doesn't require database models.
# This file is a placeholder and could be expanded in the future if needed,
# for example to store FHIR server configurations, user preferences, etc.

class FHIRServerConfig:
    """
    In-memory representation of a FHIR server configuration.
    Could be extended to use an actual database in the future.
    """
    
    def __init__(self, base_url, auth_type=None, api_key=None, username=None, password=None, name=None):
        """
        Initialize a FHIR server configuration.
        
        Args:
            base_url (str): Base URL of the FHIR server
            auth_type (str): Authentication type (none, basic, token)
            api_key (str): API key for token authentication
            username (str): Username for basic authentication
            password (str): Password for basic authentication
            name (str): Friendly name for this server configuration
        """
        self.base_url = base_url
        self.auth_type = auth_type
        self.api_key = api_key
        self.username = username
        self.password = password
        self.name = name or "Default FHIR Server"
    
    def to_dict(self, include_sensitive=False):
        """
        Convert the configuration to a dictionary.
        
        Args:
            include_sensitive (bool): Whether to include sensitive data like API keys and passwords
            
        Returns:
            dict: Configuration as a dictionary
        """
        result = {
            'base_url': self.base_url,
            'auth_type': self.auth_type,
            'name': self.name
        }
        
        if include_sensitive:
            result.update({
                'api_key': self.api_key,
                'username': self.username,
                'password': self.password
            })
        
        return result
