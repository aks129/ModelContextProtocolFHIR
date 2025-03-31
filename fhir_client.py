import logging
import requests
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class FHIRClient:
    """
    Client for interacting with FHIR servers.
    Provides methods for common FHIR operations like read, search, etc.
    """
    
    def __init__(self, base_url=None, auth_type=None, api_key=None, username=None, password=None):
        """
        Initialize the FHIR client.
        
        Args:
            base_url (str): Base URL of the FHIR server
            auth_type (str): Authentication type (none, basic, token)
            api_key (str): API key for token authentication
            username (str): Username for basic authentication
            password (str): Password for basic authentication
        """
        self.base_url = base_url
        self.auth_type = auth_type
        self.api_key = api_key
        self.username = username
        self.password = password
        
        # Default headers
        self.headers = {
            'Accept': 'application/fhir+json',
            'Content-Type': 'application/fhir+json'
        }
        
        # Update headers based on auth type
        self._configure_auth()
    
    def configure(self, base_url, auth_type=None, api_key=None, username=None, password=None):
        """
        Configure or reconfigure the FHIR client.
        
        Args:
            base_url (str): Base URL of the FHIR server
            auth_type (str): Authentication type (none, basic, token)
            api_key (str): API key for token authentication
            username (str): Username for basic authentication
            password (str): Password for basic authentication
        """
        self.base_url = base_url
        self.auth_type = auth_type
        self.api_key = api_key
        self.username = username
        self.password = password
        
        # Reconfigure authentication
        self._configure_auth()
    
    def _configure_auth(self):
        """Configure authentication based on the auth_type."""
        self.auth = None
        
        if not self.auth_type or self.auth_type == 'none':
            # No authentication
            if 'Authorization' in self.headers:
                del self.headers['Authorization']
        
        elif self.auth_type == 'basic':
            # Basic authentication
            if self.username and self.password:
                self.auth = requests.auth.HTTPBasicAuth(self.username, self.password)
            else:
                logger.warning("Basic authentication selected but username/password not provided")
        
        elif self.auth_type == 'token':
            # Token-based authentication
            if self.api_key:
                self.headers['Authorization'] = f'Bearer {self.api_key}'
            else:
                logger.warning("Token authentication selected but API key not provided")
    
    def is_configured(self):
        """Check if the client is configured with a base URL."""
        return bool(self.base_url)
    
    def test_connection(self):
        """
        Test the connection to the FHIR server.
        
        Returns:
            bool: True if connection successful
            
        Raises:
            Exception: If connection fails
        """
        if not self.is_configured():
            raise ValueError("FHIR client not configured with a base URL")
        
        try:
            response = requests.get(
                self.base_url, 
                headers=self.headers,
                auth=self.auth,
                timeout=10
            )
            
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"FHIR server connection test failed: {str(e)}")
            raise Exception(f"Connection test failed: {str(e)}")
    
    def get_metadata(self):
        """
        Get the FHIR server metadata (capability statement).
        
        Returns:
            dict: Server metadata
            
        Raises:
            Exception: If request fails
        """
        if not self.is_configured():
            raise ValueError("FHIR client not configured with a base URL")
        
        try:
            url = urljoin(self.base_url, 'metadata')
            response = requests.get(
                url, 
                headers=self.headers,
                auth=self.auth,
                timeout=10
            )
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching FHIR metadata: {str(e)}")
            raise Exception(f"Metadata request failed: {str(e)}")
    
    def read_resource(self, resource_type, resource_id):
        """
        Read a specific FHIR resource by type and ID.
        
        Args:
            resource_type (str): The FHIR resource type (e.g., Patient, Observation)
            resource_id (str): The ID of the resource
            
        Returns:
            dict: The requested resource
            
        Raises:
            Exception: If request fails
        """
        if not self.is_configured():
            raise ValueError("FHIR client not configured with a base URL")
        
        try:
            url = urljoin(self.base_url, f'{resource_type}/{resource_id}')
            response = requests.get(
                url, 
                headers=self.headers,
                auth=self.auth,
                timeout=10
            )
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error reading {resource_type}/{resource_id}: {str(e)}")
            if response.status_code == 404:
                raise Exception(f"Resource {resource_type}/{resource_id} not found")
            raise Exception(f"Resource read failed: {str(e)}")
    
    def search_resources(self, resource_type, params=None):
        """
        Search for FHIR resources of a specific type with query parameters.
        
        Args:
            resource_type (str): The FHIR resource type to search for
            params (dict): Dictionary of search parameters
            
        Returns:
            dict: Search results bundle
            
        Raises:
            Exception: If request fails
        """
        if not self.is_configured():
            raise ValueError("FHIR client not configured with a base URL")
        
        params = params or {}
        
        try:
            url = urljoin(self.base_url, resource_type)
            response = requests.get(
                url, 
                headers=self.headers,
                auth=self.auth,
                params=params,
                timeout=10
            )
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error searching for {resource_type} resources: {str(e)}")
            raise Exception(f"Resource search failed: {str(e)}")
