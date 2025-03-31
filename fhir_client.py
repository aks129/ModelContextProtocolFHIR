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
        # Ensure the base_url uses HTTPS
        if base_url and not base_url.startswith(('http://', 'https://')):
            base_url = 'https://' + base_url
        elif base_url and base_url.startswith('http://'):
            base_url = 'https://' + base_url[7:]
            
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
        # Ensure the base_url uses HTTPS
        if base_url and not base_url.startswith(('http://', 'https://')):
            base_url = 'https://' + base_url
        elif base_url and base_url.startswith('http://'):
            base_url = 'https://' + base_url[7:]
            
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
        return self.base_url is not None and bool(self.base_url)
    
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
        
        if not self.base_url:
            raise ValueError("Base URL is required")
        
        # Validate the URL format
        if not self.base_url.startswith('http://') and not self.base_url.startswith('https://'):
            raise ValueError("Base URL must start with http:// or https://")
        
        # Force HTTPS for security
        base_url = self.base_url
        if base_url.startswith('http://'):
            base_url = 'https://' + base_url[7:]
            logger.warning(f"Converting HTTP URL to HTTPS: {self.base_url} -> {base_url}")
            
        # Endpoints to try in order
        endpoints = [
            '',  # Base URL itself
            'metadata',  # Standard FHIR metadata endpoint
            'Metadata',  # Some servers use capitalized endpoint
            'fhir/metadata',  # Some servers have a /fhir prefix
            '.well-known/smart-configuration'  # SMART on FHIR configuration endpoint
        ]
        
        last_exception = None
        
        for endpoint in endpoints:
            try:
                url = base_url
                if endpoint:
                    url = url.rstrip('/') + '/' + endpoint
                
                logger.debug(f"Testing connection to: {url}")
                
                response = requests.get(
                    url,
                    headers=self.headers,
                    auth=self.auth,
                    timeout=10,
                    verify=True  # Always verify SSL certificates for security
                )
                
                # If we got a successful response, the connection works
                if response.status_code < 400:
                    logger.debug(f"Connection successful using endpoint: {endpoint or 'base URL'}")
                    return True
                
                # If we got a 404 for this endpoint, continue to the next one
                if response.status_code == 404:
                    continue
                
                # For other error codes (401, 403, 500, etc.), we consider it a valid FHIR server 
                # but with auth/permission issues that need to be addressed
                if response.status_code >= 400:
                    if response.status_code in (401, 403):
                        raise Exception(f"Authentication or authorization error (HTTP {response.status_code}). Please check your credentials.")
                    else:
                        raise Exception(f"Server error (HTTP {response.status_code}). The server is responding but returned an error.")
                    
            except requests.exceptions.SSLError as e:
                last_exception = Exception("SSL Certificate error. Please check the FHIR server's SSL certificate.")
            except requests.exceptions.ConnectionError as e:
                last_exception = Exception(f"Connection error: Could not connect to the server. Please check the URL and network connection.")
            except requests.exceptions.Timeout as e:
                last_exception = Exception("Connection timed out. The server took too long to respond.")
            except requests.exceptions.RequestException as e:
                last_exception = e
        
        # If we've tried all endpoints and none worked, process special cases and raise the appropriate error
        
        # Special case for HAPI FHIR server
        if self.base_url and 'hapi.fhir.org' in self.base_url:
            if '/baseR4' not in self.base_url:
                raise Exception(f"Connection failed. For HAPI FHIR servers, please include '/baseR4' in the URL. Try 'https://hapi.fhir.org/baseR4'")
        
        # Special case for Azure Health Data Services FHIR
        if self.base_url and ('azurehealthcareapis.com' in self.base_url or 'fhir.azurehealthcareapis.com' in self.base_url):
            raise Exception(f"Connection failed. For Azure Health Data Services FHIR, ensure you're using the full service URL including the FHIR service name and correct authentication.")
        
        # Generic error message if no specific case applied
        if last_exception:
            raise Exception(f"Connection test failed: {str(last_exception)}")
        else:
            raise Exception("Connection failed. The server did not respond to any known FHIR endpoints.")
    
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
            
        # At this point, we know self.base_url is not None due to the is_configured check
        # but we'll still be defensive with our handling
        
        try:
            # Try standard metadata endpoint
            url = urljoin(self.base_url, 'metadata')
            response = requests.get(
                url, 
                headers=self.headers,
                auth=self.auth,
                timeout=10
            )
            
            # If that fails, try appending /metadata to the base URL directly
            # This handles cases where the base URL already includes the FHIR version path
            if response.status_code == 404:
                # Safely check if base_url ends with /
                alternate_url = None
                if self.base_url:  # Additional null check
                    if not self.base_url.endswith('/'):
                        alternate_url = f"{self.base_url}/metadata"
                    else:
                        alternate_url = f"{self.base_url}metadata"
                        
                if alternate_url:  # Only try if we have a valid URL
                    response = requests.get(
                        alternate_url,
                        headers=self.headers,
                        auth=self.auth,
                        timeout=10
                    )
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching FHIR metadata: {str(e)}")
            
            # Special case for HAPI FHIR server
            if self.base_url and 'hapi.fhir.org' in self.base_url and '/baseR4' not in self.base_url:
                raise Exception(f"Metadata request failed. For HAPI FHIR, please include '/baseR4' in the URL. Try 'hapi.fhir.org/baseR4'")
                
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
        
        response = None  # Initialize response to avoid 'possibly unbound' error
        
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
            if response and response.status_code == 404:
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
        response = None
        
        try:
            # Handle the special case for HAPI FHIR server
            url = urljoin(self.base_url, resource_type)
            response = requests.get(
                url, 
                headers=self.headers,
                auth=self.auth,
                params=params,
                timeout=10
            )
            
            # Special handling for HAPI FHIR server if needed
            if response.status_code == 404 and self.base_url and 'hapi.fhir.org' in self.base_url:
                if '/baseR4' not in self.base_url:
                    raise Exception(f"Resource search failed. For HAPI FHIR, please include '/baseR4' in the base URL. Try 'hapi.fhir.org/baseR4'")
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error searching for {resource_type} resources: {str(e)}")
            if response and response.status_code == 404:
                raise Exception(f"Resource type {resource_type} not found or not supported by this server")
            raise Exception(f"Resource search failed: {str(e)}")
