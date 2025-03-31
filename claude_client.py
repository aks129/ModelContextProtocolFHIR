import os
import json
import logging
import anthropic
from anthropic import Anthropic

logger = logging.getLogger('claude_client')

class ClaudeClient:
    """
    Client for interacting with Claude AI.
    Provides methods for generating responses based on FHIR data.
    """
    
    def __init__(self):
        """Initialize the Claude client with API key from environment variables."""
        self.client = None
        self._initialize_client()
        
    def _initialize_client(self):
        """Initialize the Anthropic client if API key is available."""
        api_key = os.environ.get('ANTHROPIC_API_KEY')
        if api_key:
            try:
                # First try - if API key starts with sk-ant-, use it directly
                if api_key.startswith('sk-ant-'):
                    self.client = Anthropic(api_key=api_key)
                    logger.info("Claude client initialized successfully")
                # Second try - if API key doesn't start with sk-ant-, add the prefix
                else:
                    formatted_key = f"sk-ant-{api_key}"
                    self.client = Anthropic(api_key=formatted_key)
                    logger.info("Claude client initialized successfully with formatted key")
            except Exception as e:
                logger.error(f"Error initializing Claude client: {str(e)}")
                self.client = None
        else:
            logger.warning("ANTHROPIC_API_KEY not found in environment variables")
            self.client = None
    
    def is_configured(self):
        """Check if the client is configured with an API key and initialized."""
        return self.client is not None
        
    def generate_response(self, prompt, model="claude-3-haiku-20240307", max_tokens=1000, system_prompt=None):
        """
        Generate a response from Claude based on a prompt.
        
        Args:
            prompt (str): The user prompt to send to Claude
            model (str): Claude model to use (default: claude-3-haiku-20240307)
            max_tokens (int): Maximum tokens in the response
            system_prompt (str): Optional system prompt
            
        Returns:
            str: The generated response
            
        Raises:
            Exception: If request fails
        """
        if not self.is_configured():
            raise Exception("Claude client not configured. API key may be missing.")
            
        try:
            logger.debug(f"Generating response with model {model}, max_tokens {max_tokens}")
            
            # Build the message parameters
            message_params = {
                "model": model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            }
            
            # Add system prompt if provided
            if system_prompt:
                message_params["system"] = system_prompt
                
            response = self.client.messages.create(**message_params)
            
            # Extract the content from the response
            return response.content[0].text
            
        except Exception as e:
            logger.error(f"Error generating response: {str(e)}")
            raise Exception(f"Failed to generate response: {str(e)}")
    
    def analyze_fhir_resource(self, resource, model="claude-3-haiku-20240307", max_tokens=1500):
        """
        Analyze a FHIR resource and generate insights.
        
        Args:
            resource (dict): The FHIR resource to analyze
            model (str): Claude model to use
            max_tokens (int): Maximum tokens in the response
            
        Returns:
            str: Analysis of the FHIR resource
            
        Raises:
            Exception: If request fails
        """
        if not self.is_configured():
            raise Exception("Claude client not configured. API key may be missing.")
            
        try:
            # Format the resource as a pretty JSON string
            resource_json = json.dumps(resource, indent=2)
            
            # Craft system prompt for FHIR resource analysis
            system_prompt = """
            You are an expert in FHIR (Fast Healthcare Interoperability Resources) analysis.
            Your task is to analyze a FHIR resource and provide insights.
            
            For each resource:
            1. Identify the resource type and key information
            2. Highlight clinically relevant data
            3. Note any missing or potentially inconsistent elements
            4. Suggest potential uses for this data in a healthcare application
            
            Structure your response in clear sections, using bullet points where appropriate.
            """
            
            # Craft user prompt with the resource
            user_prompt = f"""
            Please analyze the following FHIR resource:
            
            ```json
            {resource_json}
            ```
            
            What insights can you provide about this resource?
            """
            
            # Generate the analysis
            message_params = {
                "model": model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "user", "content": user_prompt}
                ],
                "system": system_prompt
            }
            
            response = self.client.messages.create(**message_params)
            
            # Extract the content from the response
            return response.content[0].text
                
        except Exception as e:
            logger.error(f"Error analyzing FHIR resource: {str(e)}")
            raise Exception(f"Failed to analyze FHIR resource: {str(e)}")
    
    def generate_fhir_query(self, natural_language_query, model="claude-3-haiku-20240307", max_tokens=500):
        """
        Generate FHIR search parameters based on a natural language query.
        
        Args:
            natural_language_query (str): The natural language query to convert to FHIR search
            model (str): Claude model to use
            max_tokens (int): Maximum tokens in the response
            
        Returns:
            dict: Dictionary of FHIR search parameters
            
        Raises:
            Exception: If request fails
        """
        if not self.is_configured():
            raise Exception("Claude client not configured. API key may be missing.")
            
        try:
            # Craft system prompt for FHIR query generation
            system_prompt = """
            You are an expert in generating FHIR R4 search queries from natural language.
            Convert natural language healthcare queries into structured FHIR search parameters.
            
            Your response should be a JSON object with:
            
            1. "resourceType": The primary FHIR resource type to search for (e.g., Patient, Observation, Condition)
            2. "parameters": An object containing key-value pairs of valid FHIR search parameters
            
            IMPORTANT RULES:
            1. ONLY use valid FHIR R4 search parameters according to the HL7 FHIR R4 specification
            2. DO NOT use complex syntax in parameter values (no & or | characters)
            3. For searching diseases like diabetes, use code=diabetes (simple value only)
            4. Generate ONE parameter at a time - each key-value pair should be simple
            5. Never create parameter names that don't exist in the FHIR spec
            6. ALWAYS include code parameter when searching for conditions by diagnosis
            
            Common valid Patient search parameters:
            - _id: Patient resource ID
            - identifier: Patient identifier (MRN, etc)
            - name: Patient name (supports partial matches)
            - family: Family name (supports partial matches)
            - given: Given name (supports partial matches)
            - gender: Patient gender (male, female, other, unknown)
            - birthdate: Patient's date of birth (exact or range with operators)
            - address: Address field (supports partial matches)
            - email: Patient's email address
            - phone: Patient's phone number
            - _count: Number of results per page
            
            Common valid Condition search parameters:
            - patient: Reference to a patient
            - clinical-status: active, recurrence, relapse, inactive, remission, resolved
            - code: Standard medical code (SNOMED/ICD/LOINC)
            - code:text: Text search for condition description (diabetes, headache, etc.)
            - onset-date: Date when condition began
            - recorded-date: Date when condition was recorded
            - _count: Number of results per page
            - _summary: Use "count" to get total count only
            
            Common search parameter modifiers:
            - :exact - Exact string match
            - :contains - String contains search
            - gt, lt, ge, le - Comparison operators (for dates and numbers)
            
            DIABETES SEARCH EXAMPLE:
            When searching for diabetes, use the Condition resource with text search:
            {
              "resourceType": "Condition",
              "parameters": {
                "code:text": "diabetes",
                "_summary": "count"
              }
            }
            
            AGE SEARCH EXAMPLE:
            To search for patients by age, convert to birthdate range with TWO SEPARATE parameters:
            {
              "resourceType": "Patient",
              "parameters": {
                "birthdate": "ge2024-01-01",
                "_count": "100"
              }
            }
            
            Make sure your response ONLY contains valid JSON format with no explanations or comments.
            """
            
            # Generate the FHIR search parameters
            message_params = {
                "model": model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "user", "content": natural_language_query}
                ],
                "system": system_prompt
            }
            
            response = self.client.messages.create(**message_params)
            
            # Extract the content from the response and parse as JSON
            response_text = response.content[0].text
            
            # The output might have markdown backticks for JSON, so we need to clean it
            cleaned_response = response_text.strip()
            if cleaned_response.startswith("```json"):
                cleaned_response = cleaned_response[7:]
            elif cleaned_response.startswith("```"):
                cleaned_response = cleaned_response[3:]
            if cleaned_response.endswith("```"):
                cleaned_response = cleaned_response[:-3]
                
            cleaned_response = cleaned_response.strip()
            
            try:
                # Try to parse the response as JSON
                result = json.loads(cleaned_response)
                
                # Validate the result has the expected structure
                if not isinstance(result, dict):
                    logger.warning(f"Claude returned non-dictionary JSON: {cleaned_response}")
                    result = {"resourceType": "Patient", "parameters": {}}
                
                # Ensure resourceType and parameters exist
                if "resourceType" not in result:
                    logger.warning("resourceType missing from Claude response, defaulting to Patient")
                    result["resourceType"] = "Patient"
                
                if "parameters" not in result:
                    logger.warning("parameters missing from Claude response, using empty parameters")
                    result["parameters"] = {}
                
                # Sanitize parameter values - remove any invalid characters
                cleaned_params = {}
                for param_name, param_value in result["parameters"].items():
                    # Skip invalid parameters
                    if not param_name or not isinstance(param_name, str):
                        continue
                        
                    # Convert to string if not already
                    if not isinstance(param_value, str):
                        param_value = str(param_value)
                    
                    # Remove any pipe characters, URLs, and complex operators
                    if '|' in param_value:
                        param_value = param_value.split('|')[0]
                    
                    # Remove any http:// or https:// URLs
                    if 'http://' in param_value or 'https://' in param_value:
                        param_value = param_value.split('http')[0].strip()
                        
                    # Ensure no empty parameter values
                    if param_value.strip():
                        cleaned_params[param_name] = param_value
                
                # Special handling for searches about conditions (especially diabetes)
                if result["resourceType"] == "Condition":
                    # Check if code:text is already present
                    if "code:text" not in cleaned_params and "code" not in cleaned_params:
                        # For diabetes searches
                        if "diabetes" in natural_language_query.lower():
                            logger.debug("Adding missing code:text=diabetes parameter for diabetes search")
                            cleaned_params["code:text"] = "diabetes"
                        # For any other medical condition searches
                        else:
                            # Extract potential condition from the query
                            for disease in ["hypertension", "asthma", "cancer", "heart disease", 
                                           "copd", "depression", "arthritis", "alzheimer", "headache"]:
                                if disease in natural_language_query.lower():
                                    logger.debug(f"Adding missing code:text={disease} parameter")
                                    cleaned_params["code:text"] = disease
                                    break
                    
                    # If user explicitly asks for code:text search
                    elif "code:text" in natural_language_query.lower() and "code:text" not in cleaned_params:
                        # Extract the condition after "code:text"
                        import re
                        match = re.search(r"code:text\s+(\w+)", natural_language_query.lower())
                        if match:
                            condition = match.group(1)
                            logger.debug(f"Detected explicit code:text request for {condition}")
                            cleaned_params["code:text"] = condition
                            
                    # Convert code to code:text for better text-based searches
                    if "code" in cleaned_params and "code:text" not in cleaned_params:
                        condition = cleaned_params.pop("code")
                        logger.debug(f"Converting code to code:text for {condition}")
                        cleaned_params["code:text"] = condition
                
                # If asking about "how many patients" but searching Condition resource
                if "how many patient" in natural_language_query.lower() and result["resourceType"] == "Condition":
                    # Add a parameter to group by patient
                    logger.debug("Adding _summary=count parameter for counting patients with conditions")
                    cleaned_params["_summary"] = "count"
                
                # Replace the parameters with sanitized ones
                result["parameters"] = cleaned_params
                
                # Always add _count parameter to limit results
                if "_count" not in result["parameters"]:
                    result["parameters"]["_count"] = "50"
                
                return result
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Claude response as JSON: {e}. Response: {cleaned_response}")
                # If parsing fails, return a default structure
                return {
                    "resourceType": "Patient",
                    "parameters": {},
                    "error": f"Failed to parse response: {str(e)}"
                }
                
        except Exception as e:
            logger.error(f"Error generating FHIR query: {str(e)}")
            raise Exception(f"Failed to generate FHIR query: {str(e)}")