from marshmallow import Schema, fields, validates, ValidationError, EXCLUDE

class FHIRServerSchema(Schema):
    """Schema for validating FHIR server configuration data."""
    
    class Meta:
        # Ignore unknown fields instead of raising errors
        unknown = EXCLUDE
    
    base_url = fields.URL(required=True, error_messages={'required': 'Base URL is required'})
    auth_type = fields.String(required=False, validate=lambda x: x in ['none', 'basic', 'token'])
    api_key = fields.String(required=False, allow_none=True)
    username = fields.String(required=False, allow_none=True)
    password = fields.String(required=False, allow_none=True)
    name = fields.String(required=False, allow_none=True)
    is_default = fields.Boolean(required=False, allow_none=True)
    config_id = fields.String(required=False, allow_none=True)
    
    @validates('auth_type')
    def validate_auth_credentials(self, auth_type):
        """Validate that the necessary credentials are provided for the chosen auth type."""
        # Skip validation for test-connection endpoint
        if self.context.get('skip_auth_validation'):
            return
            
        data = self.context.get('data', {})
        
        if auth_type == 'basic':
            username = data.get('username')
            password = data.get('password')
            if not username or not password:
                raise ValidationError("Username and password are required for basic authentication")
        
        if auth_type == 'token':
            api_key = data.get('api_key')
            if not api_key:
                raise ValidationError("API key is required for token authentication")

class FHIRResourceRequestSchema(Schema):
    """Schema for validating FHIR resource requests."""
    
    resource_type = fields.String(required=True)
    search_params = fields.Dict(keys=fields.String(), values=fields.String())
    
    @validates('resource_type')
    def validate_resource_type(self, resource_type):
        """Validate that the resource type is a proper FHIR resource type."""
        # List of common FHIR resource types
        valid_resource_types = [
            'Patient', 'Observation', 'Condition', 'Procedure', 'MedicationRequest',
            'Encounter', 'DiagnosticReport', 'AllergyIntolerance', 'Immunization',
            'CarePlan', 'Goal', 'Practitioner', 'Organization', 'Location',
            'Device', 'Specimen', 'Medication', 'Bundle'
        ]
        
        if resource_type not in valid_resource_types and not resource_type.startswith('Binary'):
            raise ValidationError(f"Invalid FHIR resource type: {resource_type}")
