from marshmallow import Schema, fields, validates, ValidationError

class FHIRServerSchema(Schema):
    """Schema for validating FHIR server configuration data."""
    
    base_url = fields.URL(required=True, error_messages={'required': 'Base URL is required'})
    auth_type = fields.String(required=False, validate=lambda x: x in ['none', 'basic', 'token'])
    api_key = fields.String(required=False)
    username = fields.String(required=False)
    password = fields.String(required=False)
    name = fields.String(required=False)
    
    @validates('auth_type')
    def validate_auth_credentials(self, auth_type):
        """Validate that the necessary credentials are provided for the chosen auth type."""
        if auth_type == 'basic':
            if not self.context.get('username') or not self.context.get('password'):
                raise ValidationError("Username and password are required for basic authentication")
        
        if auth_type == 'token' and not self.context.get('api_key'):
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
