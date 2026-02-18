"""
R6 FHIR Validator.

Validates resources against R6 core definitions.
Can proxy to the HL7 validator-wrapper when available,
falls back to structural validation for the showcase.
"""

import json
import logging
import os
import requests

logger = logging.getLogger(__name__)

# Validator service URL (HL7 validator-wrapper)
VALIDATOR_URL = os.environ.get('FHIR_VALIDATOR_URL', 'http://localhost:8080')

# R6 supported resource types
R6_RESOURCE_TYPES = [
    'Patient', 'Encounter', 'Observation', 'Bundle',
    'AuditEvent', 'Consent', 'OperationOutcome'
]


class R6Validator:
    """Validates FHIR R6 resources."""

    def __init__(self, validator_url=None):
        self.validator_url = validator_url or VALIDATOR_URL
        self._validator_available = None

    def validate_resource(self, resource, mode='no-action', profile=None):
        """
        Validate a FHIR R6 resource.

        First tries the external HL7 validator-wrapper.
        Falls back to structural validation if unavailable.

        Args:
            resource: FHIR resource dict
            mode: Validation mode (no-action, create, update, delete)
            profile: Optional profile URL to validate against

        Returns:
            dict with 'valid' (bool) and 'operation_outcome' (FHIR OperationOutcome)
        """
        # Try external validator first
        if self._is_validator_available():
            try:
                return self._validate_external(resource, profile)
            except Exception as e:
                logger.warning(f'External validator failed, falling back to structural: {e}')

        # Structural validation fallback
        return self._validate_structural(resource)

    def _is_validator_available(self):
        """Check if the external validator service is reachable."""
        if self._validator_available is not None:
            return self._validator_available

        try:
            resp = requests.get(f'{self.validator_url}/health', timeout=2)
            self._validator_available = resp.status_code < 400
        except Exception:
            self._validator_available = False

        return self._validator_available

    def _validate_external(self, resource, profile=None):
        """Validate using the HL7 validator-wrapper service."""
        url = f'{self.validator_url}/validate'
        params = {}
        if profile:
            params['profile'] = profile

        headers = {'Content-Type': 'application/fhir+json'}
        resp = requests.post(
            url, json=resource, params=params, headers=headers, timeout=30
        )

        if resp.status_code == 200:
            outcome = resp.json()
            issues = outcome.get('issue', [])
            has_errors = any(
                i.get('severity') in ('error', 'fatal') for i in issues
            )
            return {
                'valid': not has_errors,
                'operation_outcome': outcome
            }

        # Non-200 response from validator
        return {
            'valid': False,
            'operation_outcome': {
                'resourceType': 'OperationOutcome',
                'issue': [{
                    'severity': 'error',
                    'code': 'exception',
                    'diagnostics': f'Validator returned HTTP {resp.status_code}'
                }]
            }
        }

    def _validate_structural(self, resource):
        """
        Perform basic structural validation on a FHIR resource.
        This is a fallback when the external validator is unavailable.
        """
        issues = []

        # Check resourceType
        resource_type = resource.get('resourceType')
        if not resource_type:
            issues.append({
                'severity': 'error',
                'code': 'required',
                'diagnostics': 'resourceType is required',
                'expression': ['resourceType']
            })
        elif resource_type not in R6_RESOURCE_TYPES:
            issues.append({
                'severity': 'error',
                'code': 'value',
                'diagnostics': f'Unsupported resource type: {resource_type}',
                'expression': ['resourceType']
            })

        # Resource-specific structural checks
        if resource_type == 'Patient':
            issues.extend(self._validate_patient(resource))
        elif resource_type == 'Observation':
            issues.extend(self._validate_observation(resource))
        elif resource_type == 'Encounter':
            issues.extend(self._validate_encounter(resource))

        has_errors = any(i['severity'] in ('error', 'fatal') for i in issues)

        if not issues:
            issues.append({
                'severity': 'information',
                'code': 'informational',
                'diagnostics': 'Structural validation passed (R6 ballot, external validator unavailable)'
            })

        return {
            'valid': not has_errors,
            'operation_outcome': {
                'resourceType': 'OperationOutcome',
                'issue': issues
            }
        }

    def _validate_patient(self, resource):
        """Validate Patient-specific structure."""
        issues = []
        # Patient should have at least a name or identifier
        if not resource.get('name') and not resource.get('identifier'):
            issues.append({
                'severity': 'warning',
                'code': 'business-rule',
                'diagnostics': 'Patient should have at least a name or identifier',
                'expression': ['Patient']
            })
        return issues

    def _validate_observation(self, resource):
        """Validate Observation-specific structure."""
        issues = []
        if not resource.get('status'):
            issues.append({
                'severity': 'error',
                'code': 'required',
                'diagnostics': 'Observation.status is required',
                'expression': ['Observation.status']
            })
        if not resource.get('code'):
            issues.append({
                'severity': 'error',
                'code': 'required',
                'diagnostics': 'Observation.code is required',
                'expression': ['Observation.code']
            })
        return issues

    def _validate_encounter(self, resource):
        """Validate Encounter-specific structure."""
        issues = []
        if not resource.get('status'):
            issues.append({
                'severity': 'error',
                'code': 'required',
                'diagnostics': 'Encounter.status is required',
                'expression': ['Encounter.status']
            })
        return issues
