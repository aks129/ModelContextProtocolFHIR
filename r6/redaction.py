"""
FHIR Resource Redaction.

Standard redaction profile for PHI protection applied consistently
on all resource access paths (not just context ingestion).

- Names: Keep family name, redact given names beyond first initial
- Identifiers: Keep last 4 characters
- Addresses: Remove line/text, keep city/state/country
- Telecom: Replace values with [Redacted]
- Birth dates: Truncate to year only
- Photos: Remove entirely
- Narratives: Replace with redacted div
- Notes/comments: Replace with [Redacted]
"""

import json


def apply_redaction(resource):
    """
    Apply standard redaction profile to a FHIR resource.
    Returns a deep copy with PHI fields redacted.
    """
    redacted = json.loads(json.dumps(resource))  # Deep copy
    _redact_fields(redacted)

    # Also redact any contained resources
    if 'contained' in redacted and isinstance(redacted['contained'], list):
        for contained in redacted['contained']:
            if isinstance(contained, dict):
                _redact_fields(contained)

    return redacted


def _redact_fields(resource):
    """Redact PHI fields from a single resource dict (in-place)."""
    # Redact names (keep family, truncate given to first initial)
    if 'name' in resource and isinstance(resource['name'], list):
        for name_entry in resource['name']:
            if isinstance(name_entry, dict):
                if 'given' in name_entry and isinstance(name_entry['given'], list):
                    name_entry['given'] = [
                        g[0] + '.' if isinstance(g, str) and len(g) > 0 else g
                        for g in name_entry['given']
                    ]
                name_entry.pop('text', None)

    # Truncate birth date to year only
    if 'birthDate' in resource and isinstance(resource['birthDate'], str):
        resource['birthDate'] = resource['birthDate'][:4]

    # Remove photos
    resource.pop('photo', None)

    # Remove text narratives
    if 'text' in resource:
        resource['text'] = {
            'status': 'empty',
            'div': '<div xmlns="http://www.w3.org/1999/xhtml">[Redacted]</div>'
        }

    # Redact identifiers (keep last 4 characters)
    if 'identifier' in resource and isinstance(resource['identifier'], list):
        for ident in resource['identifier']:
            if 'value' in ident and isinstance(ident['value'], str):
                val = ident['value']
                if len(val) > 4:
                    ident['value'] = '***' + val[-4:]

    # Remove full addresses
    if 'address' in resource and isinstance(resource['address'], list):
        for addr in resource['address']:
            addr.pop('line', None)
            addr.pop('text', None)
            # Keep city, state, country for demographics

    # Redact telecom (phone numbers, emails)
    if 'telecom' in resource and isinstance(resource['telecom'], list):
        for telecom in resource['telecom']:
            if 'value' in telecom and isinstance(telecom['value'], str):
                telecom['value'] = '[Redacted]'

    # Remove notes/comments
    for field in ['note', 'comment']:
        if field in resource:
            if isinstance(resource[field], list):
                resource[field] = [{'text': '[Redacted]'}]
            elif isinstance(resource[field], str):
                resource[field] = '[Redacted]'
