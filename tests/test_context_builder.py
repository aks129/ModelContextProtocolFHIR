"""
Tests for the Context Builder service.
"""

import json
import pytest


class TestContextBuilder:
    """Test context builder functionality."""

    def test_redaction_strips_identifiers(self, client, sample_bundle):
        """Context builder should redact identifiers to last 4 chars."""
        resp = client.post('/r6/fhir/Bundle/$ingest-context',
                          data=json.dumps(sample_bundle),
                          content_type='application/json')
        context_id = resp.get_json()['context_id']

        # Read the stored patient
        patient_resp = client.get('/r6/fhir/Patient/test-patient-1')
        data = patient_resp.get_json()

        # Check identifier redaction
        if 'identifier' in data:
            for ident in data['identifier']:
                if 'value' in ident:
                    assert ident['value'].startswith('***')

    def test_redaction_removes_address_lines(self, client, sample_bundle):
        """Context builder should remove address line details."""
        resp = client.post('/r6/fhir/Bundle/$ingest-context',
                          data=json.dumps(sample_bundle),
                          content_type='application/json')

        # Read the stored patient
        patient_resp = client.get('/r6/fhir/Patient/test-patient-1')
        data = patient_resp.get_json()

        # Check address redaction
        if 'address' in data:
            for addr in data['address']:
                assert 'line' not in addr

    def test_context_includes_provenance_hashes(self, client, sample_bundle):
        """Context items should include SHA-256 hashes."""
        resp = client.post('/r6/fhir/Bundle/$ingest-context',
                          data=json.dumps(sample_bundle),
                          content_type='application/json')
        data = resp.get_json()

        for item in data['items']:
            assert 'sha256' in item
            assert len(item['sha256']) == 64  # SHA-256 hex length

    def test_context_has_slice_names(self, client, sample_bundle):
        """Context items should be assigned slice names."""
        resp = client.post('/r6/fhir/Bundle/$ingest-context',
                          data=json.dumps(sample_bundle),
                          content_type='application/json')
        data = resp.get_json()

        slices = {item['slice_name'] for item in data['items']}
        assert 'demographics' in slices  # Patient
        assert 'observations' in slices  # Observation

    def test_context_has_expiry(self, client, sample_bundle):
        """Context envelope should have an expiry timestamp."""
        resp = client.post('/r6/fhir/Bundle/$ingest-context',
                          data=json.dumps(sample_bundle),
                          content_type='application/json')
        data = resp.get_json()
        assert 'expires_at' in data
        assert data['expires_at'] is not None
