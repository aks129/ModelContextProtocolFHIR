"""
Tests for R6 FHIR REST endpoints.
"""

import json
import pytest


class TestR6Metadata:
    """Test /r6/fhir/metadata endpoint (exempt from tenant requirement)."""

    def test_metadata_returns_capability_statement(self, client):
        resp = client.get('/r6/fhir/metadata')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['resourceType'] == 'CapabilityStatement'

    def test_metadata_has_r6_fhir_version(self, client):
        resp = client.get('/r6/fhir/metadata')
        data = resp.get_json()
        assert data['fhirVersion'] == '6.0.0-ballot3'

    def test_metadata_lists_supported_resources(self, client):
        resp = client.get('/r6/fhir/metadata')
        data = resp.get_json()
        rest = data['rest'][0]
        resource_types = [r['type'] for r in rest['resource']]
        assert 'Patient' in resource_types
        assert 'Observation' in resource_types
        assert 'AuditEvent' in resource_types

    def test_metadata_lists_operations(self, client):
        resp = client.get('/r6/fhir/metadata')
        data = resp.get_json()
        ops = data['rest'][0]['operation']
        op_names = [o['name'] for o in ops]
        assert 'validate' in op_names
        assert 'ingest-context' in op_names


class TestTenantEnforcement:
    """Test mandatory tenant isolation."""

    def test_read_without_tenant_returns_400(self, client):
        resp = client.get('/r6/fhir/Patient/test-1')
        assert resp.status_code == 400
        data = resp.get_json()
        assert 'X-Tenant-Id' in data['issue'][0]['diagnostics']

    def test_create_without_tenant_returns_400(self, client, sample_patient):
        resp = client.post('/r6/fhir/Patient',
                          data=json.dumps(sample_patient),
                          content_type='application/json')
        assert resp.status_code == 400

    def test_metadata_exempt_from_tenant(self, client):
        resp = client.get('/r6/fhir/metadata')
        assert resp.status_code == 200


class TestStepUpToken:
    """Test HMAC step-up token validation."""

    def test_create_with_invalid_token_rejected(self, client, sample_patient, tenant_headers):
        headers = {**tenant_headers, 'X-Step-Up-Token': 'bogus-token'}
        resp = client.post('/r6/fhir/Patient',
                          data=json.dumps(sample_patient),
                          content_type='application/json',
                          headers=headers)
        assert resp.status_code == 403
        data = resp.get_json()
        assert 'token' in data['issue'][0]['diagnostics'].lower()

    def test_create_with_valid_token_succeeds(self, client, sample_patient, auth_headers):
        resp = client.post('/r6/fhir/Patient',
                          data=json.dumps(sample_patient),
                          content_type='application/json',
                          headers=auth_headers)
        assert resp.status_code == 201


class TestR6CRUD:
    """Test R6 FHIR CRUD operations."""

    def test_create_requires_step_up_token(self, client, sample_patient, tenant_headers):
        resp = client.post('/r6/fhir/Patient',
                          data=json.dumps(sample_patient),
                          content_type='application/json',
                          headers=tenant_headers)
        assert resp.status_code == 403
        data = resp.get_json()
        assert data['resourceType'] == 'OperationOutcome'

    def test_create_with_step_up_token(self, client, sample_patient, auth_headers):
        resp = client.post('/r6/fhir/Patient',
                          data=json.dumps(sample_patient),
                          content_type='application/json',
                          headers=auth_headers)
        assert resp.status_code == 201
        data = resp.get_json()
        assert data['resourceType'] == 'Patient'
        assert 'meta' in data
        assert data['meta']['versionId'] == '1'

    def test_read_resource(self, client, sample_patient, auth_headers, tenant_headers):
        # Create first
        client.post('/r6/fhir/Patient',
                    data=json.dumps(sample_patient),
                    content_type='application/json',
                    headers=auth_headers)

        # Read
        resp = client.get(f'/r6/fhir/Patient/{sample_patient["id"]}',
                         headers=tenant_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['resourceType'] == 'Patient'
        assert data['id'] == sample_patient['id']

    def test_read_applies_redaction(self, client, sample_patient, auth_headers, tenant_headers):
        """Direct reads must also apply redaction (not just context envelope)."""
        client.post('/r6/fhir/Patient',
                    data=json.dumps(sample_patient),
                    content_type='application/json',
                    headers=auth_headers)

        resp = client.get(f'/r6/fhir/Patient/{sample_patient["id"]}',
                         headers=tenant_headers)
        data = resp.get_json()

        # Identifiers should be redacted
        for ident in data.get('identifier', []):
            if 'value' in ident:
                assert ident['value'].startswith('***')

        # Address lines should be removed
        for addr in data.get('address', []):
            assert 'line' not in addr

    def test_read_nonexistent_returns_404(self, client, tenant_headers):
        resp = client.get('/r6/fhir/Patient/nonexistent',
                         headers=tenant_headers)
        assert resp.status_code == 404

    def test_update_resource(self, client, sample_patient, auth_headers):
        # Create
        client.post('/r6/fhir/Patient',
                    data=json.dumps(sample_patient),
                    content_type='application/json',
                    headers=auth_headers)

        # Update
        sample_patient['gender'] = 'female'
        resp = client.put(f'/r6/fhir/Patient/{sample_patient["id"]}',
                         data=json.dumps(sample_patient),
                         content_type='application/json',
                         headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['meta']['versionId'] == '2'

    def test_unsupported_resource_type(self, client, tenant_headers):
        resp = client.get('/r6/fhir/MedicationRequest/123',
                         headers=tenant_headers)
        assert resp.status_code == 400

    def test_tenant_isolation_prevents_cross_tenant_read(self, client, sample_patient, auth_headers):
        """Resources created by one tenant should not be visible to another."""
        # Create with test tenant
        client.post('/r6/fhir/Patient',
                    data=json.dumps(sample_patient),
                    content_type='application/json',
                    headers=auth_headers)

        # Read with a different tenant should fail
        resp = client.get(f'/r6/fhir/Patient/{sample_patient["id"]}',
                         headers={'X-Tenant-Id': 'other-tenant'})
        assert resp.status_code == 404


class TestAuditEventImmutability:
    """Test that AuditEvent is system-managed and append-only."""

    def test_create_audit_event_via_api_blocked(self, client, auth_headers):
        audit = {
            'resourceType': 'AuditEvent',
            'id': 'fake-audit',
            'type': {'code': '110100'}
        }
        resp = client.post('/r6/fhir/AuditEvent',
                          data=json.dumps(audit),
                          content_type='application/json',
                          headers=auth_headers)
        assert resp.status_code == 403
        data = resp.get_json()
        assert 'system-managed' in data['issue'][0]['diagnostics']


class TestR6Validate:
    """Test $validate endpoint."""

    def test_validate_valid_patient(self, client, sample_patient, tenant_headers):
        resp = client.post('/r6/fhir/Patient/$validate',
                          data=json.dumps(sample_patient),
                          content_type='application/json',
                          headers=tenant_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['resourceType'] == 'OperationOutcome'

    def test_validate_invalid_observation(self, client, tenant_headers):
        # Observation missing required status and code
        invalid_obs = {'resourceType': 'Observation'}
        resp = client.post('/r6/fhir/Observation/$validate',
                          data=json.dumps(invalid_obs),
                          content_type='application/json',
                          headers=tenant_headers)
        assert resp.status_code == 422
        data = resp.get_json()
        assert data['resourceType'] == 'OperationOutcome'
        issues = data['issue']
        assert any('status' in i.get('diagnostics', '') for i in issues)

    def test_validate_missing_body(self, client, tenant_headers):
        resp = client.post('/r6/fhir/Patient/$validate',
                          content_type='application/json',
                          headers=tenant_headers)
        assert resp.status_code == 400


class TestR6ContextIngestion:
    """Test Bundle ingestion and context builder."""

    def test_ingest_bundle_creates_context(self, client, sample_bundle, tenant_headers):
        resp = client.post('/r6/fhir/Bundle/$ingest-context',
                          data=json.dumps(sample_bundle),
                          content_type='application/json',
                          headers=tenant_headers)
        assert resp.status_code == 201
        data = resp.get_json()
        assert 'context_id' in data
        assert data['resource_count'] == 2
        assert data['patient_ref'] == 'Patient/test-patient-1'

    def test_get_context_envelope(self, client, sample_bundle, tenant_headers):
        # Ingest
        ingest_resp = client.post('/r6/fhir/Bundle/$ingest-context',
                                  data=json.dumps(sample_bundle),
                                  content_type='application/json',
                                  headers=tenant_headers)
        context_id = ingest_resp.get_json()['context_id']

        # Get context
        resp = client.get(f'/r6/fhir/context/{context_id}',
                         headers=tenant_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['context_id'] == context_id
        assert data['item_count'] == 2

    def test_ingest_empty_bundle_fails(self, client, tenant_headers):
        empty_bundle = {'resourceType': 'Bundle', 'type': 'collection', 'entry': []}
        resp = client.post('/r6/fhir/Bundle/$ingest-context',
                          data=json.dumps(empty_bundle),
                          content_type='application/json',
                          headers=tenant_headers)
        assert resp.status_code == 400

    def test_ingest_non_bundle_fails(self, client, sample_patient, tenant_headers):
        resp = client.post('/r6/fhir/Bundle/$ingest-context',
                          data=json.dumps(sample_patient),
                          content_type='application/json',
                          headers=tenant_headers)
        assert resp.status_code == 400


class TestR6AuditEvents:
    """Test AuditEvent recording and querying."""

    def test_read_generates_audit_event(self, client, sample_patient,
                                         auth_headers, tenant_headers):
        # Create a resource
        client.post('/r6/fhir/Patient',
                    data=json.dumps(sample_patient),
                    content_type='application/json',
                    headers=auth_headers)

        # Read it
        client.get(f'/r6/fhir/Patient/{sample_patient["id"]}',
                  headers=tenant_headers)

        # Check audit events
        resp = client.get('/r6/fhir/AuditEvent',
                         headers=tenant_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['total'] >= 1

    def test_audit_events_filterable_by_context(self, client, sample_bundle, tenant_headers):
        # Ingest a bundle (creates a context and audit events)
        ingest_resp = client.post('/r6/fhir/Bundle/$ingest-context',
                                  data=json.dumps(sample_bundle),
                                  content_type='application/json',
                                  headers=tenant_headers)
        context_id = ingest_resp.get_json()['context_id']

        # Query audit events for this context
        resp = client.get(f'/r6/fhir/AuditEvent?context-id={context_id}',
                         headers=tenant_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['resourceType'] == 'Bundle'


class TestR6ImportStub:
    """Test cross-version import stub."""

    def test_import_stub_returns_accepted(self, client, tenant_headers):
        bundle = {
            'resourceType': 'Bundle',
            'type': 'collection',
            'entry': [
                {'resource': {'resourceType': 'Patient', 'id': 'r4-patient'}}
            ]
        }
        resp = client.post('/r6/fhir/$import-stub?source-version=R4',
                          data=json.dumps(bundle),
                          content_type='application/json',
                          headers=tenant_headers)
        assert resp.status_code == 202
        data = resp.get_json()
        assert '_import_stub' in data
        assert data['_import_stub']['source_version'] == 'R4'
        assert data['_import_stub']['entry_count'] == 1
        assert data['_import_stub']['entries'][0]['transform_status'] == 'needs-transform'
