"""
Tests for R6 FHIR REST endpoints.
"""

import json
import pytest


class TestR6Metadata:
    """Test /r6/fhir/metadata endpoint."""

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


class TestR6CRUD:
    """Test R6 FHIR CRUD operations."""

    def test_create_requires_step_up_token(self, client, sample_patient):
        resp = client.post('/r6/fhir/Patient',
                          data=json.dumps(sample_patient),
                          content_type='application/json')
        assert resp.status_code == 403
        data = resp.get_json()
        assert data['resourceType'] == 'OperationOutcome'

    def test_create_with_step_up_token(self, client, sample_patient):
        resp = client.post('/r6/fhir/Patient',
                          data=json.dumps(sample_patient),
                          content_type='application/json',
                          headers={'X-Step-Up-Token': 'test-token'})
        assert resp.status_code == 201
        data = resp.get_json()
        assert data['resourceType'] == 'Patient'
        assert 'meta' in data
        assert data['meta']['versionId'] == '1'

    def test_read_resource(self, client, sample_patient):
        # Create first
        client.post('/r6/fhir/Patient',
                    data=json.dumps(sample_patient),
                    content_type='application/json',
                    headers={'X-Step-Up-Token': 'test-token'})

        # Read
        resp = client.get(f'/r6/fhir/Patient/{sample_patient["id"]}')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['resourceType'] == 'Patient'
        assert data['id'] == sample_patient['id']

    def test_read_nonexistent_returns_404(self, client):
        resp = client.get('/r6/fhir/Patient/nonexistent')
        assert resp.status_code == 404

    def test_update_resource(self, client, sample_patient):
        # Create
        client.post('/r6/fhir/Patient',
                    data=json.dumps(sample_patient),
                    content_type='application/json',
                    headers={'X-Step-Up-Token': 'test-token'})

        # Update
        sample_patient['gender'] = 'female'
        resp = client.put(f'/r6/fhir/Patient/{sample_patient["id"]}',
                         data=json.dumps(sample_patient),
                         content_type='application/json',
                         headers={'X-Step-Up-Token': 'test-token'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['meta']['versionId'] == '2'

    def test_unsupported_resource_type(self, client):
        resp = client.get('/r6/fhir/MedicationRequest/123')
        assert resp.status_code == 400


class TestR6Validate:
    """Test $validate endpoint."""

    def test_validate_valid_patient(self, client, sample_patient):
        resp = client.post('/r6/fhir/Patient/$validate',
                          data=json.dumps(sample_patient),
                          content_type='application/json')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['resourceType'] == 'OperationOutcome'

    def test_validate_invalid_observation(self, client):
        # Observation missing required status and code
        invalid_obs = {'resourceType': 'Observation'}
        resp = client.post('/r6/fhir/Observation/$validate',
                          data=json.dumps(invalid_obs),
                          content_type='application/json')
        assert resp.status_code == 422
        data = resp.get_json()
        assert data['resourceType'] == 'OperationOutcome'
        issues = data['issue']
        assert any('status' in i.get('diagnostics', '') for i in issues)

    def test_validate_missing_body(self, client):
        resp = client.post('/r6/fhir/Patient/$validate',
                          content_type='application/json')
        assert resp.status_code == 400


class TestR6ContextIngestion:
    """Test Bundle ingestion and context builder."""

    def test_ingest_bundle_creates_context(self, client, sample_bundle):
        resp = client.post('/r6/fhir/Bundle/$ingest-context',
                          data=json.dumps(sample_bundle),
                          content_type='application/json')
        assert resp.status_code == 201
        data = resp.get_json()
        assert 'context_id' in data
        assert data['resource_count'] == 2
        assert data['patient_ref'] == 'Patient/test-patient-1'

    def test_get_context_envelope(self, client, sample_bundle):
        # Ingest
        ingest_resp = client.post('/r6/fhir/Bundle/$ingest-context',
                                  data=json.dumps(sample_bundle),
                                  content_type='application/json')
        context_id = ingest_resp.get_json()['context_id']

        # Get context
        resp = client.get(f'/r6/fhir/context/{context_id}')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['context_id'] == context_id
        assert data['item_count'] == 2

    def test_ingest_empty_bundle_fails(self, client):
        empty_bundle = {'resourceType': 'Bundle', 'type': 'collection', 'entry': []}
        resp = client.post('/r6/fhir/Bundle/$ingest-context',
                          data=json.dumps(empty_bundle),
                          content_type='application/json')
        assert resp.status_code == 400

    def test_ingest_non_bundle_fails(self, client, sample_patient):
        resp = client.post('/r6/fhir/Bundle/$ingest-context',
                          data=json.dumps(sample_patient),
                          content_type='application/json')
        assert resp.status_code == 400


class TestR6AuditEvents:
    """Test AuditEvent recording and querying."""

    def test_read_generates_audit_event(self, client, sample_patient):
        # Create a resource
        client.post('/r6/fhir/Patient',
                    data=json.dumps(sample_patient),
                    content_type='application/json',
                    headers={'X-Step-Up-Token': 'test-token'})

        # Read it
        client.get(f'/r6/fhir/Patient/{sample_patient["id"]}')

        # Check audit events
        resp = client.get('/r6/fhir/AuditEvent')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['total'] >= 1

    def test_audit_events_filterable_by_context(self, client, sample_bundle):
        # Ingest a bundle (creates a context and audit events)
        ingest_resp = client.post('/r6/fhir/Bundle/$ingest-context',
                                  data=json.dumps(sample_bundle),
                                  content_type='application/json')
        context_id = ingest_resp.get_json()['context_id']

        # Query audit events for this context
        resp = client.get(f'/r6/fhir/AuditEvent?context-id={context_id}')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['resourceType'] == 'Bundle'


class TestR6ImportStub:
    """Test cross-version import stub."""

    def test_import_stub_returns_accepted(self, client):
        bundle = {
            'resourceType': 'Bundle',
            'type': 'collection',
            'entry': [
                {'resource': {'resourceType': 'Patient', 'id': 'r4-patient'}}
            ]
        }
        resp = client.post('/r6/fhir/$import-stub?source-version=R4',
                          data=json.dumps(bundle),
                          content_type='application/json')
        assert resp.status_code == 202
        data = resp.get_json()
        assert '_import_stub' in data
        assert data['_import_stub']['source_version'] == 'R4'
        assert data['_import_stub']['entry_count'] == 1
        assert data['_import_stub']['entries'][0]['transform_status'] == 'needs-transform'
