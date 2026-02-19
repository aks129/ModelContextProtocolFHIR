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


# ===== Phase 2-5: New Feature Tests =====


class TestOAuthDiscovery:
    """Test OAuth 2.1 and SMART-on-FHIR discovery endpoints."""

    def test_oauth_discovery_endpoint(self, client):
        """OAuth authorization server metadata should be publicly accessible."""
        resp = client.get('/r6/fhir/.well-known/oauth-authorization-server')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'authorization_endpoint' in data
        assert 'token_endpoint' in data
        assert 'registration_endpoint' in data
        assert 'revocation_endpoint' in data
        assert 'S256' in data['code_challenge_methods_supported']

    def test_smart_configuration(self, client):
        """SMART App Launch v2 configuration should be accessible."""
        resp = client.get('/r6/fhir/.well-known/smart-configuration')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'authorization_endpoint' in data
        assert 'capabilities' in data
        assert 'launch-standalone' in data['capabilities']
        assert 'context-standalone-patient' in data['capabilities']


class TestOAuthFlow:
    """Test OAuth 2.1 authorization code flow with PKCE."""

    def test_dynamic_client_registration(self, client, tenant_headers):
        """Clients should be able to register dynamically."""
        resp = client.post('/r6/fhir/oauth/register',
                          data=json.dumps({
                              'client_name': 'Test Agent',
                              'redirect_uris': ['http://localhost:3000/callback'],
                              'scope': 'fhir.read context.read',
                          }),
                          content_type='application/json',
                          headers=tenant_headers)
        assert resp.status_code == 201
        data = resp.get_json()
        assert 'client_id' in data
        assert 'client_secret' in data
        assert data['client_name'] == 'Test Agent'

    def test_authorize_requires_pkce(self, client, tenant_headers):
        """Authorization endpoint should require PKCE code_challenge."""
        resp = client.get('/r6/fhir/oauth/authorize?client_id=test&redirect_uri=http://localhost',
                         headers=tenant_headers)
        assert resp.status_code == 400
        data = resp.get_json()
        assert 'PKCE' in data.get('error_description', '')

    def test_full_oauth_flow(self, client, tenant_headers):
        """Test complete OAuth 2.1 flow: register -> authorize -> token."""
        import hashlib, base64, secrets

        # 1. Register client
        reg_resp = client.post('/r6/fhir/oauth/register',
                              data=json.dumps({
                                  'client_name': 'Flow Test',
                                  'redirect_uris': ['http://localhost/cb'],
                              }),
                              content_type='application/json',
                              headers=tenant_headers)
        client_id = reg_resp.get_json()['client_id']

        # 2. Generate PKCE
        code_verifier = secrets.token_urlsafe(32)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b'=').decode()

        # 3. Authorize
        auth_resp = client.get(
            f'/r6/fhir/oauth/authorize?client_id={client_id}'
            f'&redirect_uri=http://localhost/cb'
            f'&scope=fhir.read'
            f'&code_challenge={code_challenge}'
            f'&code_challenge_method=S256'
            f'&state=test-state',
            headers=tenant_headers)
        assert auth_resp.status_code == 200
        auth_data = auth_resp.get_json()
        code = auth_data['code']
        assert auth_data['state'] == 'test-state'

        # 4. Exchange code for token
        token_resp = client.post('/r6/fhir/oauth/token',
                                data=json.dumps({
                                    'grant_type': 'authorization_code',
                                    'code': code,
                                    'code_verifier': code_verifier,
                                    'client_id': client_id,
                                }),
                                content_type='application/json',
                                headers=tenant_headers)
        assert token_resp.status_code == 200
        token_data = token_resp.get_json()
        assert 'access_token' in token_data
        assert token_data['token_type'] == 'Bearer'
        assert token_data['scope'] == 'fhir.read'

    def test_token_revocation(self, client, tenant_headers):
        """Revoked tokens should be rejected."""
        import hashlib, base64, secrets

        # Quick flow to get a token
        reg_resp = client.post('/r6/fhir/oauth/register',
                              data=json.dumps({'client_name': 'Revoke Test'}),
                              content_type='application/json',
                              headers=tenant_headers)
        client_id = reg_resp.get_json()['client_id']

        code_verifier = secrets.token_urlsafe(32)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b'=').decode()

        auth_resp = client.get(
            f'/r6/fhir/oauth/authorize?client_id={client_id}'
            f'&redirect_uri=http://localhost/cb&scope=fhir.read'
            f'&code_challenge={code_challenge}&code_challenge_method=S256',
            headers=tenant_headers)
        code = auth_resp.get_json()['code']

        token_resp = client.post('/r6/fhir/oauth/token',
                                data=json.dumps({
                                    'grant_type': 'authorization_code',
                                    'code': code,
                                    'code_verifier': code_verifier,
                                }),
                                content_type='application/json',
                                headers=tenant_headers)
        access_token = token_resp.get_json()['access_token']

        # Revoke
        revoke_resp = client.post('/r6/fhir/oauth/revoke',
                                  data=json.dumps({'token': access_token}),
                                  content_type='application/json',
                                  headers=tenant_headers)
        assert revoke_resp.status_code == 200


class TestDeidentification:
    """Test HIPAA Safe Harbor de-identification endpoint."""

    def test_deidentify_strips_identifiers(self, client, sample_patient,
                                            auth_headers, tenant_headers):
        """$deidentify should remove all Safe Harbor identifiers."""
        # Create a patient
        client.post('/r6/fhir/Patient',
                    data=json.dumps(sample_patient),
                    content_type='application/json',
                    headers=auth_headers)

        # De-identify
        resp = client.get(f'/r6/fhir/Patient/{sample_patient["id"]}/$deidentify',
                         headers=tenant_headers)
        assert resp.status_code == 200
        data = resp.get_json()

        # Name should be removed (Safe Harbor)
        assert 'name' not in data
        # Birth date should be year-only
        if 'birthDate' in data:
            assert len(data['birthDate']) == 4
        # Identifier should be removed
        assert 'identifier' not in data
        # Address should be removed
        assert 'address' not in data
        # Should have ANONYED security tag
        security = data.get('meta', {}).get('security', [])
        codes = [s.get('code') for s in security]
        assert 'ANONYED' in codes

    def test_deidentify_nonexistent_returns_404(self, client, tenant_headers):
        resp = client.get('/r6/fhir/Patient/nonexistent/$deidentify',
                         headers=tenant_headers)
        assert resp.status_code == 404


class TestAuditExport:
    """Test audit trail NDJSON export."""

    def test_export_ndjson(self, client, sample_patient, auth_headers, tenant_headers):
        """Audit export should return NDJSON by default."""
        # Generate some audit events
        client.post('/r6/fhir/Patient',
                    data=json.dumps(sample_patient),
                    content_type='application/json',
                    headers=auth_headers)

        resp = client.get('/r6/fhir/AuditEvent/$export',
                         headers=tenant_headers)
        assert resp.status_code == 200
        assert 'ndjson' in resp.content_type

    def test_export_fhir_bundle(self, client, sample_patient, auth_headers, tenant_headers):
        """Audit export should support FHIR Bundle format."""
        client.post('/r6/fhir/Patient',
                    data=json.dumps(sample_patient),
                    content_type='application/json',
                    headers=auth_headers)

        resp = client.get('/r6/fhir/AuditEvent/$export?_format=fhir-bundle',
                         headers=tenant_headers)
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data['resourceType'] == 'Bundle'
        assert data['type'] == 'collection'


class TestPrivacyPolicy:
    """Test privacy policy endpoint."""

    def test_privacy_policy_accessible(self, client, tenant_headers):
        resp = client.get('/r6/fhir/docs/privacy-policy',
                         headers=tenant_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'medical_disclaimer' in data
        assert 'data_protection' in data
        assert 'data_sharing' in data
        assert data['data_sharing']['ai_training'] == 'Data is never used for AI model training'

    def test_privacy_policy_contains_compliance_info(self, client, tenant_headers):
        resp = client.get('/r6/fhir/docs/privacy-policy',
                         headers=tenant_headers)
        data = resp.get_json()
        assert 'hipaa' in data['compliance']
        assert 'smart_on_fhir' in data['compliance']


class TestHealthCompliance:
    """Test medical disclaimer and health compliance features."""

    def test_disclaimer_added_to_clinical_data(self):
        """Clinical resources should get a disclaimer added."""
        from r6.health_compliance import add_disclaimer
        obs = {'resourceType': 'Observation', 'status': 'final'}
        result = add_disclaimer(obs)
        assert '_disclaimer' in result

    def test_disclaimer_not_added_to_non_clinical(self):
        """Non-clinical resources should not get a disclaimer."""
        from r6.health_compliance import add_disclaimer
        patient = {'resourceType': 'Patient', 'name': [{'family': 'Test'}]}
        result = add_disclaimer(patient)
        assert '_disclaimer' not in result

    def test_deidentify_module(self):
        """De-identification should remove Safe Harbor identifiers."""
        from r6.health_compliance import deidentify_resource
        resource = {
            'resourceType': 'Patient',
            'id': 'test-123',
            'name': [{'family': 'Smith'}],
            'birthDate': '1990-03-15',
            'identifier': [{'value': 'MRN12345678'}],
            'address': [{'line': ['123 Main St'], 'city': 'Springfield'}],
            'telecom': [{'value': '555-0100'}],
        }
        result = deidentify_resource(resource)
        assert 'name' not in result
        assert 'identifier' not in result
        assert 'telecom' not in result
        assert result.get('birthDate') == '1990'
        # ID should be pseudonymized
        assert result['id'] != 'test-123'


class TestRateLimitHeaders:
    """Test rate limiting headers appear on responses."""

    def test_rate_limit_headers_present(self, client, tenant_headers):
        resp = client.get('/r6/fhir/Patient/nonexistent',
                         headers=tenant_headers)
        # Rate limit headers should be present
        assert 'X-RateLimit-Limit' in resp.headers
        assert 'X-RateLimit-Remaining' in resp.headers
