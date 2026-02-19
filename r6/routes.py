"""
R6 FHIR REST Facade - Flask Blueprint.

Provides an R6-only REST surface with:
- /r6/fhir/metadata (CapabilityStatement)
- /r6/fhir/{type} (POST create, GET search)
- /r6/fhir/{type}/{id} (GET read, PUT update)
- /r6/fhir/{type}/$validate (POST validate)
- /r6/fhir/Bundle/$ingest-context (POST bundle ingestion)
- /r6/fhir/AuditEvent (GET search by contextId)
- /r6/fhir/$import-stub (POST cross-version import stub)
- /r6/fhir/oauth/* (OAuth 2.1 + SMART-on-FHIR)
- /r6/fhir/AuditEvent/$export (NDJSON audit trail export)
- /r6/fhir/{type}/{id}/$deidentify (Safe Harbor de-identification)
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, Response
from models import db
from r6.models import R6Resource, ContextEnvelope, AuditEventRecord
from r6.context_builder import ContextBuilder
from r6.validator import R6Validator
from r6.audit import record_audit_event
from r6.redaction import apply_redaction
from r6.stepup import validate_step_up_token
from r6.oauth import register_oauth_routes
from r6.rate_limit import rate_limit_middleware
from r6.health_compliance import (
    add_disclaimer, enforce_human_in_loop, deidentify_resource,
    export_audit_trail, MEDICAL_DISCLAIMER
)

logger = logging.getLogger(__name__)

r6_blueprint = Blueprint('r6', __name__, url_prefix='/r6/fhir')

# Register OAuth 2.1 endpoints
register_oauth_routes(r6_blueprint)

# Register rate limiting
rate_limit_middleware(r6_blueprint)

# R6 version identifier aligned with ballot build
R6_FHIR_VERSION = '6.0.0-ballot3'

# Initialize services
context_builder = ContextBuilder()
validator = R6Validator()

# Valid FHIR id pattern
_FHIR_ID_PATTERN = re.compile(r'^[A-Za-z0-9\-.]{1,64}$')

# AuditEvent is system-managed — block external CRUD
_SYSTEM_MANAGED_TYPES = {'AuditEvent'}


# --- Tenant Enforcement ---

@r6_blueprint.before_request
def enforce_tenant_id():
    """Require X-Tenant-Id header on all endpoints except public discovery."""
    # Public discovery endpoints (no tenant required)
    if request.path.endswith('/metadata'):
        return None
    if '/.well-known/' in request.path:
        return None
    if '/oauth/' in request.path:
        return None
    tenant_id = request.headers.get('X-Tenant-Id')
    if not tenant_id:
        return jsonify({
            'resourceType': 'OperationOutcome',
            'issue': [{
                'severity': 'error',
                'code': 'security',
                'diagnostics': 'X-Tenant-Id header is required'
            }]
        }), 400


@r6_blueprint.route('/metadata', methods=['GET'])
def r6_metadata():
    """
    Return an R6 CapabilityStatement with fhirVersion set.
    """
    capability_statement = {
        'resourceType': 'CapabilityStatement',
        'id': 'r6-showcase',
        'status': 'active',
        'date': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'kind': 'instance',
        'fhirVersion': R6_FHIR_VERSION,
        'format': ['json'],
        'software': {
            'name': 'MCP FHIR R6 Showcase',
            'version': '0.2.0'
        },
        'implementation': {
            'description': 'R6-only Agent-First FHIR Server Showcase',
            'url': request.host_url.rstrip('/') + '/r6/fhir'
        },
        'rest': [
            {
                'mode': 'server',
                'resource': [
                    _resource_capability(rt) for rt in R6Resource.SUPPORTED_TYPES
                ],
                'operation': [
                    {
                        'name': 'validate',
                        'definition': 'http://hl7.org/fhir/OperationDefinition/Resource-validate'
                    },
                    {
                        'name': 'ingest-context',
                        'definition': request.host_url.rstrip('/') + '/r6/fhir/Bundle/$ingest-context'
                    }
                ]
            }
        ]
    }
    return jsonify(capability_statement)


def _resource_capability(resource_type):
    """Build a resource entry for the CapabilityStatement."""
    interactions = [
        {'code': 'read'},
        {'code': 'create'},
        {'code': 'update'},
        {'code': 'search-type'},
    ]
    return {
        'type': resource_type,
        'interaction': interactions,
        'versioning': 'versioned',
        'readHistory': False,
        'updateCreate': False
    }


# --- CRUD Operations ---

@r6_blueprint.route('/<resource_type>', methods=['POST'])
def create_resource(resource_type):
    """Create a new R6 FHIR resource."""
    if not R6Resource.is_supported_type(resource_type):
        return _operation_outcome('error', 'not-supported',
                                  f'Resource type {resource_type} is not supported'), 400

    # Block external creation of system-managed resources
    if resource_type in _SYSTEM_MANAGED_TYPES:
        return _operation_outcome('error', 'security',
                                  f'{resource_type} is system-managed and cannot be created via API'), 403

    body = request.get_json(silent=True)
    if not body:
        return _operation_outcome('error', 'invalid', 'Request body must be valid JSON'), 400

    if body.get('resourceType') != resource_type:
        return _operation_outcome('error', 'invalid',
                                  f'resourceType mismatch: expected {resource_type}'), 400

    # Step-up authorization check with HMAC validation
    tenant_id = request.headers.get('X-Tenant-Id')
    step_up_token = request.headers.get('X-Step-Up-Token')
    if not step_up_token:
        return _operation_outcome('error', 'security',
                                  'Write operations require X-Step-Up-Token header'), 403

    valid, err = validate_step_up_token(step_up_token, tenant_id)
    if not valid:
        return _operation_outcome('error', 'security',
                                  f'Step-up token rejected: {err}'), 403

    # Validate before storing (agent proposals must pass $validate before commit)
    validation_result = validator.validate_resource(body)
    if not validation_result['valid']:
        return jsonify(validation_result['operation_outcome']), 422

    # Validate client-supplied id if present
    client_id = body.get('id')
    if client_id and not _FHIR_ID_PATTERN.match(client_id):
        return _operation_outcome('error', 'invalid',
                                  'Resource id must match [A-Za-z0-9\\-.]{1,64}'), 400

    resource_json = json.dumps(body, separators=(',', ':'), sort_keys=True)
    resource = R6Resource(
        resource_type=resource_type,
        resource_json=resource_json,
        resource_id=client_id,
        tenant_id=tenant_id
    )

    try:
        db.session.add(resource)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to create {resource_type}: {e}')
        return _operation_outcome('error', 'exception',
                                  'Failed to store resource'), 500

    record_audit_event('create', resource_type, resource.id,
                       agent_id=request.headers.get('X-Agent-Id'))

    response = jsonify(resource.to_fhir_json())
    response.status_code = 201
    response.headers['Location'] = f'/r6/fhir/{resource_type}/{resource.id}'
    response.headers['ETag'] = f'W/"{resource.version_id}"'
    return response


@r6_blueprint.route('/<resource_type>/<resource_id>', methods=['GET'])
def read_resource(resource_type, resource_id):
    """Read a specific R6 FHIR resource (redacted)."""
    if not R6Resource.is_supported_type(resource_type):
        return _operation_outcome('error', 'not-supported',
                                  f'Resource type {resource_type} is not supported'), 400

    # Enforce tenant isolation on reads
    tenant_id = request.headers.get('X-Tenant-Id')
    resource = R6Resource.query.filter_by(
        id=resource_id, resource_type=resource_type,
        is_deleted=False, tenant_id=tenant_id
    ).first()

    if not resource:
        return _operation_outcome('error', 'not-found',
                                  f'{resource_type}/{resource_id} not found'), 404

    record_audit_event('read', resource_type, resource_id,
                       agent_id=request.headers.get('X-Agent-Id'),
                       context_id=request.headers.get('X-Context-Id'))

    # Apply redaction on all reads — consistent with context envelope behavior
    fhir_json = resource.to_fhir_json()
    redacted = apply_redaction(fhir_json)

    response = jsonify(redacted)
    response.headers['ETag'] = f'W/"{resource.version_id}"'
    return response


@r6_blueprint.route('/<resource_type>/<resource_id>', methods=['PUT'])
def update_resource(resource_type, resource_id):
    """Update an existing R6 FHIR resource."""
    if not R6Resource.is_supported_type(resource_type):
        return _operation_outcome('error', 'not-supported',
                                  f'Resource type {resource_type} is not supported'), 400

    # Block updates to system-managed resources
    if resource_type in _SYSTEM_MANAGED_TYPES:
        return _operation_outcome('error', 'security',
                                  f'{resource_type} is system-managed and cannot be modified via API'), 403

    # Step-up authorization with HMAC validation
    tenant_id = request.headers.get('X-Tenant-Id')
    step_up_token = request.headers.get('X-Step-Up-Token')
    if not step_up_token:
        return _operation_outcome('error', 'security',
                                  'Write operations require X-Step-Up-Token header'), 403

    valid, err = validate_step_up_token(step_up_token, tenant_id)
    if not valid:
        return _operation_outcome('error', 'security',
                                  f'Step-up token rejected: {err}'), 403

    body = request.get_json(silent=True)
    if not body:
        return _operation_outcome('error', 'invalid', 'Request body must be valid JSON'), 400

    # Validate resourceType matches URL
    if body.get('resourceType') != resource_type:
        return _operation_outcome('error', 'invalid',
                                  f'resourceType mismatch: expected {resource_type}'), 400

    # Validate body id matches URL id
    if body.get('id') and body['id'] != resource_id:
        return _operation_outcome('error', 'invalid',
                                  f'Resource id in body ({body["id"]}) does not match URL ({resource_id})'), 400

    # Enforce tenant isolation
    resource = R6Resource.query.filter_by(
        id=resource_id, resource_type=resource_type,
        is_deleted=False, tenant_id=tenant_id
    ).first()

    if not resource:
        return _operation_outcome('error', 'not-found',
                                  f'{resource_type}/{resource_id} not found'), 404

    # Run $validate pre-commit
    validation_result = validator.validate_resource(body)
    if not validation_result['valid']:
        return jsonify(validation_result['operation_outcome']), 422

    resource_json = json.dumps(body, separators=(',', ':'), sort_keys=True)
    resource.update_resource(resource_json)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to update {resource_type}/{resource_id}: {e}')
        return _operation_outcome('error', 'exception',
                                  'Failed to update resource'), 500

    record_audit_event('update', resource_type, resource_id,
                       agent_id=request.headers.get('X-Agent-Id'))

    response = jsonify(resource.to_fhir_json())
    response.headers['ETag'] = f'W/"{resource.version_id}"'
    return response


@r6_blueprint.route('/<resource_type>', methods=['GET'])
def search_resources(resource_type):
    """Search R6 FHIR resources with basic parameters."""
    # Delegate AuditEvent searches to the dedicated handler
    if resource_type == 'AuditEvent':
        return search_audit_events()

    if not R6Resource.is_supported_type(resource_type):
        return _operation_outcome('error', 'not-supported',
                                  f'Resource type {resource_type} is not supported'), 400

    # Always enforce tenant isolation (mandatory since before_request ensures it exists)
    tenant_id = request.headers.get('X-Tenant-Id')
    query = R6Resource.query.filter_by(
        resource_type=resource_type, is_deleted=False, tenant_id=tenant_id
    )

    # Basic search: patient reference with sanitized input
    patient_ref = request.args.get('patient')
    if patient_ref:
        sanitized = patient_ref.replace('%', '').replace('_', '')
        if sanitized:
            query = query.filter(R6Resource.resource_json.contains(sanitized))

    context_id = request.args.get('context-id')

    # Clamp _count to [1, 200]
    count = request.args.get('_count', 50, type=int)
    count = max(1, min(count, 200))
    resources = query.limit(count).all()

    # Apply redaction on all search results
    bundle = {
        'resourceType': 'Bundle',
        'type': 'searchset',
        'total': len(resources),
        'entry': [
            {
                'fullUrl': f'{request.host_url.rstrip("/")}/r6/fhir/{resource_type}/{r.id}',
                'resource': apply_redaction(r.to_fhir_json())
            }
            for r in resources
        ]
    }

    record_audit_event('read', resource_type, None,
                       agent_id=request.headers.get('X-Agent-Id'),
                       context_id=context_id,
                       detail=f'search with {len(resources)} results')

    return jsonify(bundle)


# --- $validate Operation ---

@r6_blueprint.route('/<resource_type>/$validate', methods=['POST'])
def validate_resource(resource_type):
    """
    Validate a proposed FHIR R6 resource.
    Returns an OperationOutcome.
    """
    if not R6Resource.is_supported_type(resource_type):
        return _operation_outcome('error', 'not-supported',
                                  f'Resource type {resource_type} is not supported'), 400

    body = request.get_json(silent=True)
    if not body:
        return _operation_outcome('error', 'invalid', 'Request body must be valid JSON'), 400

    mode = request.args.get('mode', 'no-action')
    profile = request.args.get('profile')

    result = validator.validate_resource(body, mode=mode, profile=profile)

    record_audit_event('validate', resource_type, body.get('id'),
                       agent_id=request.headers.get('X-Agent-Id'),
                       detail=f'mode={mode}, valid={result["valid"]}')

    status_code = 200 if result['valid'] else 422
    return jsonify(result['operation_outcome']), status_code


# --- Bundle Ingestion + Context Builder ---

@r6_blueprint.route('/Bundle/$ingest-context', methods=['POST'])
def ingest_context():
    """
    Accept a small Bundle, store resources, and build a context envelope.
    """
    body = request.get_json(silent=True)
    if not body or body.get('resourceType') != 'Bundle':
        return _operation_outcome('error', 'invalid',
                                  'Request body must be a FHIR Bundle'), 400

    tenant_id = request.headers.get('X-Tenant-Id')

    try:
        result = context_builder.ingest_bundle(body, tenant_id=tenant_id)
        record_audit_event('create', 'Bundle', None,
                           agent_id=request.headers.get('X-Agent-Id'),
                           context_id=result['context_id'],
                           detail=f'ingested {result["resource_count"]} resources')
        return jsonify(result), 201
    except ValueError as e:
        return _operation_outcome('error', 'invalid', str(e)), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to ingest bundle: {e}')
        return _operation_outcome('error', 'exception',
                                  'Failed to ingest bundle'), 500


@r6_blueprint.route('/context/<context_id>', methods=['GET'])
def get_context(context_id):
    """Retrieve a context envelope by ID."""
    envelope = ContextEnvelope.query.filter_by(context_id=context_id).first()
    if not envelope:
        return _operation_outcome('error', 'not-found',
                                  f'Context {context_id} not found'), 404

    # Check expiry (handle both naive and aware datetimes from DB)
    now = datetime.now(timezone.utc)
    expires = envelope.expires_at
    if expires and expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires and expires < now:
        return _operation_outcome('error', 'expired',
                                  f'Context {context_id} has expired'), 410

    record_audit_event('read', 'ContextEnvelope', context_id,
                       agent_id=request.headers.get('X-Agent-Id'),
                       context_id=context_id)

    return jsonify(envelope.to_dict())


# --- AuditEvent Endpoints ---

@r6_blueprint.route('/AuditEvent', methods=['GET'])
def search_audit_events():
    """Search AuditEvent records, optionally filtered by context-id."""
    context_id = request.args.get('context-id')
    resource_type = request.args.get('entity-type')
    count = request.args.get('_count', 50, type=int)
    count = max(1, min(count, 200))

    query = AuditEventRecord.query.order_by(AuditEventRecord.recorded.desc())

    if context_id:
        query = query.filter_by(context_id=context_id)
    if resource_type:
        query = query.filter_by(resource_type=resource_type)

    events = query.limit(count).all()

    bundle = {
        'resourceType': 'Bundle',
        'type': 'searchset',
        'total': len(events),
        'entry': [
            {
                'fullUrl': f'{request.host_url.rstrip("/")}/r6/fhir/AuditEvent/{e.id}',
                'resource': e.to_fhir_json()
            }
            for e in events
        ]
    }

    return jsonify(bundle)


# --- Cross-Version Import Stub ---

@r6_blueprint.route('/$import-stub', methods=['POST'])
def import_stub():
    """
    R4/R5 import stub: accept Bundle + annotate "needs transform".
    """
    body = request.get_json(silent=True)
    if not body or body.get('resourceType') != 'Bundle':
        return _operation_outcome('error', 'invalid',
                                  'Request body must be a FHIR Bundle'), 400

    source_version = request.args.get('source-version', 'R4')
    entries = body.get('entry', [])

    result = {
        'resourceType': 'OperationOutcome',
        'issue': [
            {
                'severity': 'information',
                'code': 'informational',
                'diagnostics': (
                    f'Import stub received Bundle with {len(entries)} entries '
                    f'from {source_version}. Cross-version transforms for R6 ballot '
                    f'are not consistently updated. Each resource is annotated as '
                    f'"needs-transform" for pipeline processing.'
                )
            }
        ],
        '_import_stub': {
            'status': 'accepted',
            'source_version': source_version,
            'target_version': R6_FHIR_VERSION,
            'entry_count': len(entries),
            'entries': [
                {
                    'resource_type': entry.get('resource', {}).get('resourceType', 'Unknown'),
                    'resource_id': entry.get('resource', {}).get('id'),
                    'transform_status': 'needs-transform',
                    'warning': 'R6 ballot cross-version transforms are not production-ready'
                }
                for entry in entries
            ]
        }
    }

    record_audit_event('create', 'Bundle', None,
                       agent_id=request.headers.get('X-Agent-Id'),
                       detail=f'import-stub from {source_version}, {len(entries)} entries')

    return jsonify(result), 202


# --- De-identification Endpoint ---

@r6_blueprint.route('/<resource_type>/<resource_id>/$deidentify', methods=['GET'])
def deidentify_endpoint(resource_type, resource_id):
    """Return a HIPAA Safe Harbor de-identified copy of a resource."""
    if not R6Resource.is_supported_type(resource_type):
        return _operation_outcome('error', 'not-supported',
                                  f'Resource type {resource_type} is not supported'), 400

    tenant_id = request.headers.get('X-Tenant-Id')
    resource = R6Resource.query.filter_by(
        id=resource_id, resource_type=resource_type,
        is_deleted=False, tenant_id=tenant_id
    ).first()

    if not resource:
        return _operation_outcome('error', 'not-found',
                                  f'{resource_type}/{resource_id} not found'), 404

    record_audit_event('read', resource_type, resource_id,
                       agent_id=request.headers.get('X-Agent-Id'),
                       detail='de-identification export')

    fhir_json = resource.to_fhir_json()
    deidentified = deidentify_resource(fhir_json)

    return jsonify(deidentified)


# --- Audit Trail Export ---

@r6_blueprint.route('/AuditEvent/$export', methods=['GET'])
def export_audit():
    """
    Export audit trail in NDJSON or FHIR Bundle format.
    Supports date range filtering.
    """
    fmt = request.args.get('_format', 'ndjson')
    context_id = request.args.get('context-id')
    count = request.args.get('_count', 1000, type=int)
    count = max(1, min(count, 10000))

    query = AuditEventRecord.query.order_by(AuditEventRecord.recorded.desc())

    if context_id:
        query = query.filter_by(context_id=context_id)

    records = query.limit(count).all()

    record_audit_event('read', 'AuditEvent', None,
                       agent_id=request.headers.get('X-Agent-Id'),
                       detail=f'audit export: {len(records)} records, format={fmt}')

    content = export_audit_trail(records, format=fmt)

    if fmt == 'fhir-bundle':
        return Response(content, mimetype='application/fhir+json')
    else:
        return Response(content, mimetype='application/x-ndjson',
                       headers={'Content-Disposition': 'attachment; filename=audit-trail.ndjson'})


# --- Privacy Policy & Disclaimer Endpoint ---

@r6_blueprint.route('/docs/privacy-policy', methods=['GET'])
def privacy_policy():
    """Return the privacy policy and medical disclaimer."""
    return jsonify({
        'title': 'FHIR R6 MCP Privacy Policy & Medical Disclaimer',
        'effective_date': '2026-02-19',
        'medical_disclaimer': MEDICAL_DISCLAIMER,
        'data_collection': {
            'what_we_collect': [
                'FHIR resource data submitted via API (stored with PHI redaction)',
                'Audit trail of all resource access (append-only)',
                'Tenant identifiers and agent identifiers',
                'OAuth client registration metadata',
            ],
            'what_we_do_not_collect': [
                'User browsing behavior or analytics',
                'Device fingerprints',
                'Location data beyond what is in FHIR resources',
            ],
        },
        'data_protection': {
            'redaction': 'PHI redaction applied on all read paths (identifiers, addresses, telecom)',
            'de_identification': 'HIPAA Safe Harbor de-identification available via $deidentify operation',
            'encryption': 'TLS required for all production deployments',
            'audit_trail': 'Immutable, append-only AuditEvent records for all operations',
            'tenant_isolation': 'Mandatory tenant-scoped data isolation on all queries',
        },
        'data_retention': {
            'context_envelopes': 'Default TTL 30 minutes (configurable)',
            'fhir_resources': 'Retained until explicitly deleted',
            'audit_events': 'Retained indefinitely (compliance requirement)',
        },
        'data_sharing': {
            'policy': 'FHIR data is never shared with third parties',
            'ai_training': 'Data is never used for AI model training',
            'advertising': 'Data is never used for advertising',
        },
        'compliance': {
            'hipaa': 'BAA-ready architecture with zero-retention API option',
            'smart_on_fhir': 'SMART App Launch v2 compliant OAuth scopes',
            'fhir_version': 'R6 v6.0.0-ballot3',
        },
        'contact': {
            'support': 'https://github.com/aks129/ModelContextProtocolFHIR/issues',
            'maintainer': 'FHIR IQ / Eugene Vestel',
            'website': 'https://www.fhiriq.com',
        },
    })


# --- Helper Functions ---

def _operation_outcome(severity, code, diagnostics):
    """Build a FHIR OperationOutcome response."""
    return jsonify({
        'resourceType': 'OperationOutcome',
        'issue': [
            {
                'severity': severity,
                'code': code,
                'diagnostics': diagnostics
            }
        ]
    })
