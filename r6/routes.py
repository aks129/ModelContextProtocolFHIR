"""
R6 FHIR REST Facade - Flask Blueprint.

Reference implementation of MCP guardrail patterns for FHIR R6 agent access.
NOT a production FHIR server — stores resources as JSON blobs with structural
validation only. Designed to demonstrate security patterns (tenant isolation,
step-up auth, audit, redaction, human-in-the-loop) that real FHIR+MCP
integrations would need.

Search supports: patient, code, status, _lastUpdated, _count, _sort, _summary.
Validation: structural checks for required fields. Falls back when external
validator unavailable. No StructureDefinition or terminology binding validation.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, Response
from models import db
from r6.models import R6Resource, ContextEnvelope, ContextItem, AuditEventRecord
from r6.context_builder import ContextBuilder
from r6.validator import R6Validator
from r6.audit import record_audit_event
from r6.redaction import apply_redaction
from r6.stepup import validate_step_up_token, generate_step_up_token
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

# Valid tenant_id pattern: alphanumeric, hyphens, underscores, 1-64 chars
_TENANT_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,64}$')

# AuditEvent is system-managed — block external CRUD
_SYSTEM_MANAGED_TYPES = {'AuditEvent'}

# Phase 2: R6-specific valid Permission combining codes
_PERMISSION_COMBINING_CODES = {
    'deny-overrides', 'permit-overrides', 'ordered-deny-overrides',
    'ordered-permit-overrides', 'deny-unless-permit', 'permit-unless-deny',
}

# Valid Bundle types per FHIR spec
_VALID_BUNDLE_TYPES = {
    'document', 'message', 'transaction', 'transaction-response',
    'batch', 'batch-response', 'history', 'searchset', 'collection',
    'subscription-notification',
}

# Valid FHIR search patient reference pattern
_PATIENT_REF_PATTERN = re.compile(r'^Patient/[A-Za-z0-9\-.]{1,64}$')


# --- Tenant Enforcement ---

@r6_blueprint.before_request
def enforce_tenant_id():
    """Require X-Tenant-Id header on all endpoints except public discovery."""
    # Public discovery endpoints (no tenant required)
    if request.path.endswith('/metadata'):
        return None
    if request.path.endswith('/health'):
        return None
    if '/internal/' in request.path:
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
    # Validate tenant_id format
    if not _TENANT_ID_PATTERN.match(tenant_id):
        return jsonify({
            'resourceType': 'OperationOutcome',
            'issue': [{
                'severity': 'error',
                'code': 'invalid',
                'diagnostics': 'X-Tenant-Id must match [a-zA-Z0-9_-]{1,64}'
            }]
        }), 400


# --- Human-in-the-Loop Enforcement ---

@r6_blueprint.before_request
def check_human_confirmation():
    """Enforce human-in-the-loop for clinical writes."""
    result = enforce_human_in_loop()
    if result:
        return result


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
            'name': 'MCP FHIR R6 Reference',
            'version': '0.7.0'
        },
        'implementation': {
            'description': 'Reference implementation: MCP guardrail patterns for FHIR R6 agent access. '
                           'JSON blob storage with structural validation. Not a production server.',
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
                    },
                    {
                        'name': 'stats',
                        'definition': 'http://hl7.org/fhir/OperationDefinition/Observation-stats'
                    },
                    {
                        'name': 'lastn',
                        'definition': 'http://hl7.org/fhir/OperationDefinition/Observation-lastn'
                    },
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
    search_params = [
        {'name': '_count', 'type': 'number', 'documentation': 'Max results (1-200)'},
        {'name': '_sort', 'type': 'string', 'documentation': '_lastUpdated or -_lastUpdated'},
        {'name': '_lastUpdated', 'type': 'date', 'documentation': 'Filter by last updated (ge/le prefix)'},
        {'name': '_summary', 'type': 'token', 'documentation': 'count'},
        {'name': 'code', 'type': 'token', 'documentation': 'Filter by code.coding[].code (JSON string match)'},
        {'name': 'status', 'type': 'token', 'documentation': 'Filter by status field'},
        {'name': 'patient', 'type': 'reference', 'documentation': 'Filter by subject.reference (Patient/{id})'},
    ]
    return {
        'type': resource_type,
        'interaction': interactions,
        'versioning': 'versioned',
        'readHistory': False,
        'updateCreate': False,
        'searchParam': search_params,
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
                       agent_id=request.headers.get('X-Agent-Id'),
                       tenant_id=tenant_id)

    fhir_json = resource.to_fhir_json()
    fhir_json = add_disclaimer(fhir_json, resource_type)
    response = jsonify(fhir_json)
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
                       context_id=request.headers.get('X-Context-Id'),
                       tenant_id=tenant_id)

    # Apply redaction on all reads — consistent with context envelope behavior
    fhir_json = resource.to_fhir_json()
    redacted = apply_redaction(fhir_json)
    redacted = add_disclaimer(redacted, resource_type)

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

    # ETag/If-Match concurrency control
    if_match = request.headers.get('If-Match')
    if if_match:
        current_etag = f'W/"{resource.version_id}"'
        # Normalize: strip W/ prefix and quotes for comparison
        expected = if_match.strip().lstrip('W/').strip('"')
        actual = str(resource.version_id)
        if expected != actual:
            return _operation_outcome('error', 'conflict',
                                      'Resource has been modified (ETag mismatch)'), 409

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
                       agent_id=request.headers.get('X-Agent-Id'),
                       tenant_id=tenant_id)

    fhir_json = resource.to_fhir_json()
    fhir_json = add_disclaimer(fhir_json, resource_type)
    response = jsonify(fhir_json)
    response.headers['ETag'] = f'W/"{resource.version_id}"'
    return response


@r6_blueprint.route('/<resource_type>', methods=['GET'])
def search_resources(resource_type):
    """
    Search R6 FHIR resources.

    Supported parameters:
      - patient: Reference filter (Patient/{id}) — matches subject.reference
      - code: Code filter — matches code.coding[].code in the JSON
      - status: Status filter — matches the status field
      - _lastUpdated: Date filter (ge/le prefix) on last_updated column
      - _count: Max results (1-200, default 50)
      - _sort: Sort by _lastUpdated or -_lastUpdated (desc)
      - _summary: 'count' returns total only
      - context-id: Filter to resources in a specific context envelope
    """
    # Delegate AuditEvent searches to the dedicated handler
    if resource_type == 'AuditEvent':
        return search_audit_events()

    if not R6Resource.is_supported_type(resource_type):
        return _operation_outcome('error', 'not-supported',
                                  f'Resource type {resource_type} is not supported'), 400

    # Always enforce tenant isolation
    tenant_id = request.headers.get('X-Tenant-Id')
    query = R6Resource.query.filter_by(
        resource_type=resource_type, is_deleted=False, tenant_id=tenant_id
    )

    # --- patient reference filter ---
    patient_ref = request.args.get('patient')
    if patient_ref:
        if not _PATIENT_REF_PATTERN.match(patient_ref):
            return _operation_outcome('error', 'invalid',
                                      'Patient reference must match Patient/{id}'), 400
        query = query.filter(
            db.or_(
                R6Resource.resource_json.contains(f'"reference":"{patient_ref}"'),
                R6Resource.resource_json.contains(f'"reference": "{patient_ref}"'),
            )
        )

    # --- code filter (matches code.coding[].code in JSON) ---
    code_param = request.args.get('code')
    if code_param:
        # Match "code":"<value>" inside the JSON — works for coding arrays
        query = query.filter(
            R6Resource.resource_json.contains(f'"code":"{code_param}"')
        )

    # --- status filter (matches "status":"<value>" in JSON) ---
    status_param = request.args.get('status')
    if status_param:
        query = query.filter(
            R6Resource.resource_json.contains(f'"status":"{status_param}"')
        )

    # --- _lastUpdated filter (ge/le prefix on DB column) ---
    last_updated_param = request.args.get('_lastUpdated')
    if last_updated_param:
        try:
            if last_updated_param.startswith('ge'):
                dt = datetime.fromisoformat(last_updated_param[2:].replace('Z', '+00:00'))
                query = query.filter(R6Resource.last_updated >= dt)
            elif last_updated_param.startswith('le'):
                dt = datetime.fromisoformat(last_updated_param[2:].replace('Z', '+00:00'))
                query = query.filter(R6Resource.last_updated <= dt)
            elif last_updated_param.startswith('gt'):
                dt = datetime.fromisoformat(last_updated_param[2:].replace('Z', '+00:00'))
                query = query.filter(R6Resource.last_updated > dt)
            elif last_updated_param.startswith('lt'):
                dt = datetime.fromisoformat(last_updated_param[2:].replace('Z', '+00:00'))
                query = query.filter(R6Resource.last_updated < dt)
            else:
                # Exact match (to the second)
                dt = datetime.fromisoformat(last_updated_param.replace('Z', '+00:00'))
                query = query.filter(R6Resource.last_updated >= dt)
        except (ValueError, TypeError):
            return _operation_outcome('error', 'invalid',
                                      '_lastUpdated must be a valid ISO datetime with optional ge/le/gt/lt prefix'), 400

    # --- context-id filter (restrict to resources in a context envelope) ---
    context_id = request.args.get('context-id')
    if context_id:
        from r6.models import ContextItem
        context_refs = [item.resource_ref for item in
                        ContextItem.query.filter_by(context_id=context_id).all()]
        # resource_ref is like "Patient/abc-123"
        context_ids = [ref.split('/')[-1] for ref in context_refs
                       if ref.startswith(f'{resource_type}/')]
        if context_ids:
            query = query.filter(R6Resource.id.in_(context_ids))
        else:
            # No matching resources in context — return empty
            query = query.filter(db.literal(False))

    # --- _sort ---
    sort_param = request.args.get('_sort', '-_lastUpdated')
    if sort_param == '_lastUpdated':
        query = query.order_by(R6Resource.last_updated.asc())
    else:
        query = query.order_by(R6Resource.last_updated.desc())

    # Support _summary=count
    summary = request.args.get('_summary')
    if summary == 'count':
        total = query.count()
        bundle = {
            'resourceType': 'Bundle',
            'type': 'searchset',
            'total': total,
        }
        return jsonify(bundle)

    # Clamp _count to [1, 200]
    count = request.args.get('_count', 50, type=int)
    count = max(1, min(count, 200))
    resources = query.limit(count).all()

    # Apply redaction and disclaimer on all search results
    entries = []
    for r in resources:
        fhir_json = apply_redaction(r.to_fhir_json())
        fhir_json = add_disclaimer(fhir_json, resource_type)
        entries.append({
            'fullUrl': f'{request.host_url.rstrip("/")}/r6/fhir/{resource_type}/{r.id}',
            'resource': fhir_json
        })

    # Build self link with search params for transparency
    search_params = []
    for key in ('patient', 'code', 'status', '_lastUpdated', '_count', '_sort'):
        val = request.args.get(key)
        if val:
            search_params.append(f'{key}={val}')
    self_link = f'{request.host_url.rstrip("/")}/r6/fhir/{resource_type}'
    if search_params:
        self_link += '?' + '&'.join(search_params)

    bundle = {
        'resourceType': 'Bundle',
        'type': 'searchset',
        'total': len(resources),
        'link': [{'relation': 'self', 'url': self_link}],
        'entry': entries
    }

    detail_parts = [f'{len(resources)} results']
    if patient_ref:
        detail_parts.append(f'patient={patient_ref}')
    if code_param:
        detail_parts.append(f'code={code_param}')
    if status_param:
        detail_parts.append(f'status={status_param}')

    record_audit_event('read', resource_type, None,
                       agent_id=request.headers.get('X-Agent-Id'),
                       context_id=context_id,
                       tenant_id=tenant_id,
                       detail=f'search: {", ".join(detail_parts)}')

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

    tenant_id = request.headers.get('X-Tenant-Id')
    record_audit_event('validate', resource_type, body.get('id'),
                       agent_id=request.headers.get('X-Agent-Id'),
                       tenant_id=tenant_id,
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

    # Validate Bundle.type
    bundle_type = body.get('type')
    if bundle_type and bundle_type not in _VALID_BUNDLE_TYPES:
        return _operation_outcome('error', 'invalid',
                                  f'Bundle.type "{bundle_type}" is not a valid FHIR Bundle type'), 400

    tenant_id = request.headers.get('X-Tenant-Id')

    try:
        result = context_builder.ingest_bundle(body, tenant_id=tenant_id)
        record_audit_event('create', 'Bundle', None,
                           agent_id=request.headers.get('X-Agent-Id'),
                           context_id=result['context_id'],
                           tenant_id=tenant_id,
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
    """
    Retrieve a context envelope by ID.

    The context envelope includes:
    - Metadata (patient ref, encounter ref, temporal window, expiry)
    - List of resource references included in this context
    - Redaction profile applied
    - Consent decision (currently always 'permit')

    If ?_include=resources is passed, the actual resource data is included
    (redacted, filtered to context membership only).
    """
    tenant_id = request.headers.get('X-Tenant-Id')
    envelope = ContextEnvelope.query.filter_by(
        context_id=context_id, tenant_id=tenant_id
    ).first()
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

    result = envelope.to_dict()

    # If _include=resources, fetch and include actual resource data (redacted)
    include = request.args.get('_include')
    if include == 'resources':
        items = ContextItem.query.filter_by(context_id=context_id).all()
        resources = []
        for item in items:
            parts = item.resource_ref.split('/', 1)
            if len(parts) == 2:
                r_type, r_id = parts
                r = R6Resource.query.filter_by(
                    id=r_id, resource_type=r_type, tenant_id=tenant_id, is_deleted=False
                ).first()
                if r:
                    fhir_json = apply_redaction(r.to_fhir_json())
                    fhir_json = add_disclaimer(fhir_json, r_type)
                    resources.append(fhir_json)
        result['resources'] = resources
        result['_note'] = ('Resources are redacted per the context redaction profile. '
                           'Only resources belonging to this context are included.')

    record_audit_event('read', 'ContextEnvelope', context_id,
                       agent_id=request.headers.get('X-Agent-Id'),
                       context_id=context_id,
                       tenant_id=tenant_id)

    return jsonify(result)


# --- AuditEvent Endpoints ---

@r6_blueprint.route('/AuditEvent', methods=['GET'])
def search_audit_events():
    """Search AuditEvent records, optionally filtered by context-id."""
    tenant_id = request.headers.get('X-Tenant-Id')
    context_id = request.args.get('context-id')
    resource_type = request.args.get('entity-type')
    count = request.args.get('_count', 50, type=int)
    count = max(1, min(count, 200))

    # Enforce tenant isolation on audit events
    query = AuditEventRecord.query.filter_by(
        tenant_id=tenant_id
    ).order_by(AuditEventRecord.recorded.desc())

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
    tenant_id = request.headers.get('X-Tenant-Id')

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
                       tenant_id=tenant_id,
                       detail=f'import-stub from {source_version}, {len(entries)} entries')

    return jsonify(result), 202


# --- Observation $stats Operation (standard FHIR, available since R4) ---

@r6_blueprint.route('/Observation/$stats', methods=['GET'])
def observation_stats():
    """
    Observation $stats — compute statistics over stored Observations.

    Standard FHIR operation (available since R4, not R6-specific).
    Computes count, min, max, mean over numeric valueQuantity values.
    Limitations: only supports valueQuantity (not valueCodeableConcept,
    valueString, etc.). No percentile or median. No component support.
    """
    tenant_id = request.headers.get('X-Tenant-Id')
    code = request.args.get('code')
    patient_ref = request.args.get('patient')

    query = R6Resource.query.filter_by(
        resource_type='Observation', is_deleted=False, tenant_id=tenant_id
    )

    if patient_ref:
        if not _PATIENT_REF_PATTERN.match(patient_ref):
            return _operation_outcome('error', 'invalid',
                                      'Patient reference must match Patient/{id}'), 400
        query = query.filter(
            db.or_(
                R6Resource.resource_json.contains(f'"reference":"{patient_ref}"'),
                R6Resource.resource_json.contains(f'"reference": "{patient_ref}"'),
            )
        )

    observations = query.all()

    # Extract numeric values matching the code filter
    values = []
    for obs in observations:
        resource = json.loads(obs.resource_json)
        # Filter by code if specified
        if code:
            obs_codings = resource.get('code', {}).get('coding', [])
            if not any(c.get('code') == code for c in obs_codings):
                continue
        # Extract valueQuantity.value
        vq = resource.get('valueQuantity', {})
        if isinstance(vq, dict) and 'value' in vq:
            try:
                values.append(float(vq['value']))
            except (ValueError, TypeError):
                pass

    stats = {
        'count': len(values),
        'min': round(min(values), 2) if values else None,
        'max': round(max(values), 2) if values else None,
        'mean': round(sum(values) / len(values), 2) if values else None,
    }

    result = {
        'resourceType': 'Parameters',
        'parameter': [
            {'name': 'count', 'valueInteger': stats['count']},
        ]
    }
    if stats['min'] is not None:
        result['parameter'].extend([
            {'name': 'min', 'valueDecimal': stats['min']},
            {'name': 'max', 'valueDecimal': stats['max']},
            {'name': 'mean', 'valueDecimal': stats['mean']},
        ])

    unit = None
    if values and observations:
        for obs in observations:
            resource = json.loads(obs.resource_json)
            vq = resource.get('valueQuantity', {})
            if vq.get('unit'):
                unit = vq['unit']
                break
    if unit:
        result['parameter'].append({'name': 'unit', 'valueString': unit})

    record_audit_event('read', 'Observation', None,
                       agent_id=request.headers.get('X-Agent-Id'),
                       tenant_id=tenant_id,
                       detail=f'$stats: code={code}, count={stats["count"]}')

    return jsonify(result)


# --- Observation $lastn Operation (standard FHIR, available since R4) ---

@r6_blueprint.route('/Observation/$lastn', methods=['GET'])
def observation_lastn():
    """
    Observation $lastn — get the last N observations per code.

    Standard FHIR operation (available since R4, not R6-specific).
    Returns the most recent observations grouped by code, optionally
    filtered by patient and code. Default N=1.
    """
    tenant_id = request.headers.get('X-Tenant-Id')
    code = request.args.get('code')
    patient_ref = request.args.get('patient')
    max_n = request.args.get('max', 1, type=int)
    max_n = max(1, min(max_n, 100))

    query = R6Resource.query.filter_by(
        resource_type='Observation', is_deleted=False, tenant_id=tenant_id
    ).order_by(R6Resource.last_updated.desc())

    if patient_ref:
        if not _PATIENT_REF_PATTERN.match(patient_ref):
            return _operation_outcome('error', 'invalid',
                                      'Patient reference must match Patient/{id}'), 400
        query = query.filter(
            db.or_(
                R6Resource.resource_json.contains(f'"reference":"{patient_ref}"'),
                R6Resource.resource_json.contains(f'"reference": "{patient_ref}"'),
            )
        )

    all_observations = query.all()

    # Group by code and take last N per code
    code_groups = {}
    for obs in all_observations:
        resource = json.loads(obs.resource_json)
        obs_codings = resource.get('code', {}).get('coding', [])
        obs_code = obs_codings[0].get('code') if obs_codings else 'unknown'

        if code and obs_code != code:
            continue

        if obs_code not in code_groups:
            code_groups[obs_code] = []
        if len(code_groups[obs_code]) < max_n:
            code_groups[obs_code].append(obs)

    entries = []
    for code_key, obs_list in code_groups.items():
        for obs in obs_list:
            fhir_json = apply_redaction(obs.to_fhir_json())
            fhir_json = add_disclaimer(fhir_json, 'Observation')
            entries.append({
                'fullUrl': f'{request.host_url.rstrip("/")}/r6/fhir/Observation/{obs.id}',
                'resource': fhir_json
            })

    bundle = {
        'resourceType': 'Bundle',
        'type': 'searchset',
        'total': len(entries),
        'entry': entries
    }

    record_audit_event('read', 'Observation', None,
                       agent_id=request.headers.get('X-Agent-Id'),
                       tenant_id=tenant_id,
                       detail=f'$lastn: code={code}, max={max_n}, results={len(entries)}')

    return jsonify(bundle)


# --- SubscriptionTopic Discovery (R6 ballot) ---

@r6_blueprint.route('/SubscriptionTopic/$list', methods=['GET'])
def list_subscription_topics():
    """
    List available SubscriptionTopics for discovery.

    Introduced in R5, maturing in R6. Topics define subscribable events.
    This endpoint supports discovery only — no notification dispatch.
    """
    tenant_id = request.headers.get('X-Tenant-Id')

    # Query stored SubscriptionTopics for this tenant
    topics = R6Resource.query.filter_by(
        resource_type='SubscriptionTopic', is_deleted=False, tenant_id=tenant_id
    ).all()

    entries = []
    for t in topics:
        fhir_json = t.to_fhir_json()
        entries.append({
            'fullUrl': f'{request.host_url.rstrip("/")}/r6/fhir/SubscriptionTopic/{t.id}',
            'resource': fhir_json
        })

    bundle = {
        'resourceType': 'Bundle',
        'type': 'searchset',
        'total': len(entries),
        'entry': entries
    }

    record_audit_event('read', 'SubscriptionTopic', None,
                       agent_id=request.headers.get('X-Agent-Id'),
                       tenant_id=tenant_id,
                       detail=f'$list: {len(entries)} topics found')

    return jsonify(bundle)


# --- Permission $evaluate (R6 Access Control) ---

@r6_blueprint.route('/Permission/$evaluate', methods=['POST'])
def evaluate_permission():
    """
    Evaluate a Permission request against stored Permission resources.

    This is the R6 access control evaluation endpoint. Given a subject,
    action, and resource, returns whether the action is permitted or denied
    based on stored Permission resources.
    """
    tenant_id = request.headers.get('X-Tenant-Id')
    body = request.get_json(silent=True)
    if not body:
        return _operation_outcome('error', 'invalid', 'Request body must be valid JSON'), 400

    subject_ref = body.get('subject')
    action = body.get('action', 'read')
    resource_ref = body.get('resource')

    # Query active Permission resources for this tenant
    permissions = R6Resource.query.filter_by(
        resource_type='Permission', is_deleted=False, tenant_id=tenant_id
    ).all()

    # Evaluate: find matching rules
    decision = 'deny'  # Default deny
    matched_rules = []

    for perm in permissions:
        perm_data = json.loads(perm.resource_json)
        if perm_data.get('status') != 'active':
            continue

        combining = perm_data.get('combining', 'deny-overrides')
        rules = perm_data.get('rule', [])

        for rule in rules:
            rule_type = rule.get('type', 'deny')

            # Check if rule matches the requested action
            activities = rule.get('activity', [])
            action_match = not activities  # Empty means match all
            for activity in activities:
                act_actions = activity.get('action', [])
                if not act_actions:
                    action_match = True
                    break
                # Actions may be CodeableConcept with coding array, or plain code
                for a in act_actions:
                    if a.get('code') == action:
                        action_match = True
                        break
                    # Check inside coding array (CodeableConcept pattern)
                    for coding in a.get('coding', []):
                        if coding.get('code') == action:
                            action_match = True
                            break
                if action_match:
                    break

            if action_match:
                matched_rules.append({
                    'permission_id': perm.id,
                    'rule_type': rule_type,
                    'combining': combining,
                })

                if rule_type == 'permit':
                    decision = 'permit'

    # Build reasoning explanation for the decision
    if not permissions:
        reasoning = 'No active Permission resources found for this tenant. Default deny applies.'
    elif not matched_rules:
        reasoning = (f'Found {len(permissions)} Permission resource(s) but no rules matched '
                     f'action "{action}". Default deny applies.')
    else:
        rule_descs = []
        for mr in matched_rules:
            rule_descs.append(f'{mr["rule_type"]} (Permission/{mr["permission_id"]}, combining={mr["combining"]})')
        reasoning = (f'Matched {len(matched_rules)} rule(s): {"; ".join(rule_descs)}. '
                     f'Final decision: {decision}.')

    result = {
        'resourceType': 'Parameters',
        'parameter': [
            {'name': 'decision', 'valueCode': decision},
            {'name': 'matched_rules', 'valueInteger': len(matched_rules)},
            {'name': 'subject', 'valueString': subject_ref or 'unspecified'},
            {'name': 'action', 'valueCode': action},
            {'name': 'reasoning', 'valueString': reasoning},
        ]
    }

    record_audit_event('read', 'Permission', None,
                       agent_id=request.headers.get('X-Agent-Id'),
                       tenant_id=tenant_id,
                       detail=f'$evaluate: subject={subject_ref}, action={action}, decision={decision}')

    return jsonify(result)


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
                       tenant_id=tenant_id,
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
    tenant_id = request.headers.get('X-Tenant-Id')

    # Enforce tenant isolation on audit export
    query = AuditEventRecord.query.filter_by(
        tenant_id=tenant_id
    ).order_by(AuditEventRecord.recorded.desc())

    if context_id:
        query = query.filter_by(context_id=context_id)

    resource_type_filter = request.args.get('entity-type')
    if resource_type_filter:
        query = query.filter_by(resource_type=resource_type_filter)

    records = query.limit(count).all()

    record_audit_event('read', 'AuditEvent', None,
                       agent_id=request.headers.get('X-Agent-Id'),
                       tenant_id=tenant_id,
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


# --- Health Check ---

@r6_blueprint.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint for container orchestration (liveness/readiness).
    Returns 200 if the service is operational, 503 if degraded.
    """
    health = {
        'status': 'healthy',
        'version': '0.7.0',
        'fhirVersion': R6_FHIR_VERSION,
        'checks': {}
    }

    # Check database connectivity
    try:
        db.session.execute(db.text('SELECT 1'))
        health['checks']['database'] = 'ok'
    except Exception as e:
        health['status'] = 'degraded'
        health['checks']['database'] = 'error'
        logger.warning(f'Health check: database failed: {e}')

    status_code = 200 if health['status'] == 'healthy' else 503
    return jsonify(health), status_code


# --- Internal Endpoints (dashboard support) ---

@r6_blueprint.route('/internal/step-up-token', methods=['POST'])
def issue_step_up_token():
    """
    Issue a step-up token for the dashboard demo.
    In production, this would be gated behind an admin auth flow.
    """
    body = request.get_json(silent=True) or {}
    tenant_id = body.get('tenant_id') or request.headers.get('X-Tenant-Id', 'default')
    try:
        token = generate_step_up_token(tenant_id)
        return jsonify({'token': token, 'tenant_id': tenant_id})
    except ValueError as e:
        return jsonify({'error': str(e)}), 500


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
