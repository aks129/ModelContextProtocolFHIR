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
"""

import json
import logging
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from models import db
from r6.models import R6Resource, AuditEventRecord
from r6.context_builder import ContextBuilder
from r6.validator import R6Validator
from r6.audit import record_audit_event

logger = logging.getLogger(__name__)

r6_blueprint = Blueprint('r6', __name__, url_prefix='/r6/fhir')

# R6 version identifier aligned with ballot build
R6_FHIR_VERSION = '6.0.0-ballot3'

# Initialize services
context_builder = ContextBuilder()
validator = R6Validator()


@r6_blueprint.route('/metadata', methods=['GET'])
def r6_metadata():
    """
    Return an R6 CapabilityStatement with fhirVersion set.
    The R6 versioning guidance uses fhirVersion in CapabilityStatement
    as the primary way to determine version.
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
            'version': '0.1.0'
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
    ]
    if resource_type == 'AuditEvent':
        interactions.append({'code': 'search-type'})
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

    body = request.get_json(silent=True)
    if not body:
        return _operation_outcome('error', 'invalid', 'Request body must be valid JSON'), 400

    if body.get('resourceType') != resource_type:
        return _operation_outcome('error', 'invalid',
                                  f'resourceType mismatch: expected {resource_type}'), 400

    # Step-up authorization check
    step_up_token = request.headers.get('X-Step-Up-Token')
    if not step_up_token:
        return _operation_outcome('error', 'security',
                                  'Write operations require X-Step-Up-Token header'), 403

    resource_json = json.dumps(body, separators=(',', ':'), sort_keys=True)
    resource = R6Resource(
        resource_type=resource_type,
        resource_json=resource_json,
        resource_id=body.get('id'),
        tenant_id=request.headers.get('X-Tenant-Id')
    )

    db.session.add(resource)
    db.session.commit()

    record_audit_event('create', resource_type, resource.id,
                       agent_id=request.headers.get('X-Agent-Id'))

    response = jsonify(resource.to_fhir_json())
    response.status_code = 201
    response.headers['Location'] = f'/r6/fhir/{resource_type}/{resource.id}'
    response.headers['ETag'] = f'W/"{resource.version_id}"'
    return response


@r6_blueprint.route('/<resource_type>/<resource_id>', methods=['GET'])
def read_resource(resource_type, resource_id):
    """Read a specific R6 FHIR resource."""
    if not R6Resource.is_supported_type(resource_type):
        return _operation_outcome('error', 'not-supported',
                                  f'Resource type {resource_type} is not supported'), 400

    resource = R6Resource.query.filter_by(
        id=resource_id, resource_type=resource_type, is_deleted=False
    ).first()

    if not resource:
        return _operation_outcome('error', 'not-found',
                                  f'{resource_type}/{resource_id} not found'), 404

    record_audit_event('read', resource_type, resource_id,
                       agent_id=request.headers.get('X-Agent-Id'),
                       context_id=request.headers.get('X-Context-Id'))

    response = jsonify(resource.to_fhir_json())
    response.headers['ETag'] = f'W/"{resource.version_id}"'
    return response


@r6_blueprint.route('/<resource_type>/<resource_id>', methods=['PUT'])
def update_resource(resource_type, resource_id):
    """Update an existing R6 FHIR resource."""
    if not R6Resource.is_supported_type(resource_type):
        return _operation_outcome('error', 'not-supported',
                                  f'Resource type {resource_type} is not supported'), 400

    step_up_token = request.headers.get('X-Step-Up-Token')
    if not step_up_token:
        return _operation_outcome('error', 'security',
                                  'Write operations require X-Step-Up-Token header'), 403

    body = request.get_json(silent=True)
    if not body:
        return _operation_outcome('error', 'invalid', 'Request body must be valid JSON'), 400

    resource = R6Resource.query.filter_by(
        id=resource_id, resource_type=resource_type, is_deleted=False
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
    db.session.commit()

    record_audit_event('update', resource_type, resource_id,
                       agent_id=request.headers.get('X-Agent-Id'))

    response = jsonify(resource.to_fhir_json())
    response.headers['ETag'] = f'W/"{resource.version_id}"'
    return response


@r6_blueprint.route('/<resource_type>', methods=['GET'])
def search_resources(resource_type):
    """Search R6 FHIR resources with basic parameters."""
    if not R6Resource.is_supported_type(resource_type):
        return _operation_outcome('error', 'not-supported',
                                  f'Resource type {resource_type} is not supported'), 400

    query = R6Resource.query.filter_by(
        resource_type=resource_type, is_deleted=False
    )

    # Basic search parameters
    patient_ref = request.args.get('patient')
    if patient_ref:
        query = query.filter(R6Resource.resource_json.contains(patient_ref))

    context_id = request.args.get('context-id')
    tenant_id = request.headers.get('X-Tenant-Id')
    if tenant_id:
        query = query.filter_by(tenant_id=tenant_id)

    count = request.args.get('_count', 50, type=int)
    resources = query.limit(min(count, 200)).all()

    bundle = {
        'resourceType': 'Bundle',
        'type': 'searchset',
        'total': len(resources),
        'entry': [
            {
                'fullUrl': f'{request.host_url.rstrip("/")}/r6/fhir/{resource_type}/{r.id}',
                'resource': r.to_fhir_json()
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
    R6 defines $validate semantics for create/update/delete.
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
    This is the MVP ingestion endpoint for the agent showcase.
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


@r6_blueprint.route('/context/<context_id>', methods=['GET'])
def get_context(context_id):
    """Retrieve a context envelope by ID."""
    from r6.models import ContextEnvelope
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

    query = AuditEventRecord.query.order_by(AuditEventRecord.recorded.desc())

    if context_id:
        query = query.filter_by(context_id=context_id)
    if resource_type:
        query = query.filter_by(resource_type=resource_type)

    events = query.limit(min(count, 200)).all()

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
    This is explicitly non-production due to R6 ballot transform caveats.
    Cross-version transforms are "not consistently updated" for the ballot.
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
