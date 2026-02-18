"""
AuditEvent middleware for R6 FHIR operations.

All reads and writes emit AuditEvent records.
R6 defines AuditEvent as a record of events relevant for
operations, privacy, security, maintenance, and performance analysis.
"""

import logging
from models import db
from r6.models import AuditEventRecord

logger = logging.getLogger(__name__)


def record_audit_event(event_type, resource_type=None, resource_id=None,
                       agent_id=None, context_id=None, outcome='success',
                       detail=None):
    """
    Record an audit event for a FHIR operation.

    Args:
        event_type: Type of event (read, create, update, delete, validate)
        resource_type: FHIR resource type involved
        resource_id: ID of the resource involved
        agent_id: Identifier of the agent/user performing the action
        context_id: Context envelope ID if applicable
        outcome: Event outcome (success, failure)
        detail: Additional detail text
    """
    try:
        audit = AuditEventRecord(
            event_type=event_type,
            resource_type=resource_type,
            resource_id=resource_id,
            context_id=context_id,
            agent_id=agent_id,
            outcome=outcome,
            detail=detail
        )
        db.session.add(audit)
        db.session.commit()
        logger.debug(
            f'AuditEvent recorded: {event_type} on {resource_type}/{resource_id} '
            f'by {agent_id or "system"}'
        )
    except Exception as e:
        logger.error(f'Failed to record audit event: {e}')
        # Don't fail the main operation if audit logging fails
        db.session.rollback()
