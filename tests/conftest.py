"""
Test fixtures for the R6 FHIR Showcase.
"""

import os
import pytest

# Set test environment before importing app — prevents file-based DB creation
os.environ['TESTING'] = '1'
os.environ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'


@pytest.fixture
def app():
    """Create a test Flask application."""
    from main import app as flask_app
    flask_app.config['TESTING'] = True
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

    from models import db
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.drop_all()


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


@pytest.fixture
def sample_patient():
    """Sample FHIR R6 Patient resource."""
    return {
        'resourceType': 'Patient',
        'id': 'test-patient-1',
        'name': [{'family': 'Smith', 'given': ['John']}],
        'gender': 'male',
        'birthDate': '1990-01-15',
        'identifier': [
            {'system': 'http://example.org/mrn', 'value': 'MRN12345678'}
        ],
        'address': [
            {
                'line': ['123 Main St'],
                'city': 'Springfield',
                'state': 'IL',
                'postalCode': '62701',
                'country': 'US'
            }
        ]
    }


@pytest.fixture
def sample_observation():
    """Sample FHIR R6 Observation resource."""
    return {
        'resourceType': 'Observation',
        'id': 'test-obs-1',
        'status': 'final',
        'code': {
            'coding': [
                {
                    'system': 'http://loinc.org',
                    'code': '2339-0',
                    'display': 'Glucose [Mass/volume] in Blood'
                }
            ]
        },
        'subject': {'reference': 'Patient/test-patient-1'},
        'effectiveDateTime': '2024-01-15T10:30:00Z',
        'valueQuantity': {
            'value': 95,
            'unit': 'mg/dL',
            'system': 'http://unitsofmeasure.org',
            'code': 'mg/dL'
        }
    }


@pytest.fixture
def sample_bundle(sample_patient, sample_observation):
    """Sample FHIR R6 Bundle for context ingestion."""
    return {
        'resourceType': 'Bundle',
        'type': 'collection',
        'entry': [
            {'resource': sample_patient},
            {'resource': sample_observation}
        ]
    }
