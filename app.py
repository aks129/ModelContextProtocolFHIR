import os
import logging
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from marshmallow import ValidationError
from validators import FHIRServerSchema, FHIRResourceRequestSchema
from fhir_client import FHIRClient

# Configure logging
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")

# Initialize FHIR client
fhir_client = FHIRClient()

@app.route('/')
def index():
    """Render the main page of the MCP server."""
    return render_template('index.html')

@app.route('/documentation')
def documentation():
    """Render the API documentation page."""
    return render_template('documentation.html')

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    """
    GET: Render the settings page
    POST: Update FHIR server connection settings
    """
    fhir_server_schema = FHIRServerSchema()
    
    if request.method == 'POST':
        try:
            # Validate the incoming data
            data = fhir_server_schema.load(request.form)
            
            # Update FHIR client with new server configuration
            fhir_client.configure(
                base_url=data['base_url'],
                auth_type=data.get('auth_type'),
                api_key=data.get('api_key'),
                username=data.get('username'),
                password=data.get('password')
            )
            
            # Store connection info in session
            session['fhir_server'] = {
                'base_url': data['base_url'],
                'auth_type': data.get('auth_type')
            }
            
            flash('FHIR server settings updated successfully', 'success')
            return redirect(url_for('settings'))
            
        except ValidationError as err:
            flash(f'Invalid settings: {err.messages}', 'danger')
    
    # Get current settings if available
    current_settings = {}
    if fhir_client.is_configured():
        current_settings = {
            'base_url': fhir_client.base_url,
            'auth_type': fhir_client.auth_type
        }
    
    return render_template('settings.html', settings=current_settings)

@app.route('/fhir-explorer')
def fhir_explorer():
    """Render the FHIR Explorer page."""
    if not fhir_client.is_configured():
        flash('Please configure your FHIR server settings first', 'warning')
        return redirect(url_for('settings'))
    
    return render_template('fhir_explorer.html')

# MCP API Endpoints
@app.route('/api/status', methods=['GET'])
def api_status():
    """Return the status of the MCP server and FHIR server connection."""
    status = {
        'mcp_server': 'running',
        'fhir_server_configured': fhir_client.is_configured(),
    }
    
    if fhir_client.is_configured():
        try:
            # Test connection to FHIR server
            fhir_client.test_connection()
            status['fhir_server_connection'] = 'connected'
        except Exception as e:
            logger.error(f"FHIR server connection test failed: {str(e)}")
            status['fhir_server_connection'] = 'error'
            status['error_message'] = str(e)
    
    return jsonify(status)

@app.route('/api/fhir/metadata', methods=['GET'])
def fhir_metadata():
    """Get the FHIR server metadata/capability statement."""
    if not fhir_client.is_configured():
        return jsonify({'error': 'FHIR server not configured'}), 400
    
    try:
        metadata = fhir_client.get_metadata()
        return jsonify(metadata)
    except Exception as e:
        logger.error(f"Error fetching FHIR metadata: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/fhir/resource/<resource_type>/<resource_id>', methods=['GET'])
def get_resource(resource_type, resource_id):
    """Get a specific FHIR resource by type and ID."""
    if not fhir_client.is_configured():
        return jsonify({'error': 'FHIR server not configured'}), 400
    
    try:
        resource = fhir_client.read_resource(resource_type, resource_id)
        return jsonify(resource)
    except Exception as e:
        logger.error(f"Error fetching resource {resource_type}/{resource_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/fhir/search/<resource_type>', methods=['GET'])
def search_resources(resource_type):
    """Search for FHIR resources of a specific type with query parameters."""
    if not fhir_client.is_configured():
        return jsonify({'error': 'FHIR server not configured'}), 400
    
    # Get query parameters from request
    search_params = request.args.to_dict()
    
    try:
        # Validate search request
        schema = FHIRResourceRequestSchema()
        validated_data = schema.load({'resource_type': resource_type, 'search_params': search_params})
        
        results = fhir_client.search_resources(
            resource_type=validated_data['resource_type'], 
            params=validated_data['search_params']
        )
        return jsonify(results)
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400
    except Exception as e:
        logger.error(f"Error searching for {resource_type} resources: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    logger.error(f"Server error: {str(e)}")
    return render_template('500.html', error=str(e)), 500
