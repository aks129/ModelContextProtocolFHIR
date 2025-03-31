import os
import logging
import json
import time
from flask import render_template, request, jsonify, session, redirect, url_for, flash
from marshmallow import ValidationError
from validators import FHIRServerSchema, FHIRResourceRequestSchema
from fhir_client import FHIRClient
from models import db, FHIRServerConfig, RequestLog
from main import app

# Configure logging
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize FHIR client
fhir_client = FHIRClient()

# Configure FHIR client with default server if available
with app.app_context():
    try:
        default_config = FHIRServerConfig.query.filter_by(is_default=True).first()
        if default_config:
            logger.debug(f"Loading default FHIR server configuration: {default_config.name} ({default_config.base_url})")
            fhir_client.configure(
                base_url=default_config.base_url,
                auth_type=default_config.auth_type,
                api_key=default_config.api_key,
                username=default_config.username,
                password=default_config.password
            )
    except Exception as e:
        logger.error(f"Error loading default FHIR server configuration: {str(e)}")

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
    GET: Render the settings page with a list of saved FHIR server configurations
    POST: Update FHIR server connection settings and save to database
    """
    fhir_server_schema = FHIRServerSchema()
    
    if request.method == 'POST':
        try:
            # Validate the incoming data
            data = fhir_server_schema.load(request.form)
            
            # If "set_as_default" is checked, unset the current default first
            set_as_default = request.form.get('set_as_default') == 'on'
            
            if set_as_default:
                db.session.query(FHIRServerConfig).filter_by(is_default=True).update({"is_default": False})
                db.session.commit()
            
            # Check if we're updating an existing configuration
            config_id = request.form.get('config_id')
            
            if config_id and config_id.isdigit():
                # Updating existing configuration
                config = FHIRServerConfig.query.get(int(config_id))
                if config:
                    config.base_url = data['base_url']
                    config.auth_type = data.get('auth_type')
                    config.api_key = data.get('api_key')
                    config.username = data.get('username')
                    config.password = data.get('password')
                    config.name = data.get('name', 'Default FHIR Server')
                    config.is_default = set_as_default
                    db.session.commit()
                    logger.debug(f"Updated FHIR server configuration: {config.name} ({config.id})")
                else:
                    flash(f"Configuration with ID {config_id} not found", 'danger')
                    return redirect(url_for('settings'))
            else:
                # Creating a new configuration
                config = FHIRServerConfig(
                    base_url=data['base_url'],
                    auth_type=data.get('auth_type'),
                    api_key=data.get('api_key'),
                    username=data.get('username'),
                    password=data.get('password'),
                    name=data.get('name', 'FHIR Server'),
                    is_default=set_as_default
                )
                db.session.add(config)
                db.session.commit()
                logger.debug(f"Created new FHIR server configuration: {config.name} ({config.id})")
            
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
                'auth_type': data.get('auth_type'),
                'config_id': config.id if config else None
            }
            
            flash('FHIR server settings updated successfully', 'success')
            return redirect(url_for('settings'))
            
        except ValidationError as err:
            flash(f'Invalid settings: {err.messages}', 'danger')
        except Exception as e:
            logger.error(f"Error saving FHIR server configuration: {str(e)}")
            flash(f'Error saving configuration: {str(e)}', 'danger')
    
    # Get all saved configurations
    saved_configs = []
    try:
        saved_configs = FHIRServerConfig.query.all()
    except Exception as e:
        logger.error(f"Error loading saved FHIR server configurations: {str(e)}")
    
    # Get current settings if available
    current_settings = {}
    if fhir_client.is_configured():
        current_settings = {
            'base_url': fhir_client.base_url,
            'auth_type': fhir_client.auth_type
        }
    
    return render_template('settings.html', settings=current_settings, saved_configs=saved_configs)

@app.route('/fhir-explorer')
def fhir_explorer():
    """Render the FHIR Explorer page."""
    if not fhir_client.is_configured():
        flash('Please configure your FHIR server settings first', 'warning')
        return redirect(url_for('settings'))
    
    return render_template('fhir_explorer.html')

# Test Connection Endpoint
@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    """Test a connection to a FHIR server with provided settings."""
    try:
        # Get connection settings from request
        settings = request.json
        
        if not settings or 'base_url' not in settings:
            return jsonify({
                'fhir_server_configured': False,
                'fhir_server_connection': 'error',
                'error_message': 'Base URL is required'
            }), 400
        
        # Create a temporary FHIR client for testing
        temp_client = FHIRClient(
            base_url=settings.get('base_url'),
            auth_type=settings.get('auth_type'),
            api_key=settings.get('api_key'),
            username=settings.get('username'),
            password=settings.get('password')
        )
        
        # Test the connection
        temp_client.test_connection()
        
        return jsonify({
            'fhir_server_configured': True,
            'fhir_server_connection': 'connected'
        })
    except Exception as e:
        logger.error(f"Test connection failed: {str(e)}")
        return jsonify({
            'fhir_server_configured': True,
            'fhir_server_connection': 'error',
            'error_message': str(e)
        }), 200  # Return 200 even for connection errors as this is an expected case

# API Endpoints for FHIR Server Configuration Management
@app.route('/api/configs', methods=['GET'])
def get_configurations():
    """Get all saved FHIR server configurations."""
    try:
        configs = FHIRServerConfig.query.all()
        return jsonify({
            'configurations': [c.to_dict() for c in configs]
        })
    except Exception as e:
        logger.error(f"Error retrieving FHIR server configurations: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/configs/<int:config_id>', methods=['GET'])
def get_configuration(config_id):
    """Get a specific FHIR server configuration."""
    try:
        config = FHIRServerConfig.query.get(config_id)
        if not config:
            return jsonify({'error': 'Configuration not found'}), 404
        return jsonify(config.to_dict())
    except Exception as e:
        logger.error(f"Error retrieving FHIR server configuration {config_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/configs/<int:config_id>/activate', methods=['POST'])
def activate_configuration(config_id):
    """Activate a specific FHIR server configuration."""
    try:
        config = FHIRServerConfig.query.get(config_id)
        if not config:
            return jsonify({'error': 'Configuration not found'}), 404
        
        # Configure the FHIR client with this configuration
        fhir_client.configure(
            base_url=config.base_url,
            auth_type=config.auth_type,
            api_key=config.api_key,
            username=config.username,
            password=config.password
        )
        
        # Update session
        session['fhir_server'] = {
            'base_url': config.base_url,
            'auth_type': config.auth_type,
            'config_id': config.id
        }
        
        return jsonify({'message': 'Configuration activated successfully', 'config': config.to_dict()})
    except Exception as e:
        logger.error(f"Error activating FHIR server configuration {config_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/configs/<int:config_id>', methods=['DELETE'])
def delete_configuration(config_id):
    """Delete a specific FHIR server configuration."""
    try:
        config = FHIRServerConfig.query.get(config_id)
        if not config:
            return jsonify({'error': 'Configuration not found'}), 404
        
        # If this was the default configuration, we need to reset the client
        was_default = config.is_default
        
        # Delete the configuration
        db.session.delete(config)
        db.session.commit()
        
        # If we deleted the active configuration, reset the client
        if was_default or (session.get('fhir_server', {}).get('config_id') == config_id):
            # Find a new default if available
            new_default = FHIRServerConfig.query.filter_by(is_default=True).first()
            if new_default:
                fhir_client.configure(
                    base_url=new_default.base_url,
                    auth_type=new_default.auth_type,
                    api_key=new_default.api_key,
                    username=new_default.username,
                    password=new_default.password
                )
                session['fhir_server'] = {
                    'base_url': new_default.base_url,
                    'auth_type': new_default.auth_type,
                    'config_id': new_default.id
                }
            else:
                # No default available, reset the client
                fhir_client.configure(None)
                session.pop('fhir_server', None)
        
        return jsonify({'message': 'Configuration deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting FHIR server configuration {config_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

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
            
            # Include current FHIR server details if connected
            if 'fhir_server' in session:
                status['current_fhir_server'] = {
                    'base_url': session['fhir_server'].get('base_url'),
                    'auth_type': session['fhir_server'].get('auth_type')
                }
                
                # Get the configuration if available
                if 'config_id' in session['fhir_server']:
                    config = FHIRServerConfig.query.get(session['fhir_server']['config_id'])
                    if config:
                        status['current_fhir_server']['name'] = config.name
                        status['current_fhir_server']['config_id'] = config.id
                        
        except Exception as e:
            logger.error(f"FHIR server connection test failed: {str(e)}")
            status['fhir_server_connection'] = 'error'
            status['error_message'] = str(e)
            
            # Still include the server details even if connection failed
            if 'fhir_server' in session:
                status['current_fhir_server'] = {
                    'base_url': session['fhir_server'].get('base_url'),
                    'auth_type': session['fhir_server'].get('auth_type')
                }
    
    return jsonify(status)

@app.route('/api/fhir/metadata', methods=['GET'])
def fhir_metadata():
    """Get the FHIR server metadata/capability statement."""
    if not fhir_client.is_configured():
        return jsonify({'error': 'FHIR server not configured'}), 400
    
    # Create log entry
    log_entry = RequestLog(
        method='GET',
        resource_type='metadata'
    )
    
    # Get server config ID if available
    if session.get('fhir_server', {}).get('config_id'):
        log_entry.server_config_id = session['fhir_server']['config_id']
    
    start_time = time.time()
    
    try:
        metadata = fhir_client.get_metadata()
        
        # Update log with success
        log_entry.response_status = 200
        log_entry.execution_time_ms = (time.time() - start_time) * 1000
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify(metadata)
    except Exception as e:
        logger.error(f"Error fetching FHIR metadata: {str(e)}")
        
        # Update log with error
        log_entry.response_status = 500
        log_entry.error_message = str(e)
        log_entry.execution_time_ms = (time.time() - start_time) * 1000
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'error': str(e)}), 500

@app.route('/api/fhir/resource/<resource_type>/<resource_id>', methods=['GET'])
def get_resource(resource_type, resource_id):
    """Get a specific FHIR resource by type and ID."""
    if not fhir_client.is_configured():
        return jsonify({'error': 'FHIR server not configured'}), 400
    
    # Create log entry
    log_entry = RequestLog(
        method='GET',
        resource_type=resource_type,
        resource_id=resource_id
    )
    
    # Get server config ID if available
    if session.get('fhir_server', {}).get('config_id'):
        log_entry.server_config_id = session['fhir_server']['config_id']
    
    start_time = time.time()
    
    try:
        resource = fhir_client.read_resource(resource_type, resource_id)
        
        # Update log with success
        log_entry.response_status = 200
        log_entry.execution_time_ms = (time.time() - start_time) * 1000
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify(resource)
    except Exception as e:
        logger.error(f"Error fetching resource {resource_type}/{resource_id}: {str(e)}")
        
        # Update log with error
        log_entry.response_status = 500
        log_entry.error_message = str(e)
        log_entry.execution_time_ms = (time.time() - start_time) * 1000
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'error': str(e)}), 500

@app.route('/api/fhir/search/<resource_type>', methods=['GET'])
def search_resources(resource_type):
    """Search for FHIR resources of a specific type with query parameters."""
    if not fhir_client.is_configured():
        return jsonify({'error': 'FHIR server not configured'}), 400
    
    # Get query parameters from request
    search_params = request.args.to_dict()
    
    # Create log entry
    log_entry = RequestLog(
        method='GET',
        resource_type=resource_type,
        query_params=json.dumps(search_params)
    )
    
    # Get server config ID if available
    if session.get('fhir_server', {}).get('config_id'):
        log_entry.server_config_id = session['fhir_server']['config_id']
    
    start_time = time.time()
    
    try:
        # Validate search request
        schema = FHIRResourceRequestSchema()
        validated_data = schema.load({'resource_type': resource_type, 'search_params': search_params})
        
        results = fhir_client.search_resources(
            resource_type=validated_data['resource_type'], 
            params=validated_data['search_params']
        )
        
        # Update log with success
        log_entry.response_status = 200
        log_entry.execution_time_ms = (time.time() - start_time) * 1000
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify(results)
    except ValidationError as err:
        # Update log with validation error
        log_entry.response_status = 400
        log_entry.error_message = str(err.messages)
        log_entry.execution_time_ms = (time.time() - start_time) * 1000
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'error': err.messages}), 400
    except Exception as e:
        logger.error(f"Error searching for {resource_type} resources: {str(e)}")
        
        # Update log with error
        log_entry.response_status = 500
        log_entry.error_message = str(e)
        log_entry.execution_time_ms = (time.time() - start_time) * 1000
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'error': str(e)}), 500

# Logs API
@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get request logs with optional filtering."""
    try:
        # Query parameters for filtering
        resource_type = request.args.get('resource_type')
        method = request.args.get('method')
        status = request.args.get('status')
        config_id = request.args.get('config_id')
        
        # Start with base query
        query = RequestLog.query
        
        # Apply filters if provided
        if resource_type:
            query = query.filter(RequestLog.resource_type == resource_type)
        if method:
            query = query.filter(RequestLog.method == method)
        if status and status.isdigit():
            query = query.filter(RequestLog.response_status == int(status))
        if config_id and config_id.isdigit():
            query = query.filter(RequestLog.server_config_id == int(config_id))
        
        # Order by most recent
        query = query.order_by(RequestLog.created_at.desc())
        
        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        
        # Get paginated results
        logs = query.paginate(page=page, per_page=per_page)
        
        # Format output
        result = {
            'logs': [{
                'id': log.id,
                'method': log.method,
                'resource_type': log.resource_type,
                'resource_id': log.resource_id,
                'query_params': json.loads(log.query_params) if log.query_params else None,
                'response_status': log.response_status,
                'error_message': log.error_message,
                'execution_time_ms': log.execution_time_ms,
                'server_config_id': log.server_config_id,
                'created_at': log.created_at.isoformat()
            } for log in logs.items],
            'pagination': {
                'total': logs.total,
                'pages': logs.pages,
                'current_page': logs.page,
                'per_page': logs.per_page,
                'has_next': logs.has_next,
                'has_prev': logs.has_prev
            }
        }
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error retrieving request logs: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/summary', methods=['GET'])
def get_logs_summary():
    """Get a summary of request logs."""
    try:
        # Query for total count
        total_count = db.session.query(db.func.count(RequestLog.id)).scalar()
        
        # Query for success vs. error counts
        success_count = db.session.query(db.func.count(RequestLog.id)).filter(
            RequestLog.response_status < 400
        ).scalar()
        
        error_count = db.session.query(db.func.count(RequestLog.id)).filter(
            RequestLog.response_status >= 400
        ).scalar()
        
        # Query for average execution time
        avg_time = db.session.query(db.func.avg(RequestLog.execution_time_ms)).scalar()
        
        # Query for counts by resource type
        resource_counts = db.session.query(
            RequestLog.resource_type, 
            db.func.count(RequestLog.id)
        ).group_by(RequestLog.resource_type).all()
        
        # Format output
        result = {
            'total_count': total_count,
            'success_count': success_count,
            'error_count': error_count,
            'average_execution_time_ms': round(avg_time, 2) if avg_time else None,
            'resource_type_counts': {
                rt: count for rt, count in resource_counts if rt
            }
        }
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error retrieving request logs summary: {str(e)}")
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
