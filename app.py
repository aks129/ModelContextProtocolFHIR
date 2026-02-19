"""
Flask application routes for the FHIR R6 MCP Showcase.

Provides the web UI routes:
- / (landing page)
- /r6-dashboard (interactive R6 agent dashboard)
"""

from flask import render_template
from main import app


@app.route('/')
def index():
    """Landing page — redirects attention to the R6 Dashboard."""
    return render_template('index.html')


@app.route('/r6-dashboard')
def r6_dashboard():
    """Render the R6 FHIR Agent Dashboard — interactive showcase."""
    return render_template('r6_dashboard.html')
