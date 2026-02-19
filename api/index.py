"""
Vercel serverless entry point.

Wraps the Flask WSGI app for Vercel's Python runtime.
All routes are handled by Flask — Vercel just proxies to this handler.
"""

import sys
import os

# Ensure project root is on the Python path so imports resolve
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the fully-configured Flask app
from main import app

# Vercel expects the WSGI app as `app`
# (the variable name must match what vercel.json references)
