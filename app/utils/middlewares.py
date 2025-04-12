
# In a new file app/middleware/request_id.py
import uuid
from functools import wraps
from flask import request, g

def request_id_middleware(app):
    @app.before_request
    def assign_request_id():
        """Add unique request ID to each request."""
        request_id = request.headers.get('X-Request-ID') or f"flask-{uuid.uuid4()}"
        g.request_id = request_id
        request.request_id = request_id