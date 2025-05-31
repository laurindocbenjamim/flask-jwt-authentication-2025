from flask import Blueprint, send_from_directory, jsonify, current_app as app
from .worflow import WorkflowTextData, WorkflowMedia, GeneralFileUpload
from flask_restful import Api
import os
import logging

workflow_bp = Blueprint('workflow', __name__, url_prefix='/api/v2/workflow')
api = Api(workflow_bp)



@workflow_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return {'status': 'ok'}, 200

# --- Register API Resources ---
api.add_resource(WorkflowTextData, '/text-data')
api.add_resource(WorkflowMedia, '/media')
api.add_resource(GeneralFileUpload, '/upload')


# --- Serve uploaded files statically (for local storage) ---
# This route must come AFTER os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# --- Validation and Sanitization Functions ---
def sanitize_filename(filename):
    """
    Sanitizes a filename to remove potentially dangerous characters and path traversal attempts.
    Keeps alphanumeric, '.', '_', '-'.
    """
    filename = os.path.basename(filename) # Remove any path components
    return "".join(c for c in filename if c.isalnum() or c in ('.', '_', '-')).strip()


@workflow_bp.route('/uploads/<filename>')
def uploaded_file(filename):
    # Sanitize filename before serving to prevent directory traversal
    safe_filename = sanitize_filename(filename)
    if not safe_filename or safe_filename != filename:
        return jsonify({"status": "error", "message": "Invalid filename for access."}), 400
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], safe_filename)
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "File not found."}), 404
    except Exception as e:
        logging.error(f"Error serving file {filename}: {e}", exc_info=True)
        return jsonify({"status": "error", "message": "Error serving file."}), 500


