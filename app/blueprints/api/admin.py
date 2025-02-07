
from flask import (
    Blueprint, jsonify,
    make_response
)
from flask_jwt_extended import (
    JWTManager, 
    create_access_token,
    jwt_required
)

admin_api = Blueprint('admin_api', __name__)

@admin_api.route('/admin')
@jwt_required
def admin():
    return jsonify(message="Welcome to Admin area")
