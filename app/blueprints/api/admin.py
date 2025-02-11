from flask_restful import Api, Resource, reqparse


from flask import (
    Blueprint, jsonify,
    make_response,request
)
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    current_user,
    get_jwt,
    get_jwt_identity,
    set_access_cookies,
    unset_jwt_cookies
)

admin_api = Blueprint('admin_api', __name__, url_prefix='/api/v1/admin')
api = Api(admin_api)

class UserData(Resource):
    @jwt_required()
    def get(self):
        claims = get_jwt()
        response = make_response(jsonify(
            status_code=200,
            foo="bar",
            message="Welcome to protected route!",
            claims=claims,
            id=current_user.id,
            full_name=current_user.full_name,
            username=current_user.username,
            ), 200)

        return response

api.add_resource(UserData, '/user')

@admin_api.route('/admin')
@jwt_required()
def admin_r():
    return f"This is Admin BP route"

