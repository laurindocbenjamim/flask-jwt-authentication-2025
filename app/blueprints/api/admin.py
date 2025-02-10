from flask_restful import Api, Resource, reqparse


from flask import (
    Blueprint, jsonify,
    make_response,request
)
from flask_jwt_extended import (
    JWTManager, 
    create_access_token,
    jwt_required
)

admin_api = Blueprint('admin_api', __name__)
api = Api(admin_api)

class UserData(Resource):
    @jwt_required()
    def get(self):
        # Here you would add your logic to fetch user data
        return jsonify(sms="User protected data",data={"username": "admin", "email": "admin@example.com"})

api.add_resource(UserData, '/user')

