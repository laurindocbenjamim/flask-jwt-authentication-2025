

import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

from flask_restful import Api, Resource, reqparse

from flask import (
    Blueprint, jsonify,
    make_response,request, current_app
)


user_api_bp = Blueprint('user_api', __name__, url_prefix='/api/v1/user')
api = Api(user_api_bp)

from app.blueprints.auth import UserApi
"""
Create (POST): http://<your-domain>/api/v1/user/dao
Read (GET): http://<your-domain>/api/v1/user/dao (for all users) or http://<your-domain>/api/v1/user/dao/2 (for a specific user)
Update (PUT): http://<your-domain>/api/v1/user/dao/2
Delete (DELETE): http://<your-domain>/api/v1/user/dao/2
"""
api.add_resource(UserApi, '/dao/<int:user_id>', '/dao')
