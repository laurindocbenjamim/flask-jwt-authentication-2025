

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
api.add_resource(UserApi, '/dao')
