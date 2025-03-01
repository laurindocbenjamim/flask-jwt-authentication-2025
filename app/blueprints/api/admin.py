import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

from flask_restful import Api, Resource, reqparse
from app.utils import admin_required

from flask import (
    Blueprint, jsonify,
    make_response,request
)
from flask_jwt_extended import (
    jwt_required,
    current_user,
    get_jwt
)

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


# 
class Admin(Resource):
    @admin_required()
    def get(self):
        
        response = make_response(jsonify(
            status_code=200,
            foo="bar",
            full_name=current_user.full_name,
            message="Welcome to the Admin route!"
            ), 200)

        return response



