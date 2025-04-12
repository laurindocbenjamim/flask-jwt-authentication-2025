

import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

from flask import jsonify, current_app
from flask_restful import Api, Resource, reqparse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app.utils import limiter
from app.models import User
from app.factory import (
    create_user, confirm_user_email, create_user_object, delete_user
)

from app.utils import admin_required
from flask_jwt_extended import jwt_required,current_user

class UserManagementApi(Resource):
   
    @admin_required()
    @limiter.limit("20 per minute")
    def patch(self, token):
        """
        Email confirmation endpoint
        
        Args:
            token: JWT confirmation token
        
        Returns:
            Redirect to appropriate status page
        """
        return f"confirmed"
    
    @admin_required()
    @limiter.limit("20 per minute")
    def put(self, user_id):
        """
        Update user details
        """
        return f"updated"
    
    @admin_required()
    @limiter.limit("5 per minute")
    def delete(self, user_id):
        """
        Delete a user by ID
        """
        return f"deleted"
    
    @admin_required()
    @limiter.limit("15 per minute")
    def get(self):
        users = User.query.all()
        serialized_users = User.serialize_all(users)
        return jsonify(status_code=200, users=serialized_users)


