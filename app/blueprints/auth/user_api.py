

import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

from flask import jsonify, current_app, make_response
from flask_restful import Api, Resource, reqparse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app.utils import limiter
from app.models import User
from app.factory import create_user, confirm_user_email, create_user_object
from app.factory import get_user_parser

class UserApi(Resource):
    @limiter.limit("5 per minute")
    def post(self):
        """
        User registration endpoint
        
        GET: Display registration form
        POST: Process registration request
        """
        parser = get_user_parser()
        data = parser.parse_args()
        
        
        if User.query.filter_by(email=data.get('email')).first():
            return make_response(jsonify(status_code=401, error='Email already registered'),401)
        
        # Create new user
        new_user = create_user_object(data)
        
        status, sms = create_user(new_user=new_user)
        if not status:
            return make_response(jsonify(status_code=400, error=sms),400)
        return make_response(jsonify(status_code=200, message="User has been created successfull"),200)

    @limiter.limit("5 per minute")
    def patch(self, token):
        """
        Email confirmation endpoint
        
        Args:
            token: JWT confirmation token
        
        Returns:
            Redirect to appropriate status page
        """
        try:
            token_serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
            email = token_serializer.loads(
                token,
                salt='email-confirm',
                max_age=int(current_app.config['CONFIRMATION_EXPIRATION'].total_seconds())
            )
        except (SignatureExpired, BadSignature):
            return jsonify(status_code=401, error='Invalid or expired confirmation link')
        
        user = User.query.filter_by(email=email).first_or_404()
        
        status, response = confirm_user_email(user=user)
        if not status:
            return jsonify(status_code=401,error=response)
        
        return jsonify(status_code=200, message=response)
    
    def get(self):
        users = User.query.all()
        serialized_users = User.serialize_all(users)
        return jsonify(status_code=200, users=serialized_users)


