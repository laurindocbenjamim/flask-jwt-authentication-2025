"""
User Registration Email Confirmation System

This Flask application handles user registration with email confirmation,
incorporating security best practices and documentation.

Features:
- Secure password hashing
- CSRF protection
- JWT-based confirmation tokens with expiration
- Rate limiting
- Secure headers
- SQL injection protection
- Environment-based configuration
- Async email sending
"""

import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

from flask import current_app, jsonify, make_response, render_template, url_for

from flask_mail import Mail, Message
from flask_jwt_extended import (
    jwt_required,
    current_user,
)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app.utils import limiter
from app.models import User
from app.factory import confirm_user_email
from flask_restful import Api, Resource, reqparse

from app.blueprints.emails.email_factory import get_email_confirmation_token, get_mail_message, sendgrid_email_sender


class SendConfirmationEmailSendGridApi(Resource):

    @jwt_required()
    @limiter.limit("5 per minute")
    def get(self):
        email=current_user.email
        user = User.query.filter_by(email=email).first_or_404()
        if not user:
            return jsonify(status_code=401, error="User not found")
        
        # Create the body message
        # Token serializer
       
        token = get_email_confirmation_token(user_id=email)

        confirm_url = url_for('send_email.confirm_email', token=token, _external=True)
        
        html=render_template('confirm_email.html', confirm_url=confirm_url)
    
        if not token or token=='':
            return make_response(jsonify(status_code=401, message=f"Failed to send the confirmation email to '{email}'. "),400)
        
        response = sendgrid_email_sender(message=html)
        return make_response(response, 200)

    @jwt_required()
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



