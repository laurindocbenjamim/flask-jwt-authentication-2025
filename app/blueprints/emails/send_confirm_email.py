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

from flask import current_app, request, jsonify, make_response, render_template, url_for

from flask_mail import Mail, Message
from flask_jwt_extended import (
    jwt_required,
    current_user,
)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app.utils import mail, limiter
from app.models import User
from app.factory import create_user, confirm_user_email
from flask_restful import Api, Resource, reqparse
from app.factory import sanitize_email

# Email Utilities
def send_async_email(msg):
    """Send email asynchronously"""
    with current_app.app_context():
        mail.send(msg)

def send_confirmation_email(email):
    """
    Generate and send confirmation email
    
    Args:
        user: User object to send email to
    
    Returns:
        bool: True if email was successfully sent
    """
    # Token serializer
    token_serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    token = token_serializer.dumps(email, salt='email-confirm')
    confirm_url = url_for('send_email.confirm_email', token=token, _external=True)
    msg = Message(
        "Confirm Your Email Address",
        recipients=[email],
        html=render_template('confirm_email.html', confirm_url=confirm_url)
    )
    try:
        send_async_email(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Error sending email: {e}")
        return False


class SendConfirmEmailApi(Resource):

    @jwt_required()
    @limiter.limit("5 per minute")
    def get(self):
        email=current_user.email
        user = User.query.filter_by(email=email).first_or_404()
        if not user:
            return jsonify(status_code=401, error="User not found")
        status = send_confirmation_email(email)
        if not status:
            return jsonify(status_code=401, message=f"Failed to send the confirmation email to '{email}'. ")
        return jsonify(status_code=200, message=f"An email has been sent to '{email}' to confirm your registration.", recipient=email)

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



class SendConfirmEmailToNewUserApi(Resource):

    @limiter.limit("5 per minute")
    def post(self):

        """
        User confirmation endpoint
        
        GET: Display confirmation form
        POST: Process confirmation request
        """
        parser = reqparse.RequestParser()
        parser.add_argument('email', required=True, type=sanitize_email, help="Enter a valid email!")
        data = parser.parse_args()
        
        email=data.get('email')
        user = User.query.filter_by(email=email).first_or_404()
        if not user:
            return jsonify(status_code=401, error="User not found")
        status = send_confirmation_email(email)
        if not status:
            return jsonify(status_code=401, message=f"Failed to send the confirmation email to '{email}'. ")
        return jsonify(status_code=200, message=f"An email has been sent to '{email}' to confirm your registration.", recipient=email)

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


