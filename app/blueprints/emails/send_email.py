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

from flask import Blueprint, request,current_app, make_response, jsonify, render_template
from markupsafe import escape
from flask_restful import Api
from flask_jwt_extended import (
    jwt_required,
    current_user,
)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app.utils import mail, limiter
from app.models import User
from app.factory import confirm_user_email

from app.blueprints.emails.send_confirm_email import SendConfirmEmailApi, SendConfirmEmailToNewUserApi
from app.blueprints.emails.sendgrid_email_api import SendGridEmailApi
# Application Configuration

send_email_api = Blueprint("send_email", __name__, url_prefix='/api/v1/email')
api = Api(send_email_api)

api.add_resource(SendConfirmEmailApi, '/send-confirm')
api.add_resource(SendConfirmEmailToNewUserApi, '/send-confirm-to-new-user')
api.add_resource(SendGridEmailApi, '/send')

@send_email_api.route('/confirm_email')
@limiter.limit("5 per minute")
def confirm_email():
    token=escape(request.args.get('token'))
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
        return make_response(
            render_template(
                'success_email_confirm.html', status_code=400, title="Email Confirm", error='Invalid or expired confirmation link'
            ))
    
    user = User.query.filter_by(email=email).first_or_404()
    
    status, response = confirm_user_email(user=user)
    if not status:
        #return make_response(jsonify(status_code=401,error=response))
        return make_response(
            render_template(
                'success_email_confirm.html', status_code=400, title="Email Confirm", error='Failed to confirm your email.'
            ))
        
    return make_response(
            render_template(
                'success_email_confirm.html', status_code=200, title="Email Confirm", message='Your email has been confirmed successfull!'
            ))

