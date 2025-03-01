

"""
echo "export SENDGRID_API_KEY=''" > sendgrid.env
echo "sendgrid.env" >> .gitignore
source ./sendgrid.env
"""


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

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

def get_mail_message(*,subject, message, sender_email, recipient):
    if not subject:
        raise ValueError("Subject is required")
    if not message:
        raise ValueError("Message is required")
    if not sender_email:
        raise ValueError("Sender email is required")
    if not recipient:
        raise ValueError("Recipient is required")
    
    mail_content = Mail(
    from_email=sender_email,
    to_emails=[recipient],
    subject=subject,
    html_content=message)

    return mail_content

class SendGridEmailApi(Resource):

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
        
        message = get_mail_message(subject="Confirm your email address", message="Please click the link below to confirm your email address. ", sender_email="services@d-tuning.com", recipient=email)
        
        try:
            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
            response = sg.send(message)
            
            return jsonify(status_code=response.status_code, message=response.body, headers=response.headers)
        except Exception as e:
            return jsonify(status_code=400, message=str(e))
        

    


