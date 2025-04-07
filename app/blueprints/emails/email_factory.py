


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

# Send email with sendgrid
def sendgrid_email_sender(message):
    """
    
    """
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sg.send(message)
            
        return jsonify(
            status_code=response.status_code,
            message=response.body.decode('utf-8') if response.body else None,
            headers=dict(response.headers)
        )
    except Exception as e:
        return jsonify(status_code=400, message=str(e))



def get_email_confirmation_token(user_id):
    """
    
    """
    token_serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    token = token_serializer.dumps(user_id, salt='email-confirm')

    if not token:
        return ''
    return token
    

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

