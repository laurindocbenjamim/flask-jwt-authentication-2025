

import os

from flask import Flask, Blueprint, jsonify, request, redirect, url_for
from flask_jwt_extended import create_access_token

from app.factory import (
    get_user_parser,
    sanitize_name,
    sanitize_username,
    sanitize_email,
    sanitize_phone,
    sanitize_country
)

from flask_caching import Cache
from authlib.integrations.flask_client import OAuth
from app.utils import db

#csrf = SeaSurf()
oauth = OAuth()
cache = Cache()


from app.models import User


social_app = Blueprint("social", __name__)
google = oauth.register(
            name='google',
            client_id=os.getenv('GOOGLE_CLIENT_ID'),
            client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
            access_token_url='https://accounts.google.com/o/oauth2/token',
            access_token_params=None,
            authorize_url='https://accounts.google.com/o/oauth2/auth',
            authorize_params=None,
            api_base_url='https://www.googleapis.com/oauth2/v1/',
            client_kwargs={'scope': 'openid email profile'},
        )
    
# Social Login
@social_app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_auth', _external=True)
    return google.authorize_redirect(redirect_uri)

@social_app.route('/login/google/callback')
def google_auth():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()
    
    user = User.query.filter_by(social_id=user_info['id']).first()
    if not user:
        user = User(
            email=user_info['email'],
            first_name=user_info.get('given_name'),
            last_name=user_info.get('family_name'),
            social_id=user_info['id']
        )
        db.session.add(user)
        db.session.commit()
    
    access_token = create_access_token(identity=user.id)
    return redirect(url_for('dashboard', token=access_token))




#
@social_app.route('/api/auth/reset-password', methods=['POST'])
#@limiter.limit('3/hour')
def request_password_reset():
    email = sanitize_email(request.json.get('email'))
    user = User.query.filter_by(email=email).first()
    
    #if user:
        #reset_token = generate_reset_token(user)
        #send_reset_email(user.email, reset_token)
        
    return jsonify(message="If account exists, reset email sent")

@social_app.route('/api/auth/reset-password/<token>', methods=['POST'])
def reset_password(token):
    user = User.verify_reset_token(token)
    if not user:
        return jsonify(error="Invalid token"), 400
    
    new_password = sanitize_name(request.json.get('password'))
    user.set_password(new_password)
    db.session.commit()
    
    return jsonify(message="Password updated")
