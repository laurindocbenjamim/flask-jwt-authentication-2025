from flask import Blueprint, current_app, render_template, make_response, redirect, url_for, request, jsonify, session
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import os, sys


auth2_api_bp = Blueprint("auth2_api", __name__, url_prefix='/api/v1/auth2')




@auth2_api_bp.route('/')
def index():
    if 'google_id' in session:
        return render_template('index.html', logged_in=True, user_info=session)
    return render_template('index.html', logged_in=False)

@auth2_api_bp.route('/login')
def login():
    try:
        CLIENT_ID = open('app/static/credentials_google_api.json', 'r').read()  # Carregue o ID do cliente do ficheiro de credenciais
    except Exception as e:
        return jsonify(error=e)
    #return render_template('login.html', client_id=CLIENT_ID)
    return make_response(jsonify(sms="Welcome to login page", client_id=CLIENT_ID))

@auth2_api_bp.route('/google/signin', methods=['POST'])
def google_auth():
    token = request.form.get('id_token')

    try:
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), CLIENT_ID)

        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')

        # ID token is valid. Get the user's Google Account ID from the 'sub' claim.
        userid = idinfo['sub']
        email = idinfo['email']
        name = idinfo['name']
        picture = idinfo['picture']

        session['google_id'] = userid
        session['email'] = email
        session['name'] = name
        session['picture'] = picture

        return jsonify({'success': True, 'redirect': url_for('index')})

    except ValueError as e:
        # Invalid token
        print(f"Erro de autenticação: {e}")
        return jsonify({'error': 'Falha na autenticação com o Google.'}), 401

@auth2_api_bp.route('/logout')
def logout():
    session.pop('google_id', None)
    session.pop('email', None)
    session.pop('name', None)
    session.pop('picture', None)
    return redirect(url_for('index'))
