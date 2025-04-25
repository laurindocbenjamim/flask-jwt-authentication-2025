
# sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))
import os
import secrets
import jwt
import uuid
from hmac import compare_digest
import logging
# from sqlalchemy.exc import AttributeError
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from flask import Flask, jsonify, make_response, request
from flask_wtf.csrf import CSRFError
from flask_cors import CORS

from flask_jwt_extended import (
    JWTManager, 
    create_access_token,
    get_jwt,
    get_jwt_identity,
    set_access_cookies
)
from sqlalchemy.sql import func
from werkzeug.security import check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.middleware.http_proxy import ProxyMiddleware



from flask import request, g

from app.config import Config, DevelopmentConfig, ProductionConfig

from app.utils import load_extentions, db, limiter, cors, csrf
from app.utils import create_additional_claims
from app.models import User, TokenBlocklist, TokenBlocklist2
from app.blueprints import (user_api_bp,
                            auth_api, 
                            admin_api, 
                            send_email_api,
                            web_scrapping_api_bp,
                            bp_speech_recognition,
                            auth2_api_bp,
                            cv_bp_api,
                            payment_bp_api
                            #download_youtube_video_app,
                            #ai_audio_book_bp
                            )

from app.utils.handling_errors import handle_errors

from app.storage_cloud import cloud_storage_bp_api
from app.modules_web_site import web_site_app
from app.modules_author_profile import bp_author
from app.routes import routes
#from app.utils import request_id_middleware

#from dotenv import load_dotenv

#load_dotenv()

app = Flask(__name__)
#csrf = CSRFProtect()
root_files_path = 'static'
# Configuration
DOWNLOAD_FOLDER = os.path.join(app.root_path,root_files_path,'downloads')
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER

AUDIOBOOKS_FOLDER = os.path.join(app.root_path,root_files_path,'audiobooks')
app.config['AUDIOBOOKS_FOLDER'] = AUDIOBOOKS_FOLDER

COOKIES_FOLDER = os.path.join(app.root_path,root_files_path,'cookies')
app.config['COOKIES_FOLDER'] = COOKIES_FOLDER

os.makedirs(COOKIES_FOLDER, exist_ok=True)
os.makedirs(AUDIOBOOKS_FOLDER, exist_ok=True)
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)


# Email Utilities
def send_async_email(mail,msg):
    """Send email asynchronously"""
    with app.app_context():
        mail.send(msg)

def create_app():
    
    env = os.getenv("FLASK_ENV", "development")

    if env == "production":
        app.config.from_object(ProductionConfig)
    else:
        app.config.from_object(DevelopmentConfig)

    #app.config.from_object(Config)
    """
    If some errorr occurred with the CSRFProtect library implementation try
        pip uninstall babel
        pip install babel

    """

    #request_id_middleware(app=app)

    # 2. If behind a proxy, add ProxyFix (but only in production!)
    """ if app.env == 'production':
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=1,       # Trust X-Forwarded-For
            x_proto=1,      # Trust X-Forwarded-Proto
            x_host=1,       # Trust X-Forwarded-Host
            x_prefix=1      # Trust X-Forwarded-Prefix
        )"""
    
    

    load_extentions(app=app)
    #csrf.init_app(app=app)
    jwt_ex = JWTManager(app)
    app.logger.setLevel(logging.INFO)
    app.logger.setLevel(logging.DEBUG)
    app.logger.setLevel(logging.ERROR)
    app.logger.setLevel(logging.WARNING)
    app.logger.setLevel(logging.CRITICAL)
    app.logger.setLevel(logging.FATAL)
    app.logger.setLevel(logging.NOTSET)
    

    """@app.before_request
    def assign_request_id():
        #Add a unique request ID to each incoming request.
        g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
        # Make it available on the request object as well
        request.request_id = g.request_id"""

    """@app.after_request
    def add_request_id_header(response):
        #Add request ID to response headers.
        if hasattr(request, 'request_id'):
            response.headers['X-Request-ID'] = request.request_id
        return response"""


    # Using the additional_claims_loader, we can specify a method that will be
    # called when creating JWTs. The decorated method must take the identity
    # we are creating a token for and return a dictionary of additional
    # claims to add to the JWT.
    @jwt_ex.additional_claims_loader
    def add_claims_to_access_token(identity):

        claim_data = {
            "aud": "some_audience",
            "foo": "bar",
            "identity": identity,
        }
        # get user from database
        user = User.query.filter_by(id=identity).one_or_none()

        try:
            if user:
                claims = create_additional_claims(user=user)
                if claims:
                    claim_data.update(claims)

        except AttributeError as e:
            print(f"AttributeError: on add claims. Error: {str(e)}")
        except Exception as e:
            print(f"Exception on add claims. Error: {str(e)}")
        return claim_data
    
    # Set a callback function to return a custom response whenever an expired
    # token attempts to access a protected route. This particular callback function
    # takes the jwt_header and jwt_payload as arguments, and must return a Flask
    # response. Check the API documentation to see the required argument and return
    # values for other callback functions.
    @jwt_ex.expired_token_loader
    def my_expired_token_callback(jwt_header, jwt_payload):
        return jsonify(code="dave", err="IToken has expired"), 401

    # Security Middleware
    @app.after_request
    def set_security_headers(response):
        #Set secure HTTP headers
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response
    

    # load handling errors
    handle_errors(app, CSRFError)

    @app.after_request
    def refresh_expiring_jwts(response):
        try:
            exp_timestamp = get_jwt()["exp"]
            now = datetime.now(timezone.utc)
            target_timestamp = datetime.timestamp(now + timedelta(minutes=15))
            if target_timestamp > exp_timestamp:
                access_token = create_access_token(identity=get_jwt_identity())
                set_access_cookies(response, access_token)
            return response
        except (RuntimeError, KeyError):
            # Case where there is not a valid JWT. Just return the original response
            return response
    
    # Register a callback function that takes whatever object is passed in as the
    # identity when creating JWTs and converts it to a JSON serializable format.
    @jwt_ex.user_identity_loader
    def user_identity_lookup(user):
        return str(user)
    
    # Register a callback function that loads a user from your database whenever
    # a protected route is accessed. This should return any python object on a
    # successful lookup, or None if the lookup failed for any reason (for example
    # if the user has been deleted from the database).
    @jwt_ex.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.filter_by(id=identity).one_or_none()

    # Callback function to check if a JWT exists in the database blocklist
    @jwt_ex.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
        jti = jwt_payload["jti"]
        token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()

        return token is not None

    csrf.exempt(user_api_bp)
    csrf.exempt(auth_api)
    csrf.exempt(auth2_api_bp)
    csrf.exempt(bp_author)
    csrf.exempt(admin_api)
    csrf.exempt(send_email_api)
    csrf.exempt(bp_speech_recognition)
    csrf.exempt(cv_bp_api)
    csrf.exempt(payment_bp_api)
    csrf.exempt(cloud_storage_bp_api)
    #csrf.exempt(download_youtube_video_app)
    #csrf.exempt(ai_audio_book_bp)

    # Binding the blueprint Views
    app.register_blueprint(web_site_app)
    app.register_blueprint(web_scrapping_api_bp, url_prefix='/api/v1/web-scrapping')
    #app.register_blueprint(bp_author)    
    app.register_blueprint(user_api_bp, url_prefix='/api/v1/user')
    app.register_blueprint(auth_api, url_prefix='/api/v1/auth')
    app.register_blueprint(auth2_api_bp, url_prefix='/api/v1/auth2')
    app.register_blueprint(admin_api, url_prefix='/api/v1/admin')
    app.register_blueprint(send_email_api, url_prefix='/api/v1/email')
    app.register_blueprint(bp_speech_recognition, url_prefix='/api/v1/speech_recognition')
    app.register_blueprint(cv_bp_api)
    app.register_blueprint(payment_bp_api)
    app.register_blueprint(cloud_storage_bp_api)
    #app.register_blueprint(download_youtube_video_app)
    #app.register_blueprint(ai_audio_book_bp)

    routes(app=app)

    
    return app
