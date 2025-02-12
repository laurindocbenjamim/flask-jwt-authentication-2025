
import os
import sqlalchemy
from hmac import compare_digest
# from sqlalchemy.exc import AttributeError
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from flask import Flask, jsonify, make_response, request
from flask_cors import CORS

from flask_jwt_extended import (
    JWTManager, 
    create_access_token,
    jwt_required,
    current_user,
    get_jwt,
    get_jwt_identity,
    set_access_cookies,
    unset_jwt_cookies
)
from sqlalchemy.sql import func
import secrets
import jwt
from werkzeug.security import check_password_hash
from app.configs.config import DevelopmentConfig, ProductionConfig
from app.config import Config
from app.configs import load_extentions, db, limiter, cors
from app.configs import create_additional_claims
from app.models import User, TokenBlocklist, TokenBlocklist2
from app.blueprints import auth_api, admin_api, send_email_api
from app.routes import routes


app = Flask(__name__)


def create_app():
    
    """env = os.getenv("FLASK_ENV", "development")

    if env == "production":
        app.config.from_object(ProductionConfig)
    else:
        app.config.from_object(DevelopmentConfig)"""

    app.config.from_object(Config)

    load_extentions(app=app)
    
    CORS(app, supports_credentials=True, 
         resources={r"/*": {"origins": ["http://localhost:5000", "http://localhost:52330"]},
                    r"/api/*": {"origins": ["http://localhost:5000", "http://localhost:52330"]},                   
                    r"/protected": {"origins": ["http://localhost:5000", "http://localhost:52330"]},
                    r"/logout-with-revoking-token": {"origins": ["http://localhost:5000", "http://localhost:52330"]},
                    })
    
    jwt_ex = JWTManager(app)


    # Binding the blueprint Views
    app.register_blueprint(auth_api, url_prefix='/api/v1/auth')
    app.register_blueprint(admin_api, url_prefix='/api/v1/admin')
    app.register_blueprint(send_email_api, url_prefix='/api/v1/email')
    
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
    """@app.after_request
        def set_security_headers(response):
            #Set secure HTTP headers
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            return response
    """

    # Error Handlers
    @app.errorhandler(429)
    def ratelimit_handler(e):
        """Handle rate limit exceeded errors"""
        return jsonify(status_code=429, error="Too many requests. Please try again later.")

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


    routes(app=app)

    
    return app
