

from hmac import compare_digest
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from flask import Flask, jsonify, make_response, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
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
from app.config import Config, db
from app.models import User, TokenBlocklist, TokenBlocklist2
from app.blueprints import auth_api, admin_api
from app.routes import routes

app = Flask(__name__)


def create_app():
    
    ACCESS_EXPIRES = timedelta(minutes=30) # Default: timedelta(minutes=15)
    # Here you can globally configure all the ways you want to allow JWTs to
    # be sent to your web application. By default, this will be only headers.
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]

    # If true this will only allow the cookies that contain your JWTs to be sent
    # over https. In production, this should always be set to True
    app.config["JWT_COOKIE_SECURE"] = False

    secret_key = secrets.token_urlsafe(64)
    app.config['SECRET_KEY'] = secret_key
    # Correctly set the secret key and algorithm
    app.config['JWT_SECRET_KEY'] = secrets.token_urlsafe(64)  # Secure key
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config['JWT_ALGORITHM'] = "HS256"
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES
    

    CORS(app, supports_credentials=True, 
         resources={r"/*": {"origins": ["http://localhost:5000", "http://localhost:52330"]},
                    r"/api/*": {"origins": ["http://localhost:5000", "http://localhost:52330"]},
                    r"/test-token": {"origins": ["http://localhost:5000", "http://localhost:52330"]},
                    r"/protected": {"origins": ["http://localhost:5000", "http://localhost:52330"]},
                    r"/logout-with-revoking-token": {"origins": ["http://localhost:5000", "http://localhost:52330"]},
                    })
    
    jwt_ex = JWTManager(app)


    # Binding the blueprint Views
    app.register_blueprint(auth_api, url_prefix='/api/v1/auth')
    app.register_blueprint(admin_api, url_prefix='/api/v1/admin')
    # Using the additional_claims_loader, we can specify a method that will be
    # called when creating JWTs. The decorated method must take the identity
    # we are creating a token for and return a dictionary of additional
    # claims to add to the JWT.
    @jwt_ex.additional_claims_loader
    def add_claims_to_access_token(identity):
        return {
            "aud": "some_audience",
            "foo": "bar",
            "identity": identity,
        }
    
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

    # Call generic routes
    routes(app, secret_key)

    
    return app
