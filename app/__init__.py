

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

app = Flask(__name__)

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, nullable=False, unique=True)
    full_name = db.Column(db.Text, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    # NOTE: In a real application make sure to properly hash and salt passwords
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)   
     
    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "password": self.password_hash,
            "full_name": self.full_name,
        }


# This could be expanded to fit the needs of your application. For example,
# it could track who revoked a JWT, when a token expires, notes for why a
# JWT was revoked, an endpoint to un-revoked a JWT, etc.
# Making jti an index can significantly speed up the search when there are
# tens of thousands of records. Remember this query will happen for every
# (protected) request,
# If your database supports a UUID type, this can be used for the jti column
# as well
class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    type = db.Column(db.String(16), nullable=False)
    user_id = db.Column(
        db.ForeignKey('user.id'),
        default=lambda: current_user.id,
        nullable=True,
    )
    created_at = db.Column(
        db.DateTime,
        server_default=func.now(),
        nullable=True,
    )


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
                    r"/test-token": {"origins": ["http://localhost:5000", "http://localhost:52330"]},
                    r"/protected": {"origins": ["http://localhost:5000", "http://localhost:52330"]},
                    })
    
    jwt_ex = JWTManager(app)

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


    @app.route('/', methods=['GET', 'POST'])
    def login_without_cookies():

        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        

        user = User.query.filter_by(username=username).one_or_none()
        if not user or not user.check_password(password):
            return jsonify({"error": "Wrong username or password", "user": user.to_dict()}), 401
        # Generate a JWT token
       
        access_token = create_access_token(identity=str(user.id))

        return make_response(jsonify({"secret_key": secret_key, 
                                      "access_token": access_token,
                                      "username": username
                                      }),200)
    
    # Login with cookie
    @app.route('/login-w-cookies', methods=['GET', 'POST'])
    def login_with_cookies():
        response = jsonify({"msg": "login successful"}), 200
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        

        user = User.query.filter_by(username=username).one_or_none()
        if not user or not user.check_password(password):
            return jsonify({"error": "Wrong username or password", "user": user.to_dict()}), 401
        # Generate a JWT token
       
        access_token = create_access_token(identity=str(user.id))

        response = make_response(jsonify({"status_code": 200,
                                      "username": username
                                      }),200)
        set_access_cookies(response, access_token)
        return response
    
    # Logout with cookies
    @app.route("/logout_with_cookies", methods=["GET", "POST"])
    def logout_with_cookies():
        response = jsonify({'msg':"logout successful", 'status_code':200})
        unset_jwt_cookies(response)
        return response

    # Endpoint for revoking the current users access token. Saved the unique
    # identifier (jti) for the JWT into our database.
    @app.route("/logout_with_revoking_token", methods=["DELETE"])
    @jwt_required()
    def modify_token():
        jti = get_jwt()["jti"]
        now = datetime.now(timezone.utc)
        db.session.add(TokenBlocklist(jti=jti, created_at=now))
        db.session.commit()

        response = jsonify(msg="JWT revoked")
        #unset_jwt_cookies(response)
        return response

    @app.route("/logout_with_revoking_token_2", methods=["DELETE"])
    @jwt_required(verify_type=False)
    def modify_token_2():
        token = get_jwt()
        jti = token["jti"]
        ttype = token["type"]
        now = datetime.now(timezone.utc)
        db.session.add(TokenBlocklist(jti=jti, type=ttype, created_at=now))
        db.session.commit()
        
        response = jsonify(msg=f"{ttype.capitalize()} token successfully revoked")
        #unset_jwt_cookies(response)
        return response


    @app.route('/protected', methods=['GET'])
    @jwt_required()
    def ptotected():
        
        claims = get_jwt()
        response = make_response(jsonify(
            status_code=200,
            foo="bar",
            message="Welcome to protected route!",
            claims=claims,
            id=current_user.id,
            full_name=current_user.full_name,
            username=current_user.username,
            ), 200)

        return response

    @app.route("/only_headers")
    @jwt_required(locations=["headers"])
    def only_headers():
        return jsonify(foo="baz")

    @app.route('/test-token', methods=['POST'])
    def test_jwt_token():
        data = request.get_json()

        token = data.get('token')

        # Replace this with the token generated in Flask
        if(not token):
            return f"Token is required!"

        # Replace with the same secret key you used in Flask

        try:
            decoded = jwt.decode(token, secret_key, algorithms=["HS256"])
            return jsonify({'token_received': token, 'decoded': decoded})
        except jwt.ExpiredSignatureError as e:
            return f"❌ Token has expired {str(e)}"
        except jwt.InvalidTokenError as e:
            return f"❌ Token is invalid {str(e)}"

    
    return app
