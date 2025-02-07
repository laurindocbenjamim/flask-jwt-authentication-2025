

from hmac import compare_digest
from datetime import datetime, timedelta
from flask import Flask, jsonify, make_response, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, 
    create_access_token,
    jwt_required,
    current_user,
    get_jwt,
    set_access_cookies,
    unset_jwt_cookies
)
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
def create_app():
    
    # Here you can globally configure all the ways you want to allow JWTs to
    # be sent to your web application. By default, this will be only headers.
    app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies", "json", "query_string"]

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
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15) # Default: timedelta(minutes=15)
    

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
                                      }))
    
    # Login with cookie
    @app.route('/login-w-cookies', methods=['GET', 'POST'])
    def login_with_cookies():
        response = jsonify({"msg": "login successful"})
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        

        user = User.query.filter_by(username=username).one_or_none()
        if not user or not user.check_password(password):
            return jsonify({"error": "Wrong username or password", "user": user.to_dict()}), 401
        # Generate a JWT token
       
        access_token = create_access_token(identity=str(user.id))

        response = make_response(jsonify({"secret_key": secret_key, 
                                      "access_token": access_token,
                                      "username": username
                                      }))
        set_access_cookies(response, access_token)
        return response
    
    # Logout with cookies
    @app.route("/logout_with_cookies", methods=["POST"])
    def logout_with_cookies():
        response = jsonify({"msg": "logout successful"})
        unset_jwt_cookies(response)
        return response

    @app.route('/protected', methods=['GET'])
    @jwt_required()
    def ptotected():
        
        claims = get_jwt()
        response = make_response(jsonify(
            foo="bar",
            message="Welcome to protected route!",
            claims=claims,
            id=current_user.id,
            full_name=current_user.full_name,
            username=current_user.username,
            ))

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
