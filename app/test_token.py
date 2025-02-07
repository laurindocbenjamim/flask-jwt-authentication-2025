from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token
import secrets

app = Flask(__name__)

# Correctly set the secret key and algorithm
app.config['JWT_SECRET_KEY'] = secrets.token_urlsafe(64)  # Secure key
app.config['JWT_ALGORITHM'] = "HS256"

jwt = JWTManager(app)

# Generate a JWT token
access_token = create_access_token(identity="test_user")

print("Generated JWT:", access_token)
