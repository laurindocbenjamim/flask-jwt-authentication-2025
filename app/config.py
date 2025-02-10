
import secrets
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()


class Config:
    ACCESS_EXPIRES = timedelta(minutes=30) # Default: timedelta(minutes=15)
    # Here you can globally configure all the ways you want to allow JWTs to
    # be sent to your web application. By default, this will be only headers.
    JWT_TOKEN_LOCATION = ["cookies"]

    # If true this will only allow the cookies that contain your JWTs to be sent
    # over https. In production, this should always be set to True
    JWT_COOKIE_SECURE = False

    secret_key = secrets.token_urlsafe(64)
    SECRET_KEY = secret_key
    # Correctly set the secret key and algorithm
    JWT_SECRET_KEY = secrets.token_urlsafe(64)  # Secure key
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ALGORITHM = "HS256"
    JWT_ACCESS_TOKEN_EXPIRES = ACCESS_EXPIRES