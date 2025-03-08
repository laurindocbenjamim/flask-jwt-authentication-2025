
import os, secrets
from datetime import timedelta

class SqlAchemyConfig:
    #SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class JwtConfig:
    ACCESS_EXPIRES = timedelta(minutes=40) # Default: timedelta(minutes=15)
    # Here you can globally configure all the ways you want to allow JWTs to
    # be sent to your web application. By default, this will be only headers.
    JWT_TOKEN_LOCATION = ["cookies"]

    # If true this will only allow the cookies that contain your JWTs to be sent
    # over https. In production, this should always be set to True
    JWT_COOKIE_SECURE = False

   # Correctly set the secret key and algorithm
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', "PTUdaZiU9Q4yLPcTB9SX_aqgf6JrZOhM0IS-uIBLumN2gcfKFSpEe2j9AAu8YATgw8Oj4onTgEqnwRwURgupYQ")  # Secure key
    JWT_ALGORITHM = "HS256"
    JWT_ACCESS_TOKEN_EXPIRES = ACCESS_EXPIRES

    # The key for error messages in a JSON response returned by this extension.
    # Default: "msg"
    JWT_ERROR_MESSAGE_KEY = "jwt_error"

    #The name of the cookie that will hold the access token.
    # Default: "access_token_cookie
    #JWT_ACCESS_COOKIE_NAME

    #To use SameSite=None, you must set this option to the string "None" as well as setting JWT_COOKIE_SECURE to True
    #Default: None, which is treated as "Lax" by browsers.
    JWT_COOKIE_SAMESITE = "None"

    # This should always be True in production. Default: False
    JWT_COOKIE_SECURE = False

    # The name of the cookie that will hold the refresh token.
    JWT_REFRESH_COOKIE_NAME = "refresh_token_cookie"


class ProductionConfig(JwtConfig, SqlAchemyConfig):
    DEBUG = False
    LOG_LEVEL = "ERROR"
    PORT = 5000
    MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", 100))
    APP_NAME = os.getenv("APP_NAME", "FlaskJwtApp2025")
    APP_VERSION = os.getenv("APP_VERSION", "1.0.0")
    SECRET_KEY = os.getenv('SECRET_KEY', 'paaoeAtEpkR5IcoMb6AjISxhpSEz7--1iWoB6QloNjRdjsKrVwlVJGKNM8V5su1humYcrblV01svzoTmXg0e3A')
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///production.db")


class DevelopmentConfig(JwtConfig, SqlAchemyConfig):
    DEBUG = True
    LOG_LEVEL = "DEBUG"
    PORT = 5000
    MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", 100))
    APP_NAME = os.getenv("APP_NAME", "FlaskJwtApp2025")
    APP_VERSION = os.getenv("APP_VERSION", "1.0.0")
    SECRET_KEY = os.getenv('SECRET_KEY', 'paaoeAtEpkR5IcoMb6AjISxhpSEz7--1iWoB6QloNjRdjsKrVwlVJGKNM8V5su1humYcrblV01svzoTmXg0e3A')
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///development.db")

