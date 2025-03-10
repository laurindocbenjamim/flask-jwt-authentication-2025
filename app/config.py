
import os, secrets
from flask_mail import Mail, Message
from flask_limiter import Limiter
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

class MySmtpConfig:
    MAIL_SERVER=os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT=int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS=os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@example.com')
    CONFIRMATION_EXPIRATION=timedelta(hours=24)
    RATE_LIMIT = os.getenv("RATE_LIMIT", "100 per day,10 per minute")

class Config(MySmtpConfig):
    ACCESS_EXPIRES = timedelta(minutes=40) # Default: timedelta(minutes=15)
    SECRET_KEY = os.environ.get('SECRET_KEY', '12345')
    # Here you can globally configure all the ways you want to allow JWTs to
    # be sent to your web application. By default, this will be only headers.
    JWT_TOKEN_LOCATION = ["cookies"]
    # Enable CSRF protection for JWT cookies
    JWT_COOKIE_CSRF_PROTECT = True  # Enables CSRF protection
    
    # Correctly set the secret key and algorithm
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', '543210')  # Secure key
    #SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
        
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ALGORITHM = "HS256"
    JWT_ACCESS_TOKEN_EXPIRES = ACCESS_EXPIRES
    JWT_COOKIE_SAMESITE=os.environ.get('JWT_COOKIE_SAMESITE', 'Lax')
    # If true this will only allow the cookies that contain your JWTs to be sent
    # over https. In production, this should always be set to True
    JWT_COOKIE_SECURE = os.getenv("FLASK_ENV") == "production"

    CORS_ORIGIN = [origin.strip() for origin in os.environ.get('CORS_ORIGIN', 'https://www.d-tuning.com, https://laurindocbenjamim.github.io').split(',')]

    ALLOWED_COUNTRIES=["Angola", "Portugal","Brasil", "Espanha","Nigeria", "Ghana", "Kenya", "Togo", "South Africa"]

class DevelopmentConfig(Config):
    PORT=5000
    DEBUG = True
    LOG_LEVEL = "DEBUG"
    FLASK_ENV=os.environ.get('FLASK_ENV', 'development')
    MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", 100))

class ProductionConfig(Config):
    PORT=5000
    DEBUG = False
    LOG_LEVEL = "ERROR"
    FLASK_ENV=os.environ.get('FLASK_ENV', 'production')
    MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", 100))