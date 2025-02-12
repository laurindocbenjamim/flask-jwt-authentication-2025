
import os, secrets
#from flask_wtf.csrf import CSRFProtect
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
    RATE_LIMIT="100 per day,10 per minute"

class Config(MySmtpConfig):
    ACCESS_EXPIRES = timedelta(minutes=40) # Default: timedelta(minutes=15)
    # Here you can globally configure all the ways you want to allow JWTs to
    # be sent to your web application. By default, this will be only headers.
    JWT_TOKEN_LOCATION = ["cookies"]

    # If true this will only allow the cookies that contain your JWTs to be sent
    # over https. In production, this should always be set to True
    JWT_COOKIE_SECURE = False

    SECRET_KEY = os.getenv('SECRET_KEY', 'paaoeAtEpkR5IcoMb6AjISxhpSEz7--1iWoB6QloNjRdjsKrVwlVJGKNM8V5su1humYcrblV01svzoTmXg0e3A')
    # Correctly set the secret key and algorithm
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', "PTUdaZiU9Q4yLPcTB9SX_aqgf6JrZOhM0IS-uIBLumN2gcfKFSpEe2j9AAu8YATgw8Oj4onTgEqnwRwURgupYQ")  # Secure key
    #SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///development.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ALGORITHM = "HS256"
    JWT_ACCESS_TOKEN_EXPIRES = ACCESS_EXPIRES