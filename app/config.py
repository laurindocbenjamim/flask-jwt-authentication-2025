
import os, secrets
from flask_mail import Mail, Message
from flask_limiter import Limiter
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

class MySmtpConfig:
    MAIL_SERVER='smtp.gmail.com'
    MAIL_PORT=587
    MAIL_USE_TLS=True
    
    MAIL_USERNAME="iledmd3@gmail.com"
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER="iledmd3@gmail.com"

    SMTP_HOST='smtp.gmail.com'
    SMTP_PORT=465

    CONFIRMATION_EXPIRATION=timedelta(hours=24)
    RATE_LIMIT = "100 per day,10 per minute"
    MAX_CONNECTIONS=100

class Config(MySmtpConfig):

    FLASK_ENV='development'

    DEVLOPER = os.environ.get('DEVLOPER', 'laurindocbenjamim')

    UPLOAD_FOLDER = 'uploads' 
    TEMP_FRAMES_FOLDER = 'temp_frames' # New folder for waveform frames
    GENERATED_FILES_FOLDER = 'generated_files' # Folder for generated files
    AUDIOBOOKS_FOLDER = 'audiobooks'

    ALLOWED_EXTENSIONS = {'mp3', 'wav', 'ogg'}

    #MAX_CONTENT_LENGTH= None #int(os.environ.get('MAX_CONTENT_LENGTH',25 * 1024 * 1024)) # 25MB limit for file uploads

    ACCESS_EXPIRES = timedelta(minutes=40) # Default: timedelta(hours=1)
    SECRET_KEY = os.environ.get('SECRET_KEY', '12345')

     # API Keys
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '12345')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '12345')

    ELEVENLABS_API_KEY = os.getenv('ELEVENLABS_API_KEY')

    PAYPAL_CLIENT_ID = os.environ.get('PAYPAL_CLIENT_ID', '12345')
    PAYPAL_SECRET_KEY = os.environ.get('PAYPAL_SECRET_KEY', '12345')
    STRIPE_PK = os.environ.get('STRIPE_PK', '12345')
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', '12345')
   
    OPENAI_API_KEY = os.getenv('OPEN_AI_API_KEY')

    SPACES_KEY= os.environ.get('SPACES_KEY', '')
    SPACES_BUCKET='data-tuning.storage'
    SPACES_REGION='nyc3'
    SPACES_SECRET= os.environ.get('SPACES_SECRET', '')
    SPACES_ENDPOINT= os.environ.get('SPACES_ENDPOINT', '')
    
    DB_PORT=5432
    DATABASE_URL='sqlite:///development.db'
    DISABLE_COLLECTSTATIC=1

    MYSQL_DB_PORT=3306
    MYSQL_DB_SERVER='185.12.116.142'

    # Here you can globally configure all the ways you want to allow JWTs to
    # be sent to your web application. By default, this will be only headers.
    
    # JWT Configuration
    JWT_TOKEN_LOCATION = ["cookies", "headers"]  # Allow JWTs to be sent in cookies and headers
    # Enable CSRF protection for JWT cookies
    JWT_COOKIE_CSRF_PROTECT = True  # Enables CSRF protection
    #JWT_COOKIE_DOMAIN = ".d-tuning.com" if os.getenv("FLASK_ENV") == "production" else "None"  # Set in production
    
    # Correctly set the secret key and algorithm
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', '543210')  # Secure key
    #SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
        
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ALGORITHM = "HS256"
    JWT_COOKIE_HTTPONLY = False  # Set to False to allow JS access (if needed)
    JWT_ACCESS_TOKEN_EXPIRES = ACCESS_EXPIRES
    JWT_COOKIE_SAMESITE = "None" if os.getenv("FLASK_ENV") == "production" else "Lax"
    # If true this will only allow the cookies that contain your JWTs to be sent
    # over https. In production, this should always be set to True
    JWT_COOKIE_SECURE = os.getenv("FLASK_ENV") == "production"  # True in production (HTTPS)

 
    # CORS Configuration
    CORS_ORIGIN = (
        ['http://localhost:8000', 'http://192.168.1.224:8000', 'https://192.168.1.224:8000','https://192.168.1.224:8080', 
         'http://192.168.56.1:8000', 'http://0.0.0.0:8000']  # Allow local development origins
        if os.getenv("FLASK_ENV") != "production"
        else ['https://www.d-tuning.com', 'www.laurindocbenjmim.pt', 'https://laurindocbenjamim.github.io']
    )
    CORS_SUPPORTS_CREDENTIALS = True
    CORS_EXPOSE_HEADERS = ['Content-Type', 'X-CSRF-Token']

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