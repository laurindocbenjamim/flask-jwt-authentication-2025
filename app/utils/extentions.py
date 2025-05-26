from flask_sqlalchemy import SQLAlchemy
from flask import current_app
from flask_wtf.csrf import CSRFProtect
from flask_jwt_extended import JWTManager
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_cors import CORS
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
cors = None
csrf = CSRFProtect()
mail = Mail()
#limiter = Limiter(key_func=get_remote_address, default_limits=[current_app.config['RATE_LIMIT']])
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day","50 per minute"])

# Method to load the application extentions
def load_extentions(*, app):
    """
    Initialize and load extensions for the Flask application.

    This function initializes and loads the following extensions for the given Flask application:
    - CSRF protection
    - CORS (Cross-Origin Resource Sharing)
    - Rate Limiting

    Args:
        app (Flask): The Flask application instance to which the extensions will be added.
    """
    csrf.init_app(app)
    mail.init_app(app)
    cors_origin = app.config['CORS_ORIGIN']

    
    cors_p = CORS(
        app,
        supports_credentials=app.config['CORS_SUPPORTS_CREDENTIALS'],
        resources={
            r"/api/*": {
                "origins": cors_origin,
                "expose_headers": app.config['CORS_EXPOSE_HEADERS']  # ['Content-Type', 'X-CSRF-Token']
            }
        }
    )
    #cors_p.init_app(app)
    limiter.init_app(app)     
