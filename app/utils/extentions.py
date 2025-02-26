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
limiter = Limiter(key_func=get_remote_address, default_limits=["100 per day","10 per minute"])

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

    cors_p = CORS(supports_credentials=True,  resources={r"/*": {"origins": cors_origin},
                    r"/api/*": {"origins": cors_origin},                   
                    r"/protected": {"origins": cors_origin},
                    r"/logout-with-revoking-token": {"origins": cors_origin},
    })
    cors_p.init_app(app)
    limiter.init_app(app)     
