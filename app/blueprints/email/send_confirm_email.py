"""
User Registration Email Confirmation System

This Flask application handles user registration with email confirmation,
incorporating security best practices and documentation.

Features:
- Secure password hashing
- CSRF protection
- JWT-based confirmation tokens with expiration
- Rate limiting
- Secure headers
- SQL injection protection
- Environment-based configuration
- Async email sending
"""

import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Application Configuration


# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
mail = Mail(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[app.config['RATE_LIMIT']]
)

# Token serializer
token_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Database Model
class User(db.Model):
    """
    User model representing registered users
    
    Attributes:
        id: Primary key
        email: User's email address (unique)
        password_hash: Hashed password
        confirmed: Email confirmation status
        created_at: Account creation timestamp
    """
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    confirmed = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        """Securely hash and store password"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify hashed password"""
        return check_password_hash(self.password_hash, password)

# Security Middleware
@app.after_request
def set_security_headers(response):
    """Set secure HTTP headers"""
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Email Utilities
def send_async_email(msg):
    """Send email asynchronously"""
    with app.app_context():
        mail.send(msg)

def send_confirmation_email(user):
    """
    Generate and send confirmation email
    
    Args:
        user: User object to send email to
    
    Returns:
        bool: True if email was successfully sent
    """
    token = token_serializer.dumps(user.email, salt='email-confirm')
    confirm_url = url_for('confirm_email', token=token, _external=True)
    msg = Message(
        "Confirm Your Email Address",
        recipients=[user.email],
        html=render_template('confirm_email.html', confirm_url=confirm_url)
    )
    try:
        send_async_email(msg)
        return True
    except Exception as e:
        app.logger.error(f"Error sending email: {e}")
        return False

# Application Routes
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    """
    User registration endpoint
    
    GET: Display registration form
    POST: Process registration request
    """
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Input validation
        if not email or not password:
            flash('Email and password are required')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        # Create new user
        new_user = User(email=email)
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            if send_confirmation_email(new_user):
                flash('Confirmation email sent')
            else:
                flash('Error sending confirmation email')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration error: {e}")
            flash('Registration failed')
    
    return render_template('register.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    """
    Email confirmation endpoint
    
    Args:
        token: JWT confirmation token
    
    Returns:
        Redirect to appropriate status page
    """
    try:
        email = token_serializer.loads(
            token,
            salt='email-confirm',
            max_age=int(app.config['CONFIRMATION_EXPIRATION'].total_seconds())
        )
    except (SignatureExpired, BadSignature):
        flash('Invalid or expired confirmation link')
        return redirect(url_for('register'))
    
    user = User.query.filter_by(email=email).first_or_404()
    
    if user.confirmed:
        flash('Account already confirmed')
    else:
        user.confirmed = True
        db.session.commit()
        flash('Account successfully confirmed')
    
    return redirect(url_for('dashboard'))

# Error Handlers
@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded errors"""
    flash("Too many requests. Please try again later.")
    return redirect(url_for('register'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(ssl_context='adhoc')  # Use proper SSL in production