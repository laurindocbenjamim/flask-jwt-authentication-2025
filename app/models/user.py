
import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

from datetime import datetime
from app.configs import db
from werkzeug.security import generate_password_hash, check_password_hash



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
    email = db.Column(db.String(128), unique=True, nullable=False)
    username = db.Column(db.String(50), nullable=False, unique=True)
    full_name = db.Column(db.Text, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    confirmed = db.Column(db.Boolean, default=False, nullable=False)
    type_of_user = db.Column(db.String(30), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        """Securely hash and store password"""
        self.password_hash = generate_password_hash(password)

    # NOTE: In a real application make sure to properly hash and salt passwords
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)   
     
    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "password": self.password_hash,
            "full_name": self.full_name,
            "type_of_user": self.type_of_user,
            "confirmed": self.confirmed,
            "created_at": self.created_at
        }
