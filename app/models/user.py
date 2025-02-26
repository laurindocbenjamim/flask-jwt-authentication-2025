
import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

from datetime import datetime, timezone
from app.utils import db
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
    firstname = db.Column(db.Text, nullable=False)
    lastname = db.Column(db.Text, nullable=False)
    country = db.Column(db.String(100))
    country_tel_code = db.Column(db.String(6))
    phone_number = db.Column(db.String(10))
    address = db.Column(db.Text)
    address_2 = db.Column(db.Text)
    postal_code = db.Column(db.String(8))
    password_hash = db.Column(db.String(128), nullable=False)
    confirmed = db.Column(db.Boolean, default=False, nullable=False)
    type_of_user = db.Column(db.String(30), nullable=True)
    #created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def set_password(self, password):
        """Securely hash and store password"""
        self.password_hash = generate_password_hash(password)

    # NOTE: In a real application make sure to properly hash and salt passwords
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)   
     
    def to_dict(self):
        """Convert user object to dictionary."""
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            #"password_hash": self.password_hash,
            "firstname": self.firstname,
            "lastname": self.lastname,
            "country": self.country,
            "country_tel_code": self.country_tel_code,
            "phone_number": self.phone_number,
            "address": self.address,
            "address_2": self.address_2,
            "postal_code": self.postal_code,
            "confirmed": self.confirmed,
            "type_of_user": self.type_of_user,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
    
    @staticmethod
    def serialize_all(users):
        """Convert a list of user objects to a list of dictionaries."""
        return [user.to_dict() for user in users]
