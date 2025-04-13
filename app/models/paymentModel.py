


import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

from datetime import datetime, timezone
from app.utils import db
from werkzeug.security import generate_password_hash, check_password_hash



class PaymentModel(db.Model):
    """
        Payment model representing registered payments
        
        Attributes:
            id: Primary key
            username: User's username (unique)
            session_id: Unique session identifier
            amount: Payment amount
            currency: Payment currency
            status: Payment status (active/inactive)
            created_at: Payment creation timestamp
        """   
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    session_id = db.Column(db.String(128), unique=True, nullable=False)
    amount = db.Column(db.Integer(), nullable=False)
    currency = db.Column(db.String(10))
    status = db.Column(db.String(), default='N/A')
    #created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        """Convert payment object to dictionary."""
        return {
            "id": self.id,
            "username": self.username,
            "session_id": self.session_id,
            "amount": self.amount,
            "currency": self.currency,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
    
    @staticmethod
    def serialize_all(payments):
        """Convert a list of payments objects to a list of dictionaries."""
        return [pay.to_dict() for pay in payments]


    @staticmethod
    def create(payment_data: dict):
        """
        Create a new payment record in the database.

        Args:
            payment_data (dict): A dictionary containing payment details.

        Returns:
            PaymentModel: The created PaymentModel instance if successful, None otherwise.
        """
        try:
            payment = PaymentModel(**payment_data)
            db.session.add(payment)
            db.session.commit()
            return payment
        except Exception as e:
            db.session.rollback()
            return None   
        

    def update(self, session_id, status):
        """
        Update the status of a payment record based on the session_id.

        Args:
            session_id (str): The unique session identifier of the payment.
            status (str): The new status to be set.

        Returns:
            bool: True if the update was successful, False otherwise.
        """
        if not session_id or not status:
            return False

        try:
            payment = PaymentModel.query.filter_by(session_id=session_id).first()
            if not payment:
                return False

            payment.status = status
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            return False
        