
import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

from app.models import User
from app.configs import db


def create_user(new_user: User):
    """
    Create a new user and add it to the database.

    Args:
        new_user (User): The user object to be added to the database.

    Returns:
        tuple: A tuple containing a boolean indicating success or failure, and the user object or error message.
    """
    if not new_user:
        return False, "User object is None"
    try:
        db.session.add(new_user)
        db.session.commit()
        return True, new_user
    except db.IntegrityError as e:
        db.session.rollback()
        return False, f"IntegrityError: {str(e)}"
    except db.OperationalError as e:
        db.session.rollback()
        return False, f"OperationalError: {str(e)}"
    except Exception as e:
        db.session.rollback()
        return False, f"Unexpected error: {str(e)}"


def confirm_user_email(user: User):
    """
    Confirm the user's email.

    Args:
        user (User): The user object whose email is to be confirmed.

    Returns:
        tuple: A tuple containing a boolean indicating success or failure, and a message.
    """
    if not user:
        return False, "User object is None"

    if user.confirmed:
        return True, "Account already confirmed"
    
    try:
        user.confirmed = True
        db.session.commit()
        return True, "Account successfully confirmed. "
    except db.OperationalError as e:
        db.session.rollback()
        return False, f"OperationalError: {str(e)}"
    except Exception as e:
        db.session.rollback()
        return False, f"Unexpected error: {str(e)}"