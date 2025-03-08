
import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

from app.models import User
from app.utils import db

def create_user_object(data: dict):
    """
    Create a new user object.

    Args:
        data (dict): The user data.

    Returns:
        User: The user object.
    """
    if not data:
        return None

    new_user = User(
        email = data.get('email'),
        username = data.get('username'),
        firstname = data.get('firstName'),
        lastname = data.get('lastName'),
        country = data.get('country'),
        country_tel_code = data.get('country_tel_code'),
        phone_number = data.get('phoneNumber'),
        address = data.get('address'),
        address_2 = data.get('address_2'),
        postal_code = data.get('postal_code'),
        confirmed = True,
        type_of_user = 'basic'
    )
    new_user.set_password(data.get('password'))
    return new_user


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