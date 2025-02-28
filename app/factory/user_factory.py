
import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

import sqlalchemy
from app.models import User
from app.utils import db

def create_user_object(user_data):
    user = User()  # Create an instance
    
    # Set password correctly before returning the object
    user.set_password(user_data.get("password"))

    return User(
        email=user_data.get("email"),
        username=user_data.get("username"),
        password_hash=user.password_hash,
        firstname=user_data.get("firstName"),
        lastname=user_data.get("lastName"),
        country=user_data.get("country"),
        country_tel_code=user_data.get("country_tel_code"),
        phone_number=user_data.get("phone_number"),
        address=user_data.get("address"),
        address_2=user_data.get("address_2"),
        postal_code=user_data.get("postal_code"),
        type_of_user=user_data.get("type_of_user"),
        confirmed=user_data.get("user_confirmed")
        #created_at=user_data.get("created_at")
        
    )


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
    #except db.IntegrityError as e:
    except sqlalchemy.exc.IntegrityError as e:
        db.session.rollback()
        return False, f"IntegrityError: Maybe this user already exists."
    except sqlalchemy.exc.OperationalError as e:
        db.session.rollback()
        return False, f"OperationalError: {str(e)}"
    except Exception as e:
        db.session.rollback()
        return False, f"Unexpected error: {str(e)}"
    #finally:


def delete_user(user_id: int):
    """
    Delete user and add it to the database.

    Args:
        new_user (User): The user object to be added to the database.

    Returns:
        tuple: A tuple containing a boolean indicating success or failure, and the user object or error message.
    """
    if not user_id:
        return False, "User object is None"
    try:
        
        user = User.query.get(user_id)
        if not user:
            return False, "User not found"
        
        db.session.delete(user)
        db.session.commit()
        return True, user_id
    except sqlalchemy.exc.OperationalError as e:
        db.session.rollback()
        return False, f"OperationalError: {str(e)}"
    except Exception as e:
        db.session.rollback()
        return False, f"Unexpected error: {str(e)}"
    #finally:

        


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