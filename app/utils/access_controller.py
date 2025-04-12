

from functools import wraps

from flask import Flask
from flask import jsonify

from flask_jwt_extended import get_jwt
from flask_jwt_extended import verify_jwt_in_request



# Creating claim content
def create_additional_claims(*, user):
    if not user:
        return False

    try:
        return {
            "type_of_user": user.type_of_user if hasattr(user, 'type_of_user') else None,
            "is_administrator": True if str(user.type_of_user).lower() == 'admin' else False,
            "is_ceo_user": True if str(user.type_of_user).lower() == 'ceo' else False,
        }
    except Exception as e:
        return False

# Here is a custom decorator that verifies the JWT is present in the request,
# as well as insuring that the JWT has a claim indicating that this user is
# an administrator
def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            try:
                if 'is_administrator' in claims and claims["is_administrator"]:
                    return fn(*args, **kwargs)
                else:
                    return jsonify(msg="Admins only!", status_code=403)
            except Exception as e:
                print(f"Error to create the admin decorator. {str(e)}")

        return decorator

    return wrapper


def ceo_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            try:
                if 'is_ceo_user' in claims and claims["is_ceo_user"]:
                    return fn(*args, **kwargs)
                else:
                    return jsonify(msg="CEO only!", status_code=403)
            except Exception as e:
                print(f"Error to create the CEO decorator. {str(e)}")

        return decorator

    return wrapper