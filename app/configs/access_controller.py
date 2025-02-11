

from functools import wraps

from flask import Flask
from flask import jsonify

from flask_jwt_extended import get_jwt
from flask_jwt_extended import verify_jwt_in_request



# Creating claim content
def create_additional_claims(*, user):
    if not user:
        return False
    return {
        "is_administractor": True if str(user.get('type_of_user')).lower() == 'admin' else False,
        "is_ceo_user": True if str(user.get('type_of_user')).lower() == 'ceo' else False,
    }

# Here is a custom decorator that verifies the JWT is present in the request,
# as well as insuring that the JWT has a claim indicating that this user is
# an administrator
def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims["is_administrator"]:
                return fn(*args, **kwargs)
            else:
                return jsonify(msg="Admins only!"), 403

        return decorator

    return wrapper