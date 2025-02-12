from flask_restful import Api, Resource, reqparse
from app.configs import db
from app.models import User, TokenBlocklist, TokenBlocklist2

from flask import (
    Blueprint, jsonify,
    make_response,request, current_app
)

from datetime import datetime
from datetime import timedelta
from datetime import timezone
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    current_user,
    get_jwt,
    get_jwt_identity,
    set_access_cookies,
    unset_jwt_cookies
)
from sqlalchemy.sql import func
import secrets
import jwt
from werkzeug.security import check_password_hash


auth_api = Blueprint('auth_api', __name__, url_prefix='/api/v1/auth')
api = Api(auth_api)

class Login(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', required=True, help="Username cannot be blank!")
        parser.add_argument('password', required=True, help="Password cannot be blank!")
        data = parser.parse_args()
        
        # Here you would add your authentication logic
        #if data['username'] == 'admin' and data['password'] == 'password':
        #    access_token = create_access_token(identity={'username': data['username']})
        #    return jsonify(access_token=access_token)
        #return make_response(jsonify(message="Invalid credentials"), 401)
        #response = jsonify({"msg": "login successful"}), 200
        #data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        

        user = User.query.filter_by(username=username).one_or_none()
        if not user or not user.check_password(password):
            return jsonify({"status_code": 401, "error": "Wrong username or password", "user": user.to_dict()})
        # Generate a JWT token

        
        access_token = create_access_token(identity=str(user.id))
        
        response = make_response(jsonify({"status_code": 200,
                                      "username": username
                                      }),200)
        set_access_cookies(response, access_token)
        return response


class Logout(Resource):
    @jwt_required(verify_type=False)
    def get(self):
        
        token = get_jwt()
        jti = token["jti"]
        ttype = token["type"]
        now = datetime.now(timezone.utc)
        block_list=None

        try:
            block_list = TokenBlocklist(jti=jti, type=ttype, created_at=now)
            db.session.add(block_list)
            db.session.commit()
            response = jsonify(msg=f"{ttype.capitalize()} token successfully revoked", logout="Your session has been terminated!", block_list=block_list.to_dict())
        except Exception as e:
            return jsonify(error=str(e))        
        
        #unset_jwt_cookies(response)
        return response


    # Delete
    @jwt_required(verify_type=False)
    def delete(self):
        token = get_jwt()
        jti = token["jti"]
        ttype = token["type"]
        now = datetime.now(timezone.utc)
        block_list=None

        try:
            block_list = TokenBlocklist(jti=jti, type=ttype, created_at=now)
            db.session.add(block_list)
            db.session.commit()
            response = jsonify(msg=f"{ttype.capitalize()} token successfully revoked", logout="Your session has been terminated!", block_list=block_list.to_dict())
        except Exception as e:
            return jsonify(error=str(e))        
        
        #unset_jwt_cookies(response)
        return response

    

 

api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
