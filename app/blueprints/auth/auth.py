from flask_restful import Api, Resource, reqparse
from app.config import db
from app.models import User

from flask import (
    Blueprint, jsonify,
    make_response,request
)
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    set_access_cookies
)

auth_api = Blueprint('auth_api', __name__)
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
        return jsonify(sms="Successfully received data", username=username), 200

        user = User.query.filter_by(username=username).one_or_none()
        if not user or not user.check_password(password):
            return jsonify({"error": "Wrong username or password", "user": user.to_dict()}), 401
        # Generate a JWT token
       
        access_token = create_access_token(identity=str(user.id))

        response = make_response(jsonify({"status_code": 200,
                                      "username": username
                                      }),200)
        set_access_cookies(response, access_token)
        return response

api.add_resource(Login, '/login')
