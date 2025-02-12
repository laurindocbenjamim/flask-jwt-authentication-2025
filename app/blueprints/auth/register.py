
from flask import jsonify, current_app
from flask_restful import Api, Resource, reqparse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app.configs import limiter
from app.models import User
from app.factory import create_user, confirm_user_email

class UserRegisterApi(Resource):
    @limiter.limit("5 per minute")
    def post(self):
        """
        User registration endpoint
        
        GET: Display registration form
        POST: Process registration request
        """
        parser = reqparse.RequestParser()
        parser.add_argument('username', required=True, help="Username cannot be blank!")
        parser.add_argument('password', required=True, help="Password cannot be blank!")
        data = parser.parse_args()
        email = data.get('username')
        password = data.get('password')
        
        # Input validation
        if not email or not password:
            return jsonify(status_code=404, error='Email and password are required')
        
        if User.query.filter_by(email=email).first():
            return jsonify(status_code=401, error='Email already registered')
        
        # Create new user
        new_user = User(email=email)
        new_user.set_password(password)
        
        status, sms = create_user(new_user=new_user)
        if not status:
            return jsonify(status_code=400, error=sms)
        return jsonify(status_code=200, message="User has been created successfull")

    @limiter.limit("5 per minute")
    def patch(self, token):
        """
        Email confirmation endpoint
        
        Args:
            token: JWT confirmation token
        
        Returns:
            Redirect to appropriate status page
        """
        try:
            token_serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
            email = token_serializer.loads(
                token,
                salt='email-confirm',
                max_age=int(current_app.config['CONFIRMATION_EXPIRATION'].total_seconds())
            )
        except (SignatureExpired, BadSignature):
            return jsonify(status_code=401, error='Invalid or expired confirmation link')
        
        user = User.query.filter_by(email=email).first_or_404()
        
        status, response = confirm_user_email(user=user)
        if not status:
            return jsonify(status_code=401,error=response)
        
        return jsonify(status_code=200, message=response)


