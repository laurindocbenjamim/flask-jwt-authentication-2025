from flask_restful import reqparse
import re

# Custom validation functions
def validate_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(pattern, email):
        raise ValueError("Invalid email format!")
    return email

def validate_phone(phone):
    if not phone.isdigit() or len(phone) != 10:
        raise ValueError("Phone number must be exactly 10 digits!")
    return phone

def validate_password(password):
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long!")
    return password

# Create parser function
def get_user_parser():
    parser = reqparse.RequestParser()
    
    parser.add_argument('firstName', type=str, required=True, help="First name cannot be blank!")
    parser.add_argument('lastName', type=str, required=True, help="Last name cannot be blank!")
    parser.add_argument('username', type=str, required=True, help="Username cannot be blank!")
    parser.add_argument('email', type=validate_email, required=True, help="Valid email is required!")
    parser.add_argument('country', type=str, choices=["USA", "Canada", "UK", "Portugal", "Angola"], required=True, help="Invalid country!")
    parser.add_argument('phoneNumber', type=validate_phone, required=True, help="Phone number must be 10 digits!")
    parser.add_argument('password', type=validate_password, required=True, help="Password must be at least 8 characters!")

    return parser
