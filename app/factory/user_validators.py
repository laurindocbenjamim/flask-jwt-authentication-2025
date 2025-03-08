from flask_restful import reqparse
import re
from flask import current_app

def sanitize_name(name):
    """Remove extra spaces and allow alphabetic characters and digits."""
    name = name.strip()
    if not re.match(r"^[A-Za-zÀ-ÖØ-öø-ÿ0-9\s.'-+]+$", name):  # Allows letters, digits, spaces, periods, hyphens, and apostrophes
        raise ValueError("Name contains invalid characters!")
    return name.title()  # Capitalizes first letter of each word

def sanitize_username(username):
    """Ensure username contains only alphanumeric characters and underscores."""
    username = username.strip()
    if not re.match(r"^\w+$", username):  # Allows letters, numbers, and underscores
        raise ValueError("Username can only contain letters, numbers, and underscores!")
    return username.lower()  # Convert to lowercase

def sanitize_email(email):
    """Trim spaces, convert to lowercase, and validate email format."""
    email = email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email):  
        raise ValueError("Invalid email format!")
    return email

def sanitize_country(country):
    """Allow only letters and spaces in country name."""
    country = country.strip()
    if not re.match(r"^[A-Za-zÀ-ÖØ-öø-ÿ\s-+]+$", country):  # Supports accented letters
        raise ValueError("Invalid country name!")
    return country.title()

def sanitize_phone(phone):
    """Remove spaces and ensure only numbers are present."""
    phone = re.sub(r"\D", "", phone)  # Remove non-digit characters
    if not re.match(r"^\d+$", phone):  
        raise ValueError("Phone number should contain only digits!")
    return phone

# Password validation is already strong


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
    """
    Validate password to be strong:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character
    """
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long!")
    
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter (A-Z)!")
    
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter (a-z)!")
    
    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit (0-9)!")
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise ValueError("Password must contain at least one special character (!@#$%^&* etc.)!")
    
    return password



# Create parser function
def get_user_parser():
    parser = reqparse.RequestParser()
    
    #parser.add_argument('email', type=validate_email, required=True, help="Valid email is required!")

    ALLOWED_COUNTRIES = current_app.config.get('ALLOWED_COUNTRIES', [])
    
    parser.add_argument('firstName', required=True, type=sanitize_name, help="First name cannot be blank!")
    parser.add_argument('lastName', required=True, type=sanitize_name, help="Last name cannot be blank!")
    parser.add_argument('username', required=True, type=sanitize_username, help="Username cannot be blank!")
    parser.add_argument('email', required=True, type=sanitize_email, help="Enter a valid email!")
    parser.add_argument('country', required=True, type=sanitize_name, choices=ALLOWED_COUNTRIES, help=f"Country cannot be blank!")
    parser.add_argument('country_tel_code', required=True, type=sanitize_name, help="Country's phone code cannot be blank!")
    parser.add_argument('phoneNumber', required=True, type=sanitize_phone, help="Phone number cannot be blank!")
    parser.add_argument('password', required=True, type=validate_password, help="Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
    return parser
