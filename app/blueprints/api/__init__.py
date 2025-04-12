import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

from flask_restful import Api
from flask import Blueprint
from .admin import UserData, Admin
from .user_manage_api import UserManagementApi

admin_api = Blueprint('admin_api', __name__, url_prefix='/api/v1/admin')
api = Api(admin_api)

api.add_resource(UserData, '/user')
api.add_resource(Admin, '/adm_user')
api.add_resource(UserManagementApi, '/manage-user')