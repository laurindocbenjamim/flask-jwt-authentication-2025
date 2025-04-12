

from flask import Blueprint
from flask_restful import Api

cv_bp_api = Blueprint("cv_app", __name__, url_prefix="/api/v1/cv/")
api = Api(cv_bp_api)

from  .cv_customizer_api import CvCustomizerApp

api.add_resource(CvCustomizerApp,'/customizer')