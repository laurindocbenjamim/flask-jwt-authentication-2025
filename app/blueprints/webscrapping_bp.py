from flask_restful import Api

from flask import Blueprint


web_scrapping_api_bp = Blueprint('web_scrapping', __name__, url_prefix='/api/v1/web-scrapping')
api = Api(web_scrapping_api_bp)

from .webscrapping import CountryApi

api.add_resource(CountryApi, '/countries/<string:country_name>', '/countries')