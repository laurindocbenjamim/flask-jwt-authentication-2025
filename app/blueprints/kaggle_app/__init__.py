# Amazon datasets
# https://www.kaggle.com/datasets/karkavelrajaj/amazon-sales-dataset

from flask import Blueprint
from flask_restful import Api
from .load_datasets_from_kagglehub import LoadDatasetsFromKaggle


kaggle_bp_api = Blueprint('kaggle_hub_api', __name__, url_prefix='/api/v1/kagglehub')
api = Api(kaggle_bp_api)

api.add_resource(LoadDatasetsFromKaggle, '/get')
