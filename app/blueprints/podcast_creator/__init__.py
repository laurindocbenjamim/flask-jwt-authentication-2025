

from flask import Blueprint
from flask_restful import Api
from .podcast_creator__ import PodcastGenerate
from .podcast_creator import DownloadFile

podtcast_bp = Blueprint('podcast_creator', __name__, url_prefix='/api/v2/podcast')
api = Api(podtcast_bp)

api.add_resource(PodcastGenerate, '/generate')
api.add_resource(DownloadFile, '/download/<string:filename>')
