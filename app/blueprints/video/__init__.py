

# app.py
from flask import Blueprint, render_template, jsonify, send_file
from flask_restful import Api
from flask_cors import CORS

from .deepseek_youtube_download_video_api import YouTubeDownloader
from .deepseek_youtube_download_video_api import DownloadFile
from .deepseek_youtube_download_video_api import CookieUpload
from .read_media_file import ReadVideo, SelectFiles

download_youtube_video_app = Blueprint("download_youtube_video", __name__, url_prefix="/api/v1/video")

api = Api(download_youtube_video_app)


api.add_resource(YouTubeDownloader, '/download')
api.add_resource(DownloadFile, '/download/<string:filename>')
api.add_resource(ReadVideo, '/get/<string:filename>')
api.add_resource(SelectFiles, '/select/files', '/select/files/<string:directory>')

#api.add_resource(AuthCallback, '/callback')
api.add_resource(CookieUpload, '/upload-cookies')

from .clone_speech_elevenlabs import VoicesResource

from .clone_speech_elevenlabs import CloneVoiceResource

from .clone_speech_elevenlabs import TextToSpeechResource

# --- Register API Resources ---
api.add_resource(VoicesResource, '/voices')
api.add_resource(CloneVoiceResource, '/clone-voice')
api.add_resource(TextToSpeechResource, '/tts')



@download_youtube_video_app.route('/clone-voice')
def clone_voice():
    return render_template('clone_speech_elevelab.html')


