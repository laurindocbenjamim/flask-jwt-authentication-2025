
import os
import io
import uuid
import warnings
from datetime import datetime
# create the blueprint
from flask import Blueprint, request, current_app, send_from_directory, send_file
from werkzeug.utils import secure_filename
from pydub.effects import normalize
from flask_restful import Api
from .speech_recognition_view import SpeechRecognitionView
from .ai_audio_book_generator_api import AudioBookResource
from .ai_audio_book_generator_api import AudioBookFileResource
from .ai_audio_book_generator_api import ModelsResource

bp_speech_recognition = Blueprint('speech_recognition', __name__, url_prefix='/api/v1/speech_recognition')


ai_audio_book_bp = Blueprint("ai_audio_book",__name__, url_prefix='/api/v1/AI-AUDIO-BOOK')
api = Api(ai_audio_book_bp)


#bp_ai.add_url_rule("/convert-audio-speech-into-text", view_func=SpeechRecognitionView.as_view("speech", "prompts/speech_recognition.html"))
bp_speech_recognition.add_url_rule("/convert-audio-speech-into-text", view_func=SpeechRecognitionView.as_view("speech", "prompts/convert-audio-to-text.html"))



api.add_resource(AudioBookResource, '/audiobooks')
api.add_resource(ModelsResource, '/models')
api.add_resource(AudioBookFileResource, '/audiobooks/<string:filename>')


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

# Add this new endpoint for file uploads
@ai_audio_book_bp.route('/api/upload', methods=['POST'])
def upload_file():
    if 'background' not in request.files:
        return {'error': 'No file uploaded'}, 400
    
    file = request.files['background']
    if file.filename == '':
        return {'error': 'No selected file'}, 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return {'filePath': filepath}, 200
    
    return {'error': 'Invalid file type'}, 400

@ai_audio_book_bp.route('/<path:path>')
def static_files(path):
    return send_from_directory('static', path)
