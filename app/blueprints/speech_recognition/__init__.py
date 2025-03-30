

# create the blueprint
from flask import Blueprint
#from flask_restx import Api
from .speech_recognition_view import SpeechRecognitionView
bp_speech_recognition = Blueprint('speech_recognition', __name__, url_prefix='/speech_recognition')

#bp_ai.add_url_rule("/convert-audio-speech-into-text", view_func=SpeechRecognitionView.as_view("speech", "prompts/speech_recognition.html"))
bp_speech_recognition.add_url_rule("/convert-audio-speech-into-text", view_func=SpeechRecognitionView.as_view("speech", "prompts/convert-audio-to-text.html"))