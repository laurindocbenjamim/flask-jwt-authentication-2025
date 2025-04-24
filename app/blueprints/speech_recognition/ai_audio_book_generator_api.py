import os
import io
import uuid
import warnings
from datetime import datetime
from flask import Blueprint, request, jsonify, send_from_directory
from flask_restful import Api, Resource
from werkzeug.utils import secure_filename
import openai
from elevenlabs.client import ElevenLabs
from google.cloud import texttospeech
from pydub import AudioSegment
from pydub.effects import normalize
from config import Config
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Suppress pydub warnings
warnings.filterwarnings("ignore", message="Couldn't find ffmpeg or avconv")

app = Blueprint("ai_audio_book",__name__, url_prefix="")

api = Api(app)

# Initialize AI clients
openai.api_key = os.environ['OPEN_AI_API_KEY']

# Initialize ElevenLabs client
elevenlabs_client = None
if app.config['ELEVENLABS_API_KEY']:
    try:
        elevenlabs_client = ElevenLabs(
            api_key=app.config['ELEVENLABS_API_KEY'],
            timeout=30
        )
        logger.info("ElevenLabs client initialized successfully")
    except Exception as e:
        logger.error(f"ElevenLabs init error: {str(e)}")

# Initialize Google TTS client
google_client = None
if app.config['GOOGLE_APPLICATION_CREDENTIALS']:
    try:
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = app.config['GOOGLE_APPLICATION_CREDENTIALS']
        google_client = texttospeech.TextToSpeechClient()
        logger.info("Google TTS client initialized successfully")
    except Exception as e:
        logger.error(f"Google TTS init error: {str(e)}")

# Available Models and Voices
MODELS = {
    'openai': {
        'name': 'OpenAI TTS',
        'voices': {
            'alloy': {'languages': ['en', 'pt']},
            'echo': {'languages': ['en']},
            'fable': {'languages': ['en']},
            'onyx': {'languages': ['en']},
            'nova': {'languages': ['en', 'pt']},
            'shimmer': {'languages': ['en', 'pt']}
        },
        'vibes': {
            'sincere': 'be sincere',
            'chill surfer': 'be chill surfer',
            'gourmet chef': 'be like gourmet chef',
            'robot': 'be like robot',
            'dramatic': 'be dramatic'
        },
        'language_mapping': {
            'pt': {
                'pt-PT': 'Portuguese (Portugal)',
                'pt-BR': 'Portuguese (Brazil)'
            }
        }
    },

    'openai-gpt-4o': {
        'name': 'OpenAI TTS',
        'voices': {
            'alloy': {'languages': ['en', 'pt']},
            'ash': {'languages': ['en', 'pt']},
            'ballad': {'languages': ['en', 'pt']},
            'coral': {'languages': ['en', 'pt']},
            'echo': {'languages': ['en']},
            'fable': {'languages': ['en']},
            'onyx': {'languages': ['en']},
            'nova': {'languages': ['en', 'pt']},
            'sage': {'languages': ['en', 'pt']},
            'shimmer': {'languages': ['en', 'pt']},
            'verse': {'languages': ['en']},
        },
        'vibes': {
            'sincere': 'be sincere',
            'chill surfer': 'be chill surfer',
            'gourmet chef': 'be like gourmet chef',
            'robot': 'be like robot',
            'dramatic': 'be dramatic'
        },
        'language_mapping': {
            'pt': {
                'pt-PT': 'Portuguese (Portugal)',
                'pt-BR': 'Portuguese (Brazil)'
            }
        }
    }
}

if elevenlabs_client:
    MODELS['elevenlabs'] = {
        'name': 'ElevenLabs',
        'voices': {
            'Rachel': {'languages': ['en']},
            'Domi': {'languages': ['en']},
            'Bella': {'languages': ['en']},
            'Antoni': {'languages': ['en']},
            'Elli': {'languages': ['en']},
            'Josh': {'languages': ['en']},
            'Arnold': {'languages': ['en']},
            'Adam': {'languages': ['en']},
            'Sam': {'languages': ['en']},
            'Lia': {'languages': ['pt']},
            'Dani': {'languages': ['pt']}
        },
        'language_mapping': {
            'pt': {
                'pt-PT': 'Portuguese (Portugal)',
                'pt-BR': 'Portuguese (Brazil)'
            }
        }
    }

if google_client:
    MODELS['google'] = {
        'name': 'Google TTS',
        'voices': {
            'pt-PT-Standard-A': {'languages': ['pt-PT'], 'gender': 'FEMALE'},
            'pt-PT-Wavenet-A': {'languages': ['pt-PT'], 'gender': 'FEMALE'},
            'pt-BR-Standard-A': {'languages': ['pt-BR'], 'gender': 'FEMALE'},
            'pt-BR-Wavenet-A': {'languages': ['pt-BR'], 'gender': 'FEMALE'},
            'en-US-Standard-B': {'languages': ['en'], 'gender': 'MALE'},
            'en-US-Wavenet-D': {'languages': ['en'], 'gender': 'MALE'}
        },
        'language_mapping': {
            'pt': {
                'pt-PT': 'Portuguese (Portugal)',
                'pt-BR': 'Portuguese (Brazil)'
            }
        }
    }

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_tts_openai(text, voice, language='en', speed=1.0):
    try:
        response = openai.audio.speech.create(
            model="tts-1",
            voice=voice,
            input=text,
            speed=speed
        )
        return io.BytesIO(response.content)
    except Exception as e:
        logger.error(f"OpenAI error: {str(e)}")
        raise ValueError(f"OpenAI TTS failed: {str(e)}")

def generate_tts_elevenlabs(text, voice, language='en'):
    if not elevenlabs_client:
        raise ValueError("ElevenLabs not configured")
    
    try:
        if language.startswith('pt'):
            language = 'pt'
            
        audio = elevenlabs_client.generate(
            text=text,
            voice=voice,
            model_id="eleven_monolingual_v1",
            voice_settings={
                "stability": 0.7,
                "similarity_boost": 0.8
            }
        )
        return io.BytesIO(b''.join(audio))
    except Exception as e:
        logger.error(f"ElevenLabs error: {str(e)}")
        raise ValueError(f"ElevenLabs TTS failed: {str(e)}")

def generate_tts_google(text, voice, language='en-US'):
    if not google_client:
        raise ValueError("Google TTS not configured")
    
    try:
        synthesis_input = texttospeech.SynthesisInput(text=text)
        voice_params = texttospeech.VoiceSelectionParams(
            language_code=language,
            name=voice
        )
        audio_config = texttospeech.AudioConfig(
            audio_encoding=texttospeech.AudioEncoding.MP3
        )
        response = google_client.synthesize_speech(
            input=synthesis_input,
            voice=voice_params,
            audio_config=audio_config
        )
        return io.BytesIO(response.audio_content)
    except Exception as e:
        logger.error(f"Google error: {str(e)}")
        raise ValueError(f"Google TTS failed: {str(e)}")

"""def mix_audio(foreground_bytes, background_path=None, background_volume=-20):
    #Mix speech audio with background music with improved handling
    try:
        # Load speech audio
        speech = AudioSegment.from_file(foreground_bytes)
        speech = normalize(speech)
        
        # If background music is provided
        if background_path and os.path.exists(background_path):
            try:
                # Load background music
                background = AudioSegment.from_file(background_path)
                
                # Ensure background is long enough by looping
                while len(background) < len(speech):
                    background += background
                
                # Trim to speech length
                background = background[:len(speech)]
                
                # Adjust volume (negative values make it quieter)
                background = background + background_volume
                
                # Mix both audio tracks with crossfade
                mixed = speech.overlay(background, position=0)
                
                logger.info(f"Successfully mixed audio - Speech: {len(speech)}ms, Background: {len(background)}ms")
            except Exception as e:
                logger.error(f"Background processing error: {str(e)}")
                # Fallback to just speech if background processing fails
                mixed = speech
        else:
            mixed = speech
        
        # Export to bytes with higher quality
        output = io.BytesIO()
        mixed.export(output, format="mp3", bitrate="192k")
        output.seek(0)
        return output
        
    except Exception as e:
        logger.error(f"Audio mixing error: {str(e)}")
        raise ValueError(f"Audio mixing failed: {str(e)}")"""

def mix_audio(foreground_bytes, background_path=None, background_volume=-20):
    """Mix speech audio with background music and add 10s intro/outro of background music"""
    try:
        # Load and normalize speech
        speech = AudioSegment.from_file(foreground_bytes)
        speech = normalize(speech)

        # If background music is provided
        if background_path and os.path.exists(background_path):
            try:
                background = AudioSegment.from_file(background_path)
                background = normalize(background)

                # Adjust background volume
                background = background + background_volume

                # Create 15 seconds intro and outro
                ten_sec = 15 * 1000  # in milliseconds

                # Ensure background is long enough
                required_length = len(speech) + 2 * ten_sec
                while len(background) < required_length:
                    background += background

                # Extract required segments
                intro = background[:ten_sec]
                outro = background[ten_sec:2*ten_sec]
                main_bg = background[2*ten_sec:2*ten_sec+len(speech)]

                # Overlay speech on main background
                mixed_main = main_bg.overlay(speech, position=0)

                # Concatenate intro + mixed speech + outro
                mixed = intro + mixed_main + outro

                logger.info(f"Mixed audio with intro/outro: total duration {len(mixed)}ms")

            except Exception as e:
                logger.error(f"Background processing error: {str(e)}")
                mixed = speech
        else:
            mixed = speech

        # Export to bytes
        output = io.BytesIO()
        mixed.export(output, format="mp3", bitrate="192k")
        output.seek(0)
        return output

    except Exception as e:
        logger.error(f"Audio mixing error: {str(e)}")
        raise ValueError(f"Audio mixing failed: {str(e)}")

# ... (previous imports remain the same)

class AudioBookResource(Resource):
    def post(self):
        try:
            # Check if request is form-data or json
            if request.is_json:
                data = request.get_json()
                text = data.get('textInput')
                voice = data.get('voice')
                model = data.get('modelSelect')
                use_default_background = data.get('use_default_background', False)
                background_file = None
            else:
                data = request.form
                text = data.get('textInput')
                voice = data.get('voice')
                model = data.get('modelSelect')
                use_default_background = data.get('use_default_background') == 'true'
                background_file = request.files.get('background')

            if not all([text, voice, model]):
                logger.error(f"Missing required fields - Text: {text}, Voice: {voice}, Model: {model}")
                return {'error': 'Text, voice and model are required'}, 400

            language = data.get('languageSelect', 'en')
            dialect = data.get('dialect', '')
            background_volume = float(data.get('background_volume', -20))

            logger.info(f"Processing request - Model: {model}, Voice: {voice}")

            # Generate TTS audio
            if model == 'openai':
                audio = generate_tts_openai(text, voice, language)
            elif model == 'elevenlabs':
                audio = generate_tts_elevenlabs(text, voice, dialect or language)
            elif model == 'google':
                audio = generate_tts_google(text, voice, dialect or language)
            else:
                return {'error': 'Invalid model'}, 400

            # Handle background music
            background_path = None
            if use_default_background:
                background_path = os.path.join('static', 'audio', 'default-bg.mp3')
            elif background_file and allowed_file(background_file.filename):
                filename = secure_filename(background_file.filename)
                background_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                background_file.save(background_path)

            # Mix audio
            mixed = mix_audio(audio, background_path, background_volume)

            # Save result
            audiobook_id = uuid.uuid4().hex
            filename = f"audiobook_{audiobook_id}.mp3"
            path = os.path.join(app.config['AUDIOBOOKS_FOLDER'], filename)

            with open(path, 'wb') as f:
                f.write(mixed.read())

            return {
                'id': audiobook_id,
                'filename': filename,
                'url': f'/audiobooks/{filename}',
                'timestamp': datetime.utcnow().isoformat()
            }, 201

        except ValueError as e:
            logger.error(f"Validation error: {str(e)}")
            return {'error': str(e)}, 400
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {'error': 'Internal server error'}, 500

# ... (rest of the backend remains the same)

class ModelsResource(Resource):
    def get(self):
        return jsonify(MODELS)

class AudioBookFileResource(Resource):
    def get(self, filename):
        return send_from_directory(app.config['AUDIOBOOKS_FOLDER'], filename)

api.add_resource(AudioBookResource, '/api/audiobooks')
api.add_resource(ModelsResource, '/api/models')
api.add_resource(AudioBookFileResource, '/audiobooks/<string:filename>')

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


# Add this new endpoint for file uploads
@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'background' not in request.files:
        return {'error': 'No file uploaded'}, 400
    
    file = request.files['background']
    if file.filename == '':
        return {'error': 'No selected file'}, 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return {'filePath': filepath}, 200
    
    return {'error': 'Invalid file type'}, 400

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('static', path)

