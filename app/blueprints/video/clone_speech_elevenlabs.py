import os
import requests
from flask import Flask, request, current_app as app, jsonify, send_file, render_template
from flask_restful import Api, Resource
from dotenv import load_dotenv
import io
import logging

from elevenlabs.client import ElevenLabs


load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ELEVENLABS_API_KEY = os.getenv("ELEVENLABS_API_KEY")
if not ELEVENLABS_API_KEY:
    logger.error("ELEVENLABS_API_KEY not found in .env file")
    raise ValueError("ELEVENLABS_API_KEY not found in .env file")

try:
    elevenlabs_client = ElevenLabs(api_key=ELEVENLABS_API_KEY)
except Exception as e:
    logger.error(f"Failed to initialize ElevenLabs client: {e}")
    elevenlabs_client = None

ELEVENLABS_API_URL = "https://api.elevenlabs.io/v1"

# --- Helper Functions (get_elevenlabs_voices_sdk - no change) ---
def get_elevenlabs_voices_sdk():
    if not elevenlabs_client:
        raise Exception("ElevenLabs client not initialized.")
    voices_response = elevenlabs_client.voices.get_all()
    sdk_voices = []
    for voice in voices_response.voices:
        sdk_voices.append({
            "voice_id": voice.voice_id,
            "name": voice.name,
            "category": voice.category,
        })
    return sdk_voices

# --- API Resources ---
class VoicesResource(Resource):
    def get(self):
        try:
            if not elevenlabs_client:
                 return {"message": "ElevenLabs client not available. Check server logs."}, 503
            voices = get_elevenlabs_voices_sdk()
            formatted_voices = sorted(voices, key=lambda x: (x.get('category', '') != 'cloned', x['name'].lower()))
            return jsonify(formatted_voices)
        except Exception as e:
            logger.error(f"ElevenLabs SDK APIError fetching voices: {e.status_code} - {e.message}")
            return {"message": f"Error fetching voices from ElevenLabs (SDK): {e.message}"}, e.status_code or 500
        except Exception as e:
            logger.error(f"An unexpected error occurred fetching voices via SDK: {str(e)}")
            return {"message": f"An unexpected error occurred: {str(e)}"}, 500

class CloneVoiceResource(Resource):
    # No changes needed in CloneVoiceResource for language/accent
    # The user should upload audio samples with the desired accent.
    def post(self):
        if 'files' not in request.files:
            return {"message": "No files part in the request"}, 400
        files_data = request.files.getlist('files')
        voice_name = request.form.get('name')

        if not voice_name: return {"message": "Voice name is required"}, 400
        if not files_data or len(files_data) == 0 or all(f.filename == '' for f in files_data):
            return {"message": "At least one audio file is required for cloning"}, 400
        if len(files_data) > 25: return {"message": "Maximum 25 files allowed"}, 400

        api_files_for_requests = []
        valid_files_provided = False
        for file_storage in files_data:
            if file_storage.filename == '': continue
            api_files_for_requests.append(('files', (file_storage.filename, file_storage.read(), file_storage.content_type)))
            valid_files_provided = True
        
        if not valid_files_provided: return {"message": "No valid audio files provided"}, 400

        data = {'name': voice_name}
        headers = {"Accept": "application/json", "xi-api-key": ELEVENLABS_API_KEY}

        try:
            logger.info(f"Attempting to clone voice: {voice_name} with {len(api_files_for_requests)} file(s) using requests.")
            response = requests.post(f"{ELEVENLABS_API_URL}/voices/add", headers=headers, data=data, files=api_files_for_requests)
            response.raise_for_status()
            cloned_voice_data = response.json()
            logger.info(f"Voice '{voice_name}' cloned successfully. Voice ID: {cloned_voice_data.get('voice_id')}")
            return {"message": "Voice cloned successfully!", "voice_id": cloned_voice_data.get("voice_id"), "name": voice_name}, 201
        except requests.exceptions.HTTPError as e:
            error_details = "Unknown error"
            try:
                error_details_json = e.response.json().get("detail"); error_details = error_details_json["message"] if isinstance(error_details_json, dict) else (error_details_json or e.response.text)
            except: error_details = e.response.text 
            logger.error(f"Error cloning voice '{voice_name}' (requests): {str(e)}. Details: {error_details}")
            return {"message": f"Error cloning voice: {error_details}"}, e.response.status_code
        except Exception as e:
            logger.error(f"Unexpected error during cloning for '{voice_name}' (requests): {str(e)}")
            return {"message": f"An unexpected error occurred during cloning: {str(e)}"}, 500


class TextToSpeechResource(Resource):
    def post(self):
        data = request.get_json()
        text = data.get('text')
        voice_id = data.get('voice_id')
        # language_code = data.get('language', 'pt') # 'pt' for Portuguese. ElevenLabs multilingual models are good at auto-detection.
                                                   # Explicitly setting language isn't a standard param for their TTS.
                                                   # The model `eleven_multilingual_v2` handles language based on text and voice.

        if not text or not voice_id:
            logger.warning("TTS request with missing text or voice_id.")
            return {"message": "Text and voice_id are required"}, 400

        # The model ID determines language capability.
        # `eleven_multilingual_v2` is the key for Portuguese.
        # The accent will come from the voice_id itself.
        payload = {
            "text": text,
            "model_id": "eleven_multilingual_v2", 
            "voice_settings": {
                "speed": 1.00,            # 1.00 is normal speed, adjust as needed
                "stability": 0.50,          # Lower for more expressive, higher for more monotonous
                "similarity_boost": 0.75,   # Higher makes it sound more like the original voice
                # "style": 0.45,            # (0 to 1) Only for eleven_multilingual_v2. Controls "style exaggeration"
                                            # Might subtly influence accent perception but isn't a direct accent control.
                # "use_speaker_boost": True # Only for eleven_multilingual_v2.
            }
        }
        headers = {
            "Accept": "audio/mpeg",
            "Content-Type": "application/json",
            "xi-api-key": ELEVENLABS_API_KEY
        }

        try:
            logger.info(f"Generating TTS for voice_id: {voice_id} with text: \"{text[:30]}...\" using requests.")
            response = requests.post(f"{ELEVENLABS_API_URL}/text-to-speech/{voice_id}", json=payload, headers=headers, stream=True)
            response.raise_for_status()

            audio_io = io.BytesIO()
            for chunk in response.iter_content(chunk_size=4096):
                if chunk:
                    audio_io.write(chunk)
            audio_io.seek(0)
            
            logger.info(f"Successfully generated audio for voice_id: {voice_id} (requests)")
            return send_file(
                audio_io,
                mimetype='audio/mpeg',
                as_attachment=False
            )
        except requests.exceptions.HTTPError as e:
            error_details = "Unknown error"
            try:
                error_details_json = e.response.json().get("detail"); error_details = error_details_json["message"] if isinstance(error_details_json, dict) else (error_details_json or e.response.text)
            except: error_details = e.response.text
            logger.error(f"ElevenLabs TTS HTTPError for voice {voice_id} (requests): {str(e)}. Details: {error_details}")
            return {"message": f"Error generating speech: {error_details}"}, e.response.status_code
        except Exception as e:
            logger.error(f"Unexpected error during TTS for voice {voice_id} (requests): {str(e)}")
            return {"message": f"An unexpected error occurred during TTS: {str(e)}"}, 500


