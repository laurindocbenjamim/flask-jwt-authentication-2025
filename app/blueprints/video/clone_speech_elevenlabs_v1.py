import os
import requests
from flask import Flask, request, current_app as app, jsonify, send_file, render_template
from flask_restful import Api, Resource
from dotenv import load_dotenv
import io
import logging

# Import from ElevenLabs SDK
from elevenlabs.client import ElevenLabs
from elevenlabs import Voice, VoiceSettings # Voice and VoiceSettings might be useful for other operations
# from elevenlabs.api import APIError # For SDK specific errors

load_dotenv()


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ELEVENLABS_API_KEY = os.getenv("ELEVENLABS_API_KEY")
if not ELEVENLABS_API_KEY:
    logger.error("ELEVENLABS_API_KEY not found in .env file")
    raise ValueError("ELEVENLABS_API_KEY not found in .env file")

# Initialize ElevenLabs SDK Client
try:
    elevenlabs_client = ElevenLabs(api_key=ELEVENLABS_API_KEY)
except Exception as e:
    logger.error(f"Failed to initialize ElevenLabs client: {e}")
    # Depending on your app's needs, you might raise an error or handle this gracefully
    # For now, we'll let it proceed, and API calls will fail later.
    elevenlabs_client = None


ELEVENLABS_API_URL = "https://api.elevenlabs.io/v1" # Still needed for requests-based parts

# --- Helper Functions ---
def get_elevenlabs_voices_sdk():
    if not elevenlabs_client:
        raise Exception("ElevenLabs client not initialized.")
    
    voices_response = elevenlabs_client.voices.get_all()
    # The response is an iterable 'Voices' object containing 'Voice' objects
    # Each 'Voice' object has attributes like voice_id, name, category, etc.
    sdk_voices = []
    for voice in voices_response.voices: # Access the list of Voice objects
        sdk_voices.append({
            "voice_id": voice.voice_id,
            "name": voice.name,
            "category": voice.category,
            # You can add more attributes if needed, e.g., voice.labels
        })
    return sdk_voices

# --- API Resources ---
class VoicesResource(Resource):
    def get(self):
        """List all available voices from ElevenLabs account using SDK"""
        try:
            if not elevenlabs_client:
                 return {"message": "ElevenLabs client not available. Check server logs."}, 503

            voices = get_elevenlabs_voices_sdk()
            # Sort cloned voices first, then by name
            formatted_voices = sorted(voices, key=lambda x: (x.get('category', '') != 'cloned', x['name'].lower()))
            return jsonify(formatted_voices)
        except Exception as e:
            logger.error(f"An unexpected error occurred fetching voices via SDK: {str(e)}")
            return {"message": f"An unexpected error occurred: {str(e)}"}, 500

class CloneVoiceResource(Resource):
    def post(self):
        """Clone a new voice by uploading audio files (still using requests for this example)"""
        # This part remains the same as the previous version, using requests
        # because the SDK's `voices.add` method expects file paths or bytes directly,
        # which would require slightly different handling of Flask's FileStorage objects.
        # For simplicity in this focused update, we keep it as is.
        # If you want to adapt this to the SDK, you'd read file_storage.read()
        # and pass the bytes to the SDK method.

        if 'files' not in request.files:
            logger.warning("Clone attempt without files part in request.")
            return {"message": "No files part in the request"}, 400
        
        files_data = request.files.getlist('files')
        voice_name = request.form.get('name')

        if not voice_name:
            logger.warning("Clone attempt without voice name.")
            return {"message": "Voice name is required"}, 400
        if not files_data or len(files_data) == 0 or all(f.filename == '' for f in files_data):
            logger.warning("Clone attempt with no actual files selected.")
            return {"message": "At least one audio file is required for cloning"}, 400
        if len(files_data) > 25:
             logger.warning(f"Clone attempt with too many files: {len(files_data)}")
             return {"message": "Maximum 25 files allowed for cloning"}, 400

        api_files_for_requests = [] # For the 'requests' library format
        valid_files_provided = False
        for file_storage in files_data:
            if file_storage.filename == '':
                continue
            # Basic content type check, ElevenLabs API is more forgiving with actual content
            # if not file_storage.content_type or not file_storage.content_type.startswith('audio/'):
            #      logger.warning(f"Clone attempt with potentially invalid file type: {file_storage.filename} ({file_storage.content_type})")
            
            # For 'requests' library, it needs ('files', (filename, file_bytes, content_type))
            api_files_for_requests.append(('files', (file_storage.filename, file_storage.read(), file_storage.content_type)))
            valid_files_provided = True
        
        if not valid_files_provided:
             logger.warning("Clone attempt but no valid files were processed.")
             return {"message": "No valid audio files provided after filtering."}, 400

        data = {'name': voice_name}
        headers = {
            "Accept": "application/json", # ElevenLabs API expects this
            "xi-api-key": ELEVENLABS_API_KEY # The 'requests' call needs the key in headers
        }

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
                error_details_json = e.response.json().get("detail")
                if isinstance(error_details_json, dict) and "message" in error_details_json:
                    error_details = error_details_json["message"]
                elif isinstance(error_details_json, str):
                    error_details = error_details_json
                elif not error_details_json:
                     error_details = e.response.text
            except:
                error_details = e.response.text 
            logger.error(f"Error cloning voice '{voice_name}' with ElevenLabs (requests): {str(e)}. Details: {error_details}")
            return {"message": f"Error cloning voice: {error_details}"}, e.response.status_code
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during voice cloning for '{voice_name}' (requests): {str(e)}")
            return {"message": f"Network error during voice cloning: {str(e)}"}, 500
        except Exception as e:
            logger.error(f"Unexpected error during cloning for '{voice_name}' (requests): {str(e)}")
            return {"message": f"An unexpected error occurred during cloning: {str(e)}"}, 500
        # No finally block needed to close files as file_storage.read() returns bytes

class TextToSpeechResource(Resource):
    def post(self):
        """Generate audio from text using a specific voice_id (still using requests for streaming)"""
        # This part also remains the same, using requests, especially because handling
        # the audio stream directly from the SDK and then sending it via Flask's send_file
        # requires careful management of the generator returned by the SDK.
        # The `requests` approach is straightforward for this streaming scenario.

        data = request.get_json()
        text = data.get('text')
        voice_id = data.get('voice_id')

        if not text or not voice_id:
            logger.warning("TTS request with missing text or voice_id.")
            return {"message": "Text and voice_id are required"}, 400

        payload = {
            "text": text,
            "model_id": "eleven_multilingual_v2",
            "voice_settings": {
                "stability": 0.70,
                "similarity_boost": 0.75,
            }
        }
        headers = {
            "Accept": "audio/mpeg",
            "Content-Type": "application/json",
            "xi-api-key": ELEVENLABS_API_KEY
        }

        try:
            logger.info(f"Generating TTS for voice_id: {voice_id} with text: \"{text[:30]}...\" using requests.")
            # Using stream=True with requests
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
                error_details_json = e.response.json().get("detail")
                if isinstance(error_details_json, dict) and "message" in error_details_json:
                    error_details = error_details_json["message"]
                elif isinstance(error_details_json, str):
                    error_details = error_details_json
                elif not error_details_json:
                     error_details = e.response.text
            except:
                 error_details = e.response.text
            logger.error(f"ElevenLabs TTS HTTPError for voice {voice_id} (requests): {str(e)}. Details: {error_details}")
            return {"message": f"Error generating speech: {error_details}"}, e.response.status_code
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during TTS for voice {voice_id} (requests): {str(e)}")
            return {"message": f"Network error during TTS: {str(e)}"}, 500
        except Exception as e:
            logger.error(f"Unexpected error during TTS for voice {voice_id} (requests): {str(e)}")
            return {"message": f"An unexpected error occurred during TTS: {str(e)}"}, 500



