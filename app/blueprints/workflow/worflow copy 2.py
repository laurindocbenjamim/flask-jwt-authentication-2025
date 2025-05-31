from flask import Flask, request, current_app as app, jsonify, send_from_directory
from flask_restful import Resource, Api
import os
import requests
import uuid
import wave # For audio processing (splitting WAV files)
# For more robust audio handling (MP3, etc.), you might need pydub and ffmpeg:
# from pydub import AudioSegment
# from pydub.silence import split_on_silence
import json
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Configuration ---
# You would load these from a config file or environment variables in a real app
UPLOAD_FOLDER = 'uploads' # Local upload directory
DIGITALOCEAN_BUCKET_ENABLED = False # Set to True to use DigitalOcean Spaces
DIGITALOCEAN_SPACES_URL = "https://your-bucket-name.your-region.digitaloceanspaces.com" # e.g., https://my-bucket.nyc3.digitaloceanspaces.com
DIGITALOCEAN_ACCESS_KEY = "your_do_access_key"
DIGITALOCEAN_SECRET_KEY = "your_do_secret_key"
DIGITALOCEAN_BUCKET_NAME = "your-digitalocean-bucket-name" # Ensure this matches your bucket

# AI API Keys (replace with your actual keys)
GOOGLE_AI_API_KEY = "your_google_ai_api_key"
ELEVENLABS_API_KEY = "your_elevenlabs_api_key"
GOOGLE_TTS_API_KEY = "your_google_tts_api_key"
OPENAI_API_KEY = "your_openai_api_key"

# Define max file sizes/lengths for AI APIs (example values, check actual API docs)
MAX_AUDIO_CHUNK_SIZE_BYTES = 10 * 1024 * 1024 # 10 MB for a single chunk (e.g., for ASR)
MAX_TEXT_LENGTH_FOR_TTS = 4000 # characters, typical limit for some TTS APIs


# Helper function for DigitalOcean S3 client (requires boto3)
def get_s3_client():
    if DIGITALOCEAN_BUCKET_ENABLED:
        try:
            import boto3
            session = boto3.session.Session()
            client = session.client(
                's3',
                region_name='your-region', # e.g., 'nyc3', 'fra1'
                endpoint_url=f'https://{session.region_name}.digitaloceanspaces.com',
                aws_access_key_id=DIGITALOCEAN_ACCESS_KEY,
                aws_secret_access_key=DIGITALOCEAN_SECRET_KEY
            )
            return client
        except ImportError:
            logging.error("Boto3 not installed. Cannot use DigitalOcean Spaces.")
            return None
        except Exception as e:
            logging.error(f"Error initializing S3 client: {e}")
            return None
    return None

# --- Custom Exception for API Errors ---
class APIError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

# --- Utility Functions ---
def get_json_or_form_data():
    if request.is_json:
        return request.get_json()
    else:
        return request.form

def generate_unique_filename(filename):
    ext = os.path.splitext(filename)[1]
    return f"{uuid.uuid4()}{ext}"

# --- File Chunking Logic ---
def split_audio_into_chunks(audio_path, max_chunk_size_bytes):
    """
    Splits an audio file (WAV assumed for simplicity with wave module) into chunks.
    For other formats (MP3), pydub and ffmpeg would be required.
    Returns a list of paths to the temporary chunk files.
    """
    chunks = []
    try:
        with wave.open(audio_path, 'rb') as wf:
            frame_rate = wf.getframerate()
            sample_width = wf.getsampwidth()
            n_channels = wf.getnchannels()
            total_frames = wf.getnframes()
            
            bytes_per_frame = sample_width * n_channels
            # Calculate frames per chunk, ensuring at least one frame
            frames_per_chunk = max(1, max_chunk_size_bytes // bytes_per_frame)
            
            for i in range(0, total_frames, frames_per_chunk):
                wf.setpos(i)
                chunk_frames = wf.readframes(min(frames_per_chunk, total_frames - i))
                
                chunk_filename = generate_unique_filename(os.path.basename(audio_path))
                chunk_path = os.path.join(app.config['UPLOAD_FOLDER'], chunk_filename)
                
                with wave.open(chunk_path, 'wb') as chunk_wf:
                    chunk_wf.setnchannels(n_channels)
                    chunk_wf.setsampwidth(sample_width)
                    chunk_wf.setframerate(frame_rate)
                    chunk_wf.writeframes(chunk_frames)
                chunks.append(chunk_path)
        logging.info(f"Split audio file '{audio_path}' into {len(chunks)} chunks.")
        return chunks
    except wave.Error as e:
        logging.error(f"Failed to open/process WAV file '{audio_path}': {e}. Ensure it's a valid WAV.")
        raise APIError(f"Audio file processing error: {e}. Please ensure it's a WAV file or convert it.")
    except Exception as e:
        logging.error(f"Error splitting audio '{audio_path}': {e}")
        raise APIError(f"Error splitting audio file: {e}")

def split_text_into_chunks(text, max_length):
    """
    Splits text into chunks, trying to break at sentence endings for natural flow.
    """
    chunks = []
    if not text:
        return chunks
    
    # Simple split by sentences (can be improved with NLTK for better sentence tokenization)
    sentences = text.split('.')
    current_chunk = ""
    
    for sentence in sentences:
        temp_chunk = (current_chunk + "." + sentence).strip() if current_chunk else sentence.strip()
        if len(temp_chunk) <= max_length:
            current_chunk = temp_chunk
        else:
            if current_chunk: # Add previous chunk if not empty
                chunks.append(current_chunk)
            current_chunk = sentence.strip()
            if len(current_chunk) > max_length: # If a single sentence is too long, split it forcibly
                logging.warning(f"A single sentence exceeded max_length ({max_length}). Forcibly splitting.")
                chunks.extend([current_chunk[i:i+max_length] for i in range(0, len(current_chunk), max_length)])
                current_chunk = "" # Reset after forceful split
    
    if current_chunk: # Add last chunk
        chunks.append(current_chunk)
        
    logging.info(f"Split text into {len(chunks)} chunks.")
    return chunks

# --- API Endpoints ---

class WorkflowTextData(Resource):
    """
    Handles processing of text data using selected AI models.
    Endpoint: /api/v2/workflow/text-data
    """
    def post(self):
        try:
            data = request.get_json() # Frontend sends JSON
            model_type = data.get('modelType')
            action = data.get('action') # e.g., 'generate_text', 'summarize'
            input_text = data.get('inputData') # The text content to process

            if not all([model_type, action, input_text]):
                raise APIError("Missing modelType, action, or inputData.", 400)

            result_data = {}
            if model_type == 'google_ai':
                if action == 'generate_text':
                    logging.info(f"Calling Google AI for text generation with input: {input_text[:100]}...")
                    # Placeholder for Google AI (e.g., Gemini) API call
                    # url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={GOOGLE_AI_API_KEY}"
                    # headers = {"Content-Type": "application/json"}
                    # payload = {"contents": [{"parts": [{"text": input_text}]}]}
                    # response = requests.post(url, headers=headers, json=payload)
                    # response.raise_for_status()
                    # api_response = response.json()
                    # generated_text = api_response.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', 'No response from Google AI.')
                    generated_text = f"Simulated Google AI text generation for: '{input_text[:50]}...'"
                    result_data = {"result": generated_text, "type": "text"}
                else:
                    raise APIError(f"Unsupported action '{action}' for Google AI text processing.", 400)

            elif model_type == 'openai':
                if action == 'generate_text':
                    logging.info(f"Calling OpenAI for text generation with input: {input_text[:100]}...")
                    # Placeholder for OpenAI (e.g., GPT-3.5-turbo) API call
                    # url = "https://api.openai.com/v1/chat/completions"
                    # headers = {"Content-Type": "application/json", "Authorization": f"Bearer {OPENAI_API_KEY}"}
                    # payload = {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": input_text}]}
                    # response = requests.post(url, headers=headers, json=payload)
                    # response.raise_for_status()
                    # api_response = response.json()
                    # generated_text = api_response.get('choices', [{}])[0].get('message', {}).get('content', 'No response from OpenAI.')
                    generated_text = f"Simulated OpenAI text generation for: '{input_text[:50]}...'"
                    result_data = {"result": generated_text, "type": "text"}
                else:
                    raise APIError(f"Unsupported action '{action}' for OpenAI text processing.", 400)
            else:
                raise APIError(f"Unsupported modelType '{model_type}' for text data.", 400)

            # Expected response structure from line 2039
            return jsonify({
                "status": "success",
                "message": f"Text data processed successfully by {model_type}.",
                "data": result_data
            }), 200

        except APIError as e:
            logging.error(f"API Error in WorkflowTextData: {e.message}")
            return jsonify({"status": "error", "message": e.message}), e.status_code
        except requests.exceptions.RequestException as e:
            logging.error(f"External AI API request failed: {e}")
            return jsonify({"status": "error", "message": f"Error interacting with external AI service: {str(e)}"}), 502
        except Exception as e:
            logging.exception("An unexpected error occurred in WorkflowTextData.")
            return jsonify({"status": "error", "message": f"An unexpected server error occurred: {str(e)}"}), 500

class WorkflowMedia(Resource):
    """
    Handles processing of media data (audio, potentially video/images) using selected AI models.
    Endpoint: /api/v2/workflow/media
    """
    def post(self):
        try:
            data = request.get_json() # Frontend sends JSON
            model_type = data.get('modelType')
            action = data.get('action') # e.g., 'transcribe_audio', 'text_to_speech'
            input_data = data.get('inputData') # This could be a URL to media, or text for TTS

            if not all([model_type, action, input_data]):
                raise APIError("Missing modelType, action, or inputData.", 400)

            result_data = {}
            if model_type == 'google_ai':
                if action == 'transcribe_audio':
                    logging.info(f"Calling Google AI for audio transcription. Input: {input_data}")
                    # input_data is expected to be a URL or path to an uploaded audio file
                    audio_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(input_data))
                    
                    if not os.path.exists(audio_path):
                        raise APIError(f"Audio file not found locally: {audio_path}", 404)

                    # Check file size and split if necessary
                    if os.path.getsize(audio_path) > MAX_AUDIO_CHUNK_SIZE_BYTES:
                        logging.info(f"Audio file too large ({os.path.getsize(audio_path)} bytes), splitting into chunks...")
                        chunks = split_audio_into_chunks(audio_path, MAX_AUDIO_CHUNK_SIZE_BYTES)
                    else:
                        chunks = [audio_path]

                    full_transcription = []
                    for i, chunk_path in enumerate(chunks):
                        logging.info(f"Processing audio chunk {i+1}/{len(chunks)}: {chunk_path}")
                        # Placeholder for Google AI Speech-to-Text API call
                        # with open(chunk_path, 'rb') as audio_file:
                        #     audio_content = audio_file.read()
                        # url = f"https://speech.googleapis.com/v1/speech:recognize?key={GOOGLE_AI_API_KEY}"
                        # headers = {"Content-Type": "application/json"}
                        # payload = {"audio": {"content": base64.b64encode(audio_content).decode('utf-8')}, "config": {"encoding": "LINEAR16", "sampleRateHertz": 16000, "languageCode": "en-US"}}
                        # response = requests.post(url, headers=headers, json=payload)
                        # response.raise_for_status()
                        # api_response = response.json()
                        # transcription = " ".join([res.get('alternatives', [{}])[0].get('transcript', '') for res in api_response.get('results', [])])
                        transcription = f"Simulated transcription of chunk {i+1} from {os.path.basename(chunk_path)}."
                        full_transcription.append(transcription)
                        os.remove(chunk_path) # Clean up temporary chunk file

                    result_data = {"result": " ".join(full_transcription), "type": "text"}

                else:
                    raise APIError(f"Unsupported action '{action}' for Google AI media processing.", 400)

            elif model_type == 'elevenlabs':
                if action == 'text_to_speech':
                    logging.info(f"Calling ElevenLabs for TTS. Input text: {input_data[:100]}...")
                    # Input is text for TTS
                    text_chunks = split_text_into_chunks(input_data, MAX_TEXT_LENGTH_FOR_TTS)
                    audio_urls = []
                    for i, chunk_text in enumerate(text_chunks):
                        logging.info(f"Processing ElevenLabs TTS chunk {i+1}/{len(text_chunks)}")
                        # Placeholder for ElevenLabs TTS API call
                        # url = f"https://api.elevenlabs.io/v1/text-to-speech/YOUR_VOICE_ID"
                        # headers = {"xi-api-key": ELEVENLABS_API_KEY, "Content-Type": "application/json"}
                        # payload = {"text": chunk_text, "model_id": "eleven_monolingual_v1", "voice_settings": {"stability": 0.5, "similarity_boost": 0.5}}
                        # response = requests.post(url, headers=headers, json=payload)
                        # response.raise_for_status()
                        # Save the audio content to a file (local or DO Spaces)
                        audio_filename = generate_unique_filename(f"elevenlabs_tts_chunk_{i}.mp3")
                        audio_filepath = os.path.join(app.config['UPLOAD_FOLDER'], audio_filename)
                        # with open(audio_filepath, 'wb') as f:
                        #     f.write(response.content)
                        # For simulation, just create a dummy file
                        with open(audio_filepath, 'w') as f:
                            f.write(f"Dummy audio content for ElevenLabs chunk {i}")

                        file_url = f"/uploads/{audio_filename}"
                        if DIGITALOCEAN_BUCKET_ENABLED:
                            s3_client = get_s3_client()
                            if s3_client:
                                try:
                                    s3_client.upload_file(audio_filepath, DIGITALOCEAN_BUCKET_NAME, audio_filename)
                                    file_url = f"{DIGITALOCEAN_SPACES_URL}/{audio_filename}"
                                    os.remove(audio_filepath) # Clean up local file after DO upload
                                except Exception as e:
                                    logging.error(f"Failed to upload ElevenLabs audio chunk to DigitalOcean: {e}")
                                    # Fallback to local URL if DO upload fails
                        audio_urls.append(file_url)
                    
                    result_data = {"result": audio_urls, "type": "audio_url"}
                else:
                    raise APIError(f"Unsupported action '{action}' for ElevenLabs media processing.", 400)

            elif model_type == 'google_tts':
                if action == 'text_to_speech':
                    logging.info(f"Calling Google TTS. Input text: {input_data[:100]}...")
                    # Input is text for TTS
                    text_chunks = split_text_into_chunks(input_data, MAX_TEXT_LENGTH_FOR_TTS)
                    audio_urls = []
                    for i, chunk_text in enumerate(text_chunks):
                        logging.info(f"Processing Google TTS chunk {i+1}/{len(text_chunks)}")
                        # Placeholder for Google TTS API call
                        # url = f"https://texttospeech.googleapis.com/v1/text:synthesize?key={GOOGLE_TTS_API_KEY}"
                        # headers = {"Content-Type": "application/json"}
                        # payload = {
                        #     "input": {"text": chunk_text},
                        #     "voice": {"languageCode": "en-US", "ssmlGender": "NEUTRAL"},
                        #     "audioConfig": {"audioEncoding": "MP3"}
                        # }
                        # response = requests.post(url, headers=headers, json=payload)
                        # response.raise_for_status()
                        # api_response = response.json()
                        # audio_content = base64.b64decode(api_response['audioContent'])

                        audio_filename = generate_unique_filename(f"google_tts_chunk_{i}.mp3")
                        audio_filepath = os.path.join(app.config['UPLOAD_FOLDER'], audio_filename)
                        # with open(audio_filepath, 'wb') as f:
                        #     f.write(audio_content)
                        # For simulation, just create a dummy file
                        with open(audio_filepath, 'w') as f:
                            f.write(f"Dummy audio content for Google TTS chunk {i}")

                        file_url = f"/uploads/{audio_filename}"
                        if DIGITALOCEAN_BUCKET_ENABLED:
                            s3_client = get_s3_client()
                            if s3_client:
                                try:
                                    s3_client.upload_file(audio_filepath, DIGITALOCEAN_BUCKET_NAME, audio_filename)
                                    file_url = f"{DIGITALOCEAN_SPACES_URL}/{audio_filename}"
                                    os.remove(audio_filepath) # Clean up local file after DO upload
                                except Exception as e:
                                    logging.error(f"Failed to upload Google TTS audio chunk to DigitalOcean: {e}")
                                    # Fallback to local URL if DO upload fails
                        audio_urls.append(file_url)

                    result_data = {"result": audio_urls, "type": "audio_url"}
                else:
                    raise APIError(f"Unsupported action '{action}' for Google TTS media processing.", 400)

            elif model_type == 'openai':
                if action == 'image_generation':
                    logging.info(f"Calling OpenAI DALL-E for image generation. Prompt: {input_data[:100]}...")
                    # Placeholder for OpenAI DALL-E API call
                    # url = "https://api.openai.com/v1/images/generations"
                    # headers = {"Content-Type": "application/json", "Authorization": f"Bearer {OPENAI_API_KEY}"}
                    # payload = {"prompt": input_data, "n": 1, "size": "1024x1024"}
                    # response = requests.post(url, headers=headers, json=payload)
                    # response.raise_for_status()
                    # api_response = response.json()
                    # image_url = api_response.get('data', [{}])[0].get('url', '')
                    image_url = f"/images/dalle_generated_{uuid.uuid4()}.png" # Simulated URL
                    result_data = {"result": image_url, "type": "image_url"}
                else:
                    raise APIError(f"Unsupported action '{action}' for OpenAI media processing.", 400)
            else:
                raise APIError(f"Unsupported modelType '{model_type}' for media data.", 400)

            # Expected response structure from line 2039
            return jsonify({
                "status": "success",
                "message": f"Media data processed successfully by {model_type}.",
                "data": result_data
            }), 200

        except APIError as e:
            logging.error(f"API Error in WorkflowMedia: {e.message}")
            return jsonify({"status": "error", "message": e.message}), e.status_code
        except requests.exceptions.RequestException as e:
            logging.error(f"External AI API request failed: {e}")
            return jsonify({"status": "error", "message": f"Error interacting with external AI service: {str(e)}"}), 502
        except Exception as e:
            logging.exception("An unexpected error occurred in WorkflowMedia.")
            return jsonify({"status": "error", "message": f"An unexpected server error occurred: {str(e)}"}), 500

# Endpoint for general file uploads (e.g., from a file input node, not necessarily for AI processing directly)
class GeneralFileUpload(Resource):
    def post(self):
        if 'file' not in request.files:
            logging.error("No 'file' part in the upload request.")
            raise APIError("No file part in the request.", 400)

        uploaded_file = request.files['file']
        if uploaded_file.filename == '':
            logging.error("No selected file in upload request.")
            raise APIError("No selected file.", 400)

        if uploaded_file:
            unique_filename = generate_unique_filename(uploaded_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            uploaded_file.save(file_path)
            logging.info(f"File saved locally: {file_path}")

            file_url = f"/uploads/{unique_filename}" # Default local URL

            if DIGITALOCEAN_BUCKET_ENABLED:
                s3_client = get_s3_client()
                if s3_client:
                    try:
                        logging.info(f"Attempting to upload {unique_filename} to DigitalOcean Spaces.")
                        s3_client.upload_file(file_path, DIGITALOCEAN_BUCKET_NAME, unique_filename)
                        file_url = f"{DIGITALOCEAN_SPACES_URL}/{unique_filename}"
                        os.remove(file_path) # Remove local file after upload to DO
                        logging.info(f"File uploaded to DigitalOcean: {file_url} and local file removed.")
                    except Exception as e:
                        logging.error(f"Error uploading to DigitalOcean Spaces: {e}. Falling back to local storage.", exc_info=True)
                        # Optionally, you could raise APIError here if DO is mandatory
                else:
                    logging.warning("DigitalOcean S3 client not configured or initialized. Storing locally.")
            
            return jsonify({
                "status": "success",
                "message": "File uploaded successfully",
                "fileName": uploaded_file.filename,
                "fileUrl": file_url,
                "uniqueFileName": unique_filename # Useful for later referencing this specific file
            }), 200
        else:
            raise APIError("File upload failed for unknown reason.", 500)




