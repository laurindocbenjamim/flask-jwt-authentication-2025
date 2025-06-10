from flask import Flask, request, current_app as app, jsonify
from flask_restful import Resource, reqparse
import re # For YouTube URL validation
import base64 # For simulating file handling (if blobs were sent)
import os # For file operations (saving simulated files)



root_files_path = 'static'


# --- Helper Functions for Validation and Sanitization ---
def sanitize_text(text):
    """Strips leading/trailing whitespace and basic HTML escaping."""
    if text is None:
        return None
    # Basic HTML escaping (e.g., for display, not for execution)
    # For robust escaping, consider a dedicated library like bleach
    return str(text).strip().replace('<', '&lt;').replace('>', '&gt;')

def validate_youtube_url(url):
    """Validates a YouTube URL."""
    if not url:
        return False
    youtube_regex = re.compile(r"^(https?://)?(www\.)?(youtube\.com|youtu\.be)\/(watch\?v=|embed\/|v\/|)([\w-]{11})(.*)?$")
    return bool(youtube_regex.match(url))

# --- Request Parsers for different Node Types ---

# Base parser for common fields
base_parser = reqparse.RequestParser()
base_parser.add_argument('id', type=str, required=True, help='Node ID is required.')
base_parser.add_argument('type', type=str, required=True, help='Node type is required.')
base_parser.add_argument('title', type=str, required=True, help='Node title is required.')
base_parser.add_argument('settings', type=dict, default={}, help='Node settings.')

# Parser for Media and Audio-Record nodes
media_audio_parser = base_parser.copy()
media_audio_parser.add_argument('file_reference', type=str, help='Local blob URL placeholder or actual file reference.')
media_audio_parser.add_argument('file_type', type=str, help='MIME type of the file.')
media_audio_parser.add_argument('recorded_audio_file_name', type=str, help='File name for recorded audio.')

# Parser for Text, File, and Generic nodes
text_file_generic_parser = base_parser.copy()
text_file_generic_parser.add_argument('description', type=str, help='Node description or content.')
text_file_generic_parser.add_argument('selected_file', type=str, help='Selected file name (for file type).')


# --- API Resources ---

class MediaResource(Resource):
    def post(self):
        try:

            return {'message': f'An error occurred: ', 'data': {request.get_json()}}, 200

            args = media_audio_parser.parse_args()

            node_id = sanitize_text(args['id'])
            node_type = sanitize_text(args['type'])
            title = sanitize_text(args['title'])
            file_reference = sanitize_text(args['file_reference'])
            file_type = sanitize_text(args['file_type'])
            recorded_audio_file_name = sanitize_text(args['recorded_audio_file_name'])
            settings = args['settings'] # Settings is already a dict, no sanitization needed for keys/values unless specific string values are expected


            print(f"Error in MediaResource: {settings}")
            return {'message': f'An error occurred: {str(file_type)}'}, 200
        
            # Validation
            if node_type not in ['media', 'audio-record']:
                return {'message': 'Invalid node type for this endpoint.'}, 400
            
            if node_type == 'media':
                if not file_reference:
                    return {'message': 'File reference is required for media nodes.'}, 400
                if not file_type or not (file_type.startswith('image/') or file_type.startswith('video/') or file_type.startswith('audio/')):
                    return {'message': 'Invalid or missing file type for media node.'}, 400
                
                # Simulate file processing (in a real app, you'd handle actual file uploads)
                # If the frontend sends a base64 encoded file, you'd decode and save it here.
                # For blob_url_placeholder, we just acknowledge.
                print(f"Processing media node {node_id}: {title}, File: {file_reference} ({file_type})")
                # Example: Save a dummy file
                # with open(os.path.join(UPLOAD_FOLDER, f"{node_id}.{file_type.split('/')[-1]}"), "wb") as f:
                #     f.write(b"dummy media content")

            elif node_type == 'audio-record':
                if not recorded_audio_file_name:
                    return {'message': 'Recorded audio file name is required for audio-record nodes.'}, 400
                # Simulate audio processing
                print(f"Processing audio-record node {node_id}: {title}, Recorded file: {recorded_audio_file_name}")
                # with open(os.path.join(UPLOAD_FOLDER, recorded_audio_file_name), "wb") as f:
                #     f.write(b"dummy audio content")

            # Further processing based on settings (e.g., extract audio, run parallel)
            if settings.get('extractAudio'):
                print(f"Extracting audio for node {node_id}...")
            if settings.get('runParallel'):
                print(f"Node {node_id} configured to run in parallel.")

            return {'message': f'{node_type.capitalize()} node processed successfully!', 'node_id': node_id}, 200

        except Exception as e:
            print(f"Error in MediaResource: {e}")
            return {'message': f'An error occurred: {str(e)}'}, 500

class TextDataResource(Resource):
    def post(self):
        try:
            args = text_file_generic_parser.parse_args()
            
            node_id = sanitize_text(args['id'])
            node_type = sanitize_text(args['type'])
            title = sanitize_text(args['title'])
            description = sanitize_text(args['description'])
            selected_file = sanitize_text(args['selected_file'])
            file_type = sanitize_text(args['file_type'])
            settings = args['settings']

            print(f"Error in TextDataResource: {file_type}")
            return {'message': f'An error occurred in TextDataResource: {str(e)}'}, 500

            # Validation
            if node_type not in ['text', 'file', 'textarea', 'generic']:
                return {'message': 'Invalid node type for this endpoint.'}, 400

            if node_type == 'text': # YouTube URL
                if not description:
                    return {'message': 'YouTube URL is required for text nodes.'}, 400
                if not validate_youtube_url(description):
                    return {'message': 'Invalid YouTube URL format.'}, 400
                print(f"Processing YouTube URL node {node_id}: {title}, URL: {description}")
                # In a real app, you'd interact with YouTube API or a video processing library

            elif node_type == 'file':
                if not selected_file:
                    return {'message': 'File name is required for file nodes.'}, 400
                if not file_type:
                    return {'message': 'File type is required for file nodes.'}, 400
                # Simulate file operation (e.g., parse PDF, JSON, CSV, TXT, MD)
                print(f"Processing file node {node_id}: {title}, File: {selected_file} ({file_type})")
                # Example: Read content if file was uploaded
                # with open(os.path.join(UPLOAD_FOLDER, selected_file), "r") as f:
                #     file_content = f.read()

            elif node_type == 'textarea':
                if not description or description.strip() == '':
                    return {'message': 'Text area content cannot be empty.'}, 400
                print(f"Processing textarea node {node_id}: {title}, Content: {description[:50]}...")
                # LLM Integration for summarization
                if request.args.get('action') == 'summarize':
                    # Call Gemini API for summarization
                    # This is a placeholder; actual API call would go here
                    # response_from_gemini = call_gemini_api("summarize", description)
                    # return {'message': 'Text summarized', 'summary': response_from_gemini}, 200
                    print(f"Simulating summarization for node {node_id}")
                    return {'message': 'Text area processed', 'summary': f"Summarized: {description[:30]}..."}, 200

            elif node_type == 'generic':
                if not description or description.strip() == '' or description == 'Description...':
                    return {'message': 'Generic block description cannot be empty.'}, 400
                print(f"Processing generic node {node_id}: {title}, Description: {description}")
                # LLM Integration for description generation
                if request.args.get('action') == 'generate_description':
                    # Call Gemini API for description generation
                    # This is a placeholder; actual API call would go here
                    # response_from_gemini = call_gemini_api("generate_description", title, selected_file, file_type)
                    # return {'message': 'Description generated', 'description': response_from_gemini}, 200
                    print(f"Simulating description generation for node {node_id}")
                    return {'message': 'Generic block processed', 'generated_description': f"Generated desc for {title}"}, 200

            # Further processing based on settings
            if settings.get('runParallel'):
                print(f"Node {node_id} configured to run in parallel.")
            if settings.get('aiModel'):
                print(f"AI Model selected for node {node_id}: {settings['aiModel']}")
            if settings.get('speechLang'):
                print(f"Speech language selected for node {node_id}: {settings['speechLang']}")

            return {'message': f'{node_type.capitalize()} node processed successfully!', 'node_id': node_id}, 200

        except Exception as e:
            print(f"Error in TextDataResource: {e}")
            return {'message': f'An error occurred in TextDataResource: {str(e)}'}, 500

# --- LLM Integration Placeholder (for backend calls) ---
# This function would be called internally by your API resources
# when an LLM action is required (e.g., summarization, description generation).
# It would make the actual fetch call to the Gemini API.
async def call_gemini_api_backend(action_type, *args):
    """
    Simulates a backend call to the Gemini API.
    In a real application, you would implement the actual fetch call here.
    """
    prompt_text = ""
    if action_type == "summarize":
        text_to_summarize = args[0]
        prompt_text = f"Summarize the following text:\n\n\"{text_to_summarize}\""
    elif action_type == "generate_description":
        title = args[0]
        selected_file = args[1]
        file_type = args[2]
        prompt_text = f"Generate a concise description for a workflow automation block titled \"{title}\"."
        if selected_file:
            prompt_text += f" The block is related to a file named \"{selected_file}\" of type \"{file_type}\"."
    
    print(f"Backend: Calling Gemini API for '{action_type}' with prompt: {prompt_text[:100]}...")

    # This part would be the actual fetch call in a real backend
    # Example (using requests for Python, not fetch):
    # import requests
    # url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=YOUR_API_KEY"
    # headers = {'Content-Type': 'application/json'}
    # payload = {'contents': [{'role': 'user', 'parts': [{'text': prompt_text}]}]}
    # response = requests.post(url, headers=headers, json=payload)
    # response.raise_for_status()
    # result = response.json()
    # if result.get('candidates') and result['candidates'][0].get('content') and result['candidates'][0]['content'].get('parts'):
    #     return result['candidates'][0]['content']['parts'][0]['text']
    # return "Simulated LLM response."

    # For this example, we'll return a simulated response
    return f"Simulated LLM response for {action_type} based on: {prompt_text[:50]}..."

