

from flask import request, current_app, make_response
from flask_restful import Resource
from flask import jsonify, send_file
import os
import yt_dlp
import whisper
from whisper.utils import get_writer
from werkzeug.utils import secure_filename
from datetime import datetime

# Whisper model (load only when needed to save memory)
whisper_model = None


def trasncribe(speech_to_text, extract_audio, new_filepath):
    # Process speech-to-text if requested
        transcript = None
        if speech_to_text and (format == 'mp3' or extract_audio):
            try:
                # CORRECT way to load models in openai-whisper
                model = whisper.load_model("base")
                
                # For better performance:
                result = model.transcribe(
                    new_filepath,
                    fp16=False,  # Disable if you're not using GPU
                    verbose=True  # Shows progress in console
                )
                transcript = result["text"]
                
                # Save transcript
                txt_writer = get_writer("txt", current_app.config['DOWNLOAD_FOLDER'])
                transcripted_file = new_filepath.replace('.mp3', '_transcript.txt')
                txt_writer(result, transcripted_file)
                
                return True, transcripted_file 
            except Exception as e:
                transcript = f"Transcription failed: {str(e)}"
                return False, transcript


class YouTubeDownloader(Resource):
    def post(self):
        data = request.get_json()
        url = data.get('url')
        extract_audio = data.get('extract_audio', False)
        speech_to_text = data.get('speech_to_text', False)
        format = data.get('format', 'mp4')
        user_id = data.get('user_id', 'default')

        if not url:
            return {'error': 'URL is required'}, 400

        try:
            # Generate formatted filename
            def format_filename(title, ext):
                clean_title = title.lower().replace(' ', '_')
                date_str = datetime.now().strftime("%Y%m%d")
                return f"{clean_title}_{date_str}.{ext}"

            # Check for cookies
            cookie_path = os.path.join(current_app.config['COOKIES_FOLDER'], f'{user_id}_cookies.txt')
            cookies_file = cookie_path if os.path.exists(cookie_path) else None

            # Download options
            ydl_opts = {
                'outtmpl': os.path.join(current_app.config['DOWNLOAD_FOLDER'], '%(title)s.%(ext)s'),
                'quiet': True,
                'no_warnings': True,
                'cookiefile': cookies_file,
                'extract_flat': False,
                'format': 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' if format == 'mp4' else 'bestaudio/best',
                'postprocessors': []
            }

            if extract_audio or format == 'mp3':
                ydl_opts['postprocessors'].append({
                    'key': 'FFmpegExtractAudio',
                    'preferredcodec': 'mp3',
                    'preferredquality': '192',
                })

            response_data = {
                'status': 'success',
                'video_file': None,
                'audio_file': None,
                'transcript_file': None,
                'title': None,
                'thumbnail': None,
                'duration': None
            }

            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=True)
                original_filename = ydl.prepare_filename(info)
                original_title = info.get('title', 'video')

                response_data.update({
                    'title': info.get('title'),
                    'thumbnail': info.get('thumbnail'),
                    'duration': info.get('duration')
                })

                # Handle different download cases
                if format == 'mp4' and not extract_audio:
                    new_filename = format_filename(original_title, 'mp4')
                    new_filepath = os.path.join(current_app.config['DOWNLOAD_FOLDER'], new_filename)
                    os.rename(original_filename, new_filepath)
                    response_data['video_file'] = new_filename
                    response_data['size'] = os.path.getsize(new_filepath)
                    response_data['size_mb'] = round(response_data['size'] / (1024 * 1024), 2)
                else:
                    # Handle audio extraction
                    audio_filename = format_filename(original_title, 'mp3')
                    audio_filepath = os.path.join(current_app.config['DOWNLOAD_FOLDER'], audio_filename)
                    
                    if format == 'mp3' or extract_audio:
                        with yt_dlp.YoutubeDL(ydl_opts) as ydl_audio:
                            ydl_audio.extract_info(url, download=True)
                            temp_audio_path = os.path.splitext(ydl_audio.prepare_filename(info))[0] + '.mp3'
                            os.rename(temp_audio_path, audio_filepath)
                        
                        response_data['audio_file'] = audio_filename
                        response_data['audio_size'] = os.path.getsize(audio_filepath)
                        response_data['audio_size_mb'] = round(response_data['audio_size'] / (1024 * 1024), 2)

                        # Handle speech-to-text
                        if speech_to_text:
                            try:
                                model = whisper.load_model("base")
                                result = model.transcribe(audio_filepath)
                                transcript_filename = format_filename(original_title + '_transcript', 'txt')
                                transcript_filepath = os.path.join(current_app.config['DOWNLOAD_FOLDER'], transcript_filename)
                                
                                txt_writer = get_writer("txt", current_app.config['DOWNLOAD_FOLDER'])
                                txt_writer(result, transcript_filepath)
                                
                                response_data['transcript_file'] = transcript_filename
                                response_data['transcript'] = result['text']
                                response_data['transcript_size'] = os.path.getsize(transcript_filepath)
                            except Exception as e:
                                response_data['transcript_error'] = str(e)

                    # Clean up original file if we converted to audio
                    if os.path.exists(original_filename):
                        os.remove(original_filename)

            return jsonify(response_data)

        except Exception as e:
            error_msg = str(e)
            if "Sign in to confirm you're not a bot" in error_msg:
                return jsonify({
                    'error': 'YouTube requires authentication',
                    'auth_required': True,
                    'solution': {
                        'description': 'Please upload your YouTube cookies file',
                        'cookie_upload_url': '/api/upload-cookies',
                        'instructions_url': 'https://github.com/yt-dlp/yt-dlp/wiki/FAQ#how-do-i-pass-cookies-to-yt-dlp'
                    }
                }), 401
            return jsonify({'error': error_msg}), 500

class CookieUpload(Resource):
    def post(self):
        if 'cookies_file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['cookies_file']
        user_id = request.form.get('user_id', 'default')
        
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        try:
            filename = f'{user_id}_cookies.txt'
            filepath = os.path.join(current_app.config['COOKIES_FOLDER'], filename)
            file.save(filepath)
            return jsonify({'status': 'success', 'message': 'Cookies uploaded successfully'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500


class DownloadFile(Resource):
    def get(self, filename):
        try:
            safe_filename = secure_filename(filename)
            file_path = os.path.join(current_app.config['DOWNLOAD_FOLDER'], safe_filename)
            
            if not os.path.exists(file_path):
                return {'error': f'File not found. {file_path}'}, 404
                
            return send_file(file_path, as_attachment=True)
        except Exception as e:
            return {'error': str(e)}, 500
