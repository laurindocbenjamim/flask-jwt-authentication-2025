

from flask import request, current_app
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
        
        if not url:
            return {'error': 'URL is required'}, 400
        
        try:
            # Generate formatted filename
            def format_filename(title, ext):
                clean_title = title.lower().replace(' ', '_')
                date_str = datetime.now().strftime("%Y%m%d")
                return f"{clean_title}_{date_str}.{ext}"
            
            # Download options
            ydl_opts = {
                'outtmpl': os.path.join(current_app.config['DOWNLOAD_FOLDER'], '%(title)s.%(ext)s'),
                'quiet': True,
                'no_warnings': True,
                'format': 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' if format == 'mp4' else 'bestaudio/best',
                'postprocessors': []
            }
            
            # Initialize variables
            new_filename = None
            transcript = None
            transcripted_file = None
            
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=True)
                original_filename = ydl.prepare_filename(info)
                original_title = info.get('title', 'video')
                
                # Handle MP3 conversion if requested
                if extract_audio or format == 'mp3':
                    # FFmpeg will create the MP3 file with the correct extension
                    ydl_opts['postprocessors'].append({
                        'key': 'FFmpegExtractAudio',
                        'preferredcodec': 'mp3',
                        'preferredquality': '192',
                    })
                    
                    # Process with yt-dlp again to do the conversion
                    with yt_dlp.YoutubeDL(ydl_opts) as ydl_audio:
                        ydl_audio.extract_info(url, download=True)
                    
                    # The MP3 file will have the same name but with .mp3 extension
                    new_filename = format_filename(original_title, 'mp3')
                    new_filepath = os.path.join(current_app.config['DOWNLOAD_FOLDER'], new_filename)
                    original_mp3_path = os.path.splitext(original_filename)[0] + '.mp3'
                    
                    # Rename the converted file
                    if os.path.exists(original_mp3_path):
                        os.rename(original_mp3_path, new_filepath)
                    else:
                        raise FileNotFoundError(f"Converted audio file not found at {original_mp3_path}")
                    
                    # Remove the original video file if we're extracting audio
                    if os.path.exists(original_filename):
                        os.remove(original_filename)
                    
                    # Process speech-to-text if requested
                    if speech_to_text:
                        global whisper_model
                        #status, transcript = trasncribe(speech_to_text, extract_audio, new_filepath)
                            
                
                else:  # Regular video download
                    new_filename = format_filename(original_title, 'mp4')
                    new_filepath = os.path.join(current_app.config['DOWNLOAD_FOLDER'], new_filename)
                    os.rename(original_filename, new_filepath)
                
                # Get file size
                file_size = os.path.getsize(new_filepath) if new_filename else 0
                
            return {
                'status': 'success',
                'filename': new_filename,
                'original_filename': os.path.basename(original_filename),
                'title': info.get('title', ''),
                'thumbnail': info.get('thumbnail', ''),
                'duration': info.get('duration', 0),
                'size': file_size,
                'size_mb': round(file_size / (1024 * 1024), 2),
                'transcript': transcript if speech_to_text else None
            }
        
        except Exception as e:
            return {'error': str(e)}, 500
        
class CookieUpload(Resource):
    def post(self):
        if 'cookies_file' not in request.files:
            return {'error': 'No file uploaded'}, 400
        
        file = request.files['cookies_file']
        user_id = request.form.get('user_id', 'default')
        
        if file.filename == '':
            return {'error': 'No selected file'}, 400
        
        if file:
            filename = secure_filename(f'{user_id}_cookies.txt')
            filepath = os.path.join(current_app.config['COOKIES_FOLDER'], filename)
            file.save(filepath)
            return {'status': 'success', 'message': 'Cookies uploaded successfully'}



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
