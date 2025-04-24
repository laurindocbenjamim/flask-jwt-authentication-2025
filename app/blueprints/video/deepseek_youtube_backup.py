

from flask import request, current_app
from flask_restful import Resource
from flask import jsonify, send_file
import os
import yt_dlp
import whisper
from werkzeug.utils import secure_filename
from datetime import datetime

# Whisper model (load only when needed to save memory)
whisper_model = None

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
                # Convert to lowercase and replace spaces with underscores
                clean_title = title.lower().replace(' ', '_')
                # Add current date in YYYYMMDD format
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
            
            if extract_audio or format == 'mp3':
                ydl_opts['postprocessors'].append({
                    'key': 'FFmpegExtractAudio',
                    'preferredcodec': 'mp3',
                    'preferredquality': '192',
                })
            
            # Download the video/audio
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=True)
                original_filename = ydl.prepare_filename(info)
                
                # Generate new formatted filename
                original_title = info.get('title', 'video')
                new_filename = format_filename(original_title, 'mp3' if (format == 'mp3' or extract_audio) else 'mp4')
                new_filepath = os.path.join(current_app.config['DOWNLOAD_FOLDER'], new_filename)
                
                # Rename the file
                os.rename(original_filename, new_filepath)
                
                # Get file size
                file_size = os.path.getsize(new_filepath)
                
                # Process speech-to-text if requested
                transcript = None
                if speech_to_text and (format == 'mp3' or extract_audio):
                    global whisper_model
                    if whisper_model is None:
                        whisper_model = whisper.load_model("base")
                    
                    result = whisper_model.transcribe(new_filepath)
                    transcript = result['text']
                    
                    # Save transcript to file
                    transcript_filename = format_filename(original_title + '_transcript', 'txt')
                    transcript_filepath = os.path.join(current_app.config['DOWNLOAD_FOLDER'], transcript_filename)
                    with open(transcript_filepath, 'w') as f:
                        f.write(transcript)
                
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
