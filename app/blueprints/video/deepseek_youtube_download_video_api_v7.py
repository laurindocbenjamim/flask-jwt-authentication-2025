

from flask import request, current_app
from flask_restful import Resource
from flask import jsonify, send_file, make_response
from flask import send_from_directory
from flask_restful import Api, Resource
from flask_cors import CORS
import yt_dlp
import whisper
from whisper.utils import get_writer
from werkzeug.utils import secure_filename
import os
from datetime import datetime


class YouTubeDownloader(Resource):
    def post(self):
        data = request.get_json()
        url = data.get('url')
        if not url:
            return {'error': 'URL is required'}, 400

        try:
            user_id = data.get('user_id', 'default')
            cookie_file = self.get_cookie_path(user_id)
            
            result = self.process_download(url, data, cookie_file)
            
            if 'error' in result:
                if "Sign in to confirm you're not a bot" in result['error']:
                    return {
                        'error': result['error'],
                        'auth_required': True,
                        'solution': {
                            'description': 'YouTube requires cookie authentication',
                            'instructions': [
                                '1. Install "Get cookies.txt" browser extension',
                                '2. Login to YouTube in your browser',
                                '3. Export cookies and upload them here'
                            ],
                            'extension_url': 'https://chrome.google.com/webstore/detail/get-cookiestxt/bgaddhkoddajcdgocldbbfleckgcbcid'
                        }
                    }, 401
                return result, 500
            
            return result, 200

        except Exception as e:
            return {'error': str(e)}, 500

    def process_download(self, url, data, cookie_file):
        ydl_opts = {
            'outtmpl': os.path.join(current_app.config['DOWNLOAD_FOLDER'], '%(title)s.%(ext)s'),
            'quiet': True,
            'no_warnings': True,
            'cookiefile': cookie_file,
            'extract_flat': False
        }

        if data.get('format', 'mp4') == 'mp4':
            ydl_opts['format'] = 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best'
            if data.get('extract_audio', False):
                ydl_opts['postprocessors'] = [{
                    'key': 'FFmpegExtractAudio',
                    'preferredcodec': 'mp3',
                    'preferredquality': '192',
                }]
        else:
            ydl_opts['format'] = 'bestaudio/best'
            ydl_opts['postprocessors'] = [{
                'key': 'FFmpegExtractAudio',
                'preferredcodec': 'mp3',
                'preferredquality': '192',
            }]

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)
            return self.process_files(info, data)

    def get_cookie_path(self, user_id):
        cookie_path = os.path.join(current_app.config['COOKIES_FOLDER'], f'{user_id}_cookies.txt')
        return cookie_path if os.path.exists(cookie_path) else None
    
    

    def get_ydl_opts(self, data, cookies_file):
        format = data.get('format', 'mp4')
        return {
            'outtmpl': os.path.join(current_app.config['DOWNLOAD_FOLDER'], '%(title)s.%(ext)s'),
            'quiet': True,
            'no_warnings': True,
            'cookiefile': cookies_file,
            'extract_flat': False,
            'format': 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best' if format == 'mp4' else 'bestaudio/best',
            'postprocessors': self.get_postprocessors(data)
        }

    def get_postprocessors(self, data):
        if data.get('extract_audio', False) or data.get('format') == 'mp3':
            return [{
                'key': 'FFmpegExtractAudio',
                'preferredcodec': 'mp3',
                'preferredquality': '192',
            }]
        return []

    def process_files(self, info, data):
        original_title = info.get('title', 'video')
        result = {
            'title': info.get('title'),
            'thumbnail': info.get('thumbnail'),
            'duration': info.get('duration'),
            'files': []
        }

        ydl = yt_dlp.YoutubeDL({'outtmpl': os.path.join(current_app.config['DOWNLOAD_FOLDER'], '%(title)s.%(ext)s')})
        original_filename = ydl.prepare_filename(info)

        if data.get('format', 'mp4') == 'mp4' and not data.get('extract_audio', False):
            # Video only download
            new_filename = self.format_filename(original_title, 'mp4')
            new_filepath = os.path.join(current_app.config['DOWNLOAD_FOLDER'], new_filename)
            os.rename(original_filename, new_filepath)
            result['files'].append(self.create_file_info('video', new_filename, new_filepath))
        else:
            
            # Audio download (with optional transcription)
            audio_filename = self.format_filename(original_title, 'mp3')
            audio_filepath = os.path.join(current_app.config['DOWNLOAD_FOLDER'], audio_filename)
            
            # Handle different audio file extensions
            temp_audio = original_filename.replace('.webm', '.mp3').replace('.m4a', '.mp3')
            os.rename(temp_audio, audio_filepath)
            result['files'].append(self.create_file_info('audio', audio_filename, audio_filepath))

            if data.get('speech_to_text', False):
                self.process_transcription(audio_filepath, original_title, result)

            # Clean up original files
            if os.path.exists(original_filename):
                os.remove(original_filename)

        return result

    def process_video(self, original_filename, original_title, response_data):
        new_filename = self.format_filename(original_title, 'mp4')
        new_filepath = os.path.join(current_app.config['DOWNLOAD_FOLDER'], new_filename)
        os.rename(original_filename, new_filepath)
        response_data['files'].append(self.create_file_info('video', new_filename, new_filepath))

    def process_audio(self, original_filename, original_title, data, response_data):
        audio_filename = self.format_filename(original_title, 'mp3')
        audio_filepath = os.path.join(current_app.config['DOWNLOAD_FOLDER'], audio_filename)
        
        with yt_dlp.YoutubeDL(self.get_ydl_opts(data, None)) as ydl_audio:
            ydl_audio.extract_info(data['url'], download=True)
            temp_audio_path = os.path.splitext(ydl_audio.prepare_filename({'title': original_title}))[0] + '.mp3'
            os.rename(temp_audio_path, audio_filepath)
        
        response_data['files'].append(self.create_file_info('audio', audio_filename, audio_filepath))

        if data.get('speech_to_text', False):
            self.process_transcription(audio_filepath, original_title, response_data)

        if os.path.exists(original_filename):
            os.remove(original_filename)

    def process_transcription(self, audio_filepath, original_title, response_data):
        try:
            model = whisper.load_model("base")
            result = model.transcribe(audio_filepath)
            transcript_filename = self.format_filename(original_title + '_transcript', 'txt')
            transcript_filepath = os.path.join(current_app.config['DOWNLOAD_FOLDER'], transcript_filename)
            
            txt_writer = get_writer("txt", current_app.config['DOWNLOAD_FOLDER'])
            txt_writer(result, transcript_filepath)
            
            file_info = self.create_file_info('transcript', transcript_filename, transcript_filepath)
            file_info['text'] = result['text']
            response_data['files'].append(file_info)
        except Exception as e:
            response_data['transcription_error'] = str(e)

    def format_filename(self, title, ext):
        clean_title = title.lower().replace(' ', '_')
        clean_title = clean_title.replace('.', '-')
        date_str = datetime.now().strftime("%Y%m%d")
        return f"{clean_title}_{date_str}.{ext}"

    def create_file_info(self, file_type, filename, filepath):
        size = os.path.getsize(filepath)
        return {
            'type': file_type,
            'filename': filename,
            'size': size,
            'size_mb': round(size / (1024 * 1024), 2)
        }

class CookieUpload(Resource):
    def post(self):
        if 'cookies_file' not in request.files:
            return {'error': 'No file uploaded'}, 400
        
        file = request.files['cookies_file']
        user_id = request.form.get('user_id', 'default')
        
        if file.filename == '':
            return {'error': 'No selected file'}, 400
        
        try:
            filename = f'{user_id}_cookies.txt'
            filepath = os.path.join(current_app.config['COOKIES_FOLDER'], filename)
            file.save(filepath)
            return {'status': 'success'}, 200
        except Exception as e:
            return {'error': str(e)}, 500

class FileDownload(Resource):
    def get(self, filename):
        try:
            return send_from_directory(
                current_app.config['DOWNLOAD_FOLDER'],
                filename,
                as_attachment=True
            )
        except FileNotFoundError:
            return {'error': 'File not found'}, 404



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
