

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



from flask import request, current_app
from flask_restful import Resource
from flask import jsonify
import yt_dlp
import whisper
from whisper.utils import get_writer
from datetime import datetime
import os
import tempfile
import boto3
from botocore.exceptions import ClientError
import logging

class YouTubeDownloader(Resource):
    def __init__(self):
        # Initialize Digital Ocean Spaces client
        self.s3_client = boto3.client(
            's3',
            region_name=current_app.config['DO_SPACES_REGION'],
            endpoint_url=f"https://{current_app.config['DO_SPACES_REGION']}.digitaloceanspaces.com",
            aws_access_key_id=current_app.config['DO_SPACES_KEY'],
            aws_secret_access_key=current_app.config['DO_SPACES_SECRET']
        )
        self.bucket_name = current_app.config['DO_SPACES_BUCKET']

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
            logging.error(f"Error processing download: {str(e)}")
            return {'error': str(e)}, 500

    def process_download(self, url, data, cookie_file):
        # Create a temporary directory for processing
        with tempfile.TemporaryDirectory() as temp_dir:
            ydl_opts = {
                'outtmpl': os.path.join(temp_dir, '%(title)s.%(ext)s'),
                'quiet': True,
                'no_warnings': True,
                'cookiefile': cookie_file,
                'extract_flat': False,
                'format': 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best',
                'overwrites': True
            }

            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=True)
                return self.process_files(info, data, temp_dir)

    def get_cookie_path(self, user_id):
        # Check if cookie exists in Digital Ocean Spaces
        cookie_key = f'cookies/{user_id}_cookies.txt'
        try:
            self.s3_client.head_object(Bucket=self.bucket_name, Key=cookie_key)
            # Download cookie to temp file
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                self.s3_client.download_fileobj(self.bucket_name, cookie_key, temp_file)
                return temp_file.name
        except ClientError:
            return None

    def process_files(self, info, data, temp_dir):
        original_title = info.get('title', 'video')
        result = {
            'title': info.get('title'),
            'thumbnail': info.get('thumbnail'),
            'duration': info.get('duration'),
            'files': []
        }

        ydl = yt_dlp.YoutubeDL({'outtmpl': os.path.join(temp_dir, '%(title)s.%(ext)s')})
        original_filename = ydl.prepare_filename(info)

        # Case 1: Just download the video (format=mp4 and extract_audio=False)
        if data.get('format', 'mp4') == 'mp4' and not data.get('extract_audio', False):
            if os.path.exists(original_filename):
                video_filename = self.format_filename(original_title, 'mp4')
                video_key = f'media/{video_filename}'
                self.upload_to_spaces(original_filename, video_key)
                result['files'].append(self.create_file_info('video', video_filename, video_key))
            else:
                return {'error': 'Downloaded video file not found'}, 500

        # Case 2: Download video and extract audio (format=mp4 or mp3 and extract_audio=True)
        else:
            # First save the video file if format is mp4
            if data.get('format', 'mp4') == 'mp4' and os.path.exists(original_filename):
                video_filename = self.format_filename(original_title, 'mp4')
                video_key = f'media/{video_filename}'
                self.upload_to_spaces(original_filename, video_key)
                result['files'].append(self.create_file_info('video', video_filename, video_key))

            # Now extract audio from the video file
            audio_filename = self.format_filename(original_title, 'mp3')
            audio_path = os.path.join(temp_dir, audio_filename)
            
            try:
                import subprocess
                subprocess.run([
                    'ffmpeg',
                    '-y',
                    '-i', original_filename,
                    '-q:a', '0',
                    '-map', 'a',
                    audio_path
                ], check=True)
                
                if os.path.exists(audio_path):
                    audio_key = f'media/{audio_filename}'
                    self.upload_to_spaces(audio_path, audio_key)
                    result['files'].append(self.create_file_info('audio', audio_filename, audio_key))
                    
                    # Process transcription if requested
                    if data.get('speech_to_text', False):
                        self.process_transcription(audio_path, original_title, result, temp_dir)
                else:
                    return {'error': 'Audio extraction failed'}, 500
            except Exception as e:
                return {'error': f'Audio extraction failed: {str(e)}'}, 500

        return result

    def process_transcription(self, audio_path, original_title, response_data, temp_dir):
        try:
            model = whisper.load_model("base")
            result = model.transcribe(audio_path)
            transcript_filename = self.format_filename(original_title + '_transcript', 'txt')
            transcript_path = os.path.join(temp_dir, transcript_filename)
            
            txt_writer = get_writer("txt", temp_dir)
            txt_writer(result, transcript_path)
            
            transcript_key = f'media/{transcript_filename}'
            self.upload_to_spaces(transcript_path, transcript_key)
            
            file_info = self.create_file_info('transcript', transcript_filename, transcript_key)
            file_info['text'] = result['text']
            response_data['files'].append(file_info)
        except Exception as e:
            response_data['transcription_error'] = str(e)

    def upload_to_spaces(self, local_path, spaces_key):
        try:
            self.s3_client.upload_file(
                local_path,
                self.bucket_name,
                spaces_key,
                ExtraArgs={
                    'ACL': 'public-read',
                    'ContentType': self.get_content_type(local_path)
                }
            )
            return f"https://{self.bucket_name}.{current_app.config['DO_SPACES_REGION']}.digitaloceanspaces.com/{spaces_key}"
        except Exception as e:
            logging.error(f"Error uploading to Digital Ocean Spaces: {str(e)}")
            raise

    def get_content_type(self, filename):
        extension = os.path.splitext(filename)[1].lower()
        if extension == '.mp4':
            return 'video/mp4'
        elif extension == '.mp3':
            return 'audio/mpeg'
        elif extension == '.txt':
            return 'text/plain'
        return 'application/octet-stream'

    def format_filename(self, title, ext):
        clean_title = title.lower().replace(' ', '_')
        clean_title = ''.join(c if c.isalnum() or c in ('_', '-') else '' for c in clean_title)
        date_str = datetime.now().strftime("%Y%m%d")
        return f"{clean_title}_{date_str}.{ext}"

    def create_file_info(self, file_type, filename, spaces_key):
        try:
            response = self.s3_client.head_object(Bucket=self.bucket_name, Key=spaces_key)
            size = response['ContentLength']
            
            return {
                'type': file_type,
                'filename': filename,
                'url': f"https://{self.bucket_name}.{current_app.config['DO_SPACES_REGION']}.digitaloceanspaces.com/{spaces_key}",
                'size': size,
                'size_mb': round(size / (1024 * 1024), 2)
            }
        except ClientError as e:
            logging.error(f"Error getting file info from Spaces: {str(e)}")
            return {
                'type': file_type,
                'filename': filename,
                'url': f"https://{self.bucket_name}.{current_app.config['DO_SPACES_REGION']}.digitaloceanspaces.com/{spaces_key}",
                'size': 0,
                'size_mb': 0
            }

class CookieUpload(Resource):
    def __init__(self):
        # Initialize Digital Ocean Spaces client
        self.s3_client = boto3.client(
            's3',
            region_name=current_app.config['DO_SPACES_REGION'],
            endpoint_url=f"https://{current_app.config['DO_SPACES_REGION']}.digitaloceanspaces.com",
            aws_access_key_id=current_app.config['DO_SPACES_KEY'],
            aws_secret_access_key=current_app.config['DO_SPACES_SECRET']
        )
        self.bucket_name = current_app.config['DO_SPACES_BUCKET']

    def post(self):
        if 'cookies_file' not in request.files:
            return {'error': 'No file uploaded'}, 400
        
        file = request.files['cookies_file']
        user_id = request.form.get('user_id', 'default')
        
        if file.filename == '':
            return {'error': 'No selected file'}, 400
        
        try:
            # Save to temporary file first
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                file.save(temp_file.name)
                temp_file_path = temp_file.name
            
            # Upload to Digital Ocean Spaces
            filename = f'cookies/{user_id}_cookies.txt'
            self.s3_client.upload_file(
                temp_file_path,
                self.bucket_name,
                filename
            )
            
            # Clean up temp file
            os.unlink(temp_file_path)
            
            return {'status': 'success'}, 200
        except Exception as e:
            logging.error(f"Error uploading cookie file: {str(e)}")
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
