from flask import Flask, request, current_app, jsonify
from flask_restful import Resource
from werkzeug.utils import secure_filename
import os
import tempfile
import boto3
from botocore.exceptions import ClientError
import subprocess
import logging
from datetime import datetime


# Configure these in your actual application
"""current_app.config['DO_SPACES_REGION'] = 'nyc3'
current_app.config['DO_SPACES_KEY'] = 'your-access-key'
current_app.config['DO_SPACES_SECRET'] = 'your-secret-key'
current_app.config['DO_SPACES_BUCKET'] = 'your-bucket-name'"""

# Initialize Digital Ocean Spaces client
s3_client = boto3.client(
    's3',
    region_name=current_app.config['DO_SPACES_REGION'],
    endpoint_url=f"https://{current_app.config['DO_SPACES_REGION']}.digitaloceanspaces.com",
    aws_access_key_id=current_app.config['DO_SPACES_KEY'],
    aws_secret_access_key=current_app.config['DO_SPACES_SECRET']
)

class AudioReplacer:
    @staticmethod
    def replace_audio(video_path, audio_path, output_path):
        """
        Replace audio in video file with new audio
        """
        try:
            # Command to remove original audio and merge with new audio
            cmd = [
                'ffmpeg',
                '-y',  # Overwrite output file without asking
                '-i', video_path,  # Input video
                '-i', audio_path,  # Input audio
                '-c:v', 'copy',  # Copy video stream without re-encoding
                '-map', '0:v:0',  # Take video from first input
                '-map', '1:a:0',  # Take audio from second input
                '-shortest',  # Finish encoding when the shortest stream ends
                output_path
            ]
            
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"FFmpeg error: {e.stderr.decode()}")
            return False

class MergeVideo(Resource):

    def post(self):
        """
        API endpoint to replace audio in a video
        Expects JSON with:
        - video_key: path to video file in Spaces
        - audio_key: path to audio file in Spaces
        """
        data = request.get_json()
        if not data or 'video_key' not in data or 'audio_key' not in data:
            return jsonify({'error': 'video_key and audio_key are required'}), 400

        video_key = data['video_key']
        audio_key = data['audio_key']
        
        # Create temporary directory for processing
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Download files from Spaces
                video_path = os.path.join(temp_dir, 'input_video.mp4')
                audio_path = os.path.join(temp_dir, 'input_audio.mp3')
                output_path = os.path.join(temp_dir, 'output_video.mp4')
                
                # Download video
                s3_client.download_file(current_app.config['DO_SPACES_BUCKET'], video_key, video_path)
                
                # Download audio
                s3_client.download_file(current_app.config['DO_SPACES_BUCKET'], audio_key, audio_path)
                
                # Process files
                if not AudioReplacer.replace_audio(video_path, audio_path, output_path):
                    return jsonify({'error': 'Failed to process video'}), 500
                
                # Upload result to Spaces
                output_key = f"processed/{datetime.now().strftime('%Y%m%d_%H%M%S')}_output.mp4"
                s3_client.upload_file(
                    output_path,
                    current_app.config['DO_SPACES_BUCKET'],
                    output_key,
                    ExtraArgs={
                        'ACL': 'public-read',
                        'ContentType': 'video/mp4'
                    }
                )
                
                # Generate public URL
                video_url = f"https://{current_app.config['DO_SPACES_BUCKET']}.{current_app.config['DO_SPACES_REGION']}.digitaloceanspaces.com/{output_key}"
                
                return jsonify({
                    'message': 'Audio replaced successfully',
                    'video_url': video_url,
                    'video_key': output_key
                }), 200
                
            except ClientError as e:
                logging.error(f"Spaces error: {str(e)}")
                return jsonify({'error': 'Failed to access storage'}), 500
            except Exception as e:
                logging.error(f"Unexpected error: {str(e)}")
                return jsonify({'error': 'Internal server error'}), 500
