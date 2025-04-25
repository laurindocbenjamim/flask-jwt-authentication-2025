import os
from flask_restful import Resource
from flask import send_file, Response, current_app, request
from werkzeug.utils import secure_filename


class ReadVideo(Resource):

    MAX_STREAM_SIZE = 10 * 1024 * 1024

    def post(self):
        """
        Retrieves a video file from the configured upload directory.

        Args:
            filename (str): The name of the video file.

        Returns:
            flask.Response: The video file as a response.
        """
        data = request.get_json()
        filename = data.get('filename')
        if not filename:
            return {'error': 'filename is required'}, 400
        
        # Ensure filename is safe and prevent directory traversal attacks
        safe_filename = secure_filename(filename) 

        video_path = os.path.join(
            current_app.root_path, 
            'static', 
            current_app.config['DOWNLOAD_FOLDER'], 
            safe_filename
        )

        # Ensure the file exists before attempting to send it
        if not os.path.isfile(video_path):
            return {"message": f"Video '{safe_filename}' not found."}, 404

        # Set appropriate file permissions (if necessary)
        #os.chmod(video_path, 0o755) 

        return send_file(video_path, mimetype='video/mp4')



    def get(self, filename):
        """
        Retrieves a video file from the configured upload directory.

        Args:
            filename (str): The name of the video file.

        Returns:
            flask.Response: The video file as a response.
        """

        # Ensure filename is safe and prevent directory traversal attacks
        safe_filename = secure_filename(filename) 


        video_path = os.path.join(
            current_app.root_path, 
            'static', 
            current_app.config['DOWNLOAD_FOLDER'], 
            safe_filename
        )

        # Ensure the file exists before attempting to send it
        if not os.path.isfile(video_path):
            return {"message": f"Video '{safe_filename}' not found."}, 404
        
        if not os.path.exists(video_path):
            return {"message": "File not found"}, 404

        file_size = os.path.getsize(video_path)
        size = round(file_size / (1024 * 1024), 2)
        range_header = request.headers.get('Range', None)

        
        #return f"Ola {file_size > self.MAX_STREAM_SIZE }. Range {range_header}"

        if file_size > self.MAX_STREAM_SIZE or range_header:
            
            # Use streaming method
            def generate():
                with open(video_path, 'rb') as f:
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        yield chunk

            return Response(generate(), mimetype='video/mp4')
        else:
            # Set appropriate file permissions (if necessary)
            #os.chmod(video_path, 0o755) 
            # Small file, send as whole
            return send_file(video_path, mimetype='video/mp4')

        
    