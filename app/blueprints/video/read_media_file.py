import os
from flask_restful import Resource
from flask import send_file, current_app, request
from werkzeug.utils import secure_filename


class ReadVideo(Resource):
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

        # Set appropriate file permissions (if necessary)
        #os.chmod(video_path, 0o755) 

        return send_file(video_path, mimetype='video/mp4')