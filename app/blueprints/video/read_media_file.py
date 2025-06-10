import os, re
from flask_restful import Resource
from flask import send_file, make_response, jsonify, Response, current_app, request
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
        return self.load_file(video_path, range_header, file_size)



    def load_file(self,video_path, range_header, file_size):
        if range_header:
            byte1, byte2 = 0, None

            match = re.search(r'bytes=(\d+)-(\d*)', range_header)
            if match:
                byte1 = int(match.group(1))
                if match.group(2):
                    byte2 = int(match.group(2))

            byte2 = byte2 if byte2 is not None else file_size - 1
            length = byte2 - byte1 + 1

            with open(video_path, 'rb') as f:
                f.seek(byte1)
                data = f.read(length)

            response = Response(data, status=206, mimetype='video/mp4')
            response.headers.add('Content-Range', f'bytes {byte1}-{byte2}/{file_size}')
            response.headers.add('Accept-Ranges', 'bytes')
            response.headers.add('Content-Length', str(length))
            return response

        # No Range: send the whole file
        def generate():
            with open(video_path, 'rb') as f:
                while True:
                    data = f.read(8192)
                    if not data:
                        break
                    yield data

        return Response(generate(), mimetype='video/mp4')

        

class SelectFiles(Resource):
    def get(self, directory="uploads"):
        """
        Returns a list of files in the specified directory.

        Args:
            directory (str): The name of the directory to list files from. Defaults to "uploads".

        Returns:
            dict: A dictionary containing the list of files in the directory.
        """

        directory = secure_filename(directory)

        upload_folder = os.path.join(
            current_app.root_path, 
            'static', 
            current_app.config['DOWNLOAD_FOLDER']
        )

        if not os.path.exists(upload_folder):
            return {"message": "Folder not found."}, 404

        files = [
            f for f in os.listdir(upload_folder) 
            if os.path.isfile(os.path.join(upload_folder, f))
        ]

        return {"files": files}, 200