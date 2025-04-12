import os
from flask import Flask, request, send_from_directory, jsonify
from pydub import AudioSegment

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'output'
ALLOWED_EXTENSIONS = {'mp3', 'wav', 'ogg', 'flac', 'm4a'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER

# Create directories if they don’t exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file and allowed_file(file.filename):
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        # Split the audio into 3 parts
        output_files = split_audio(filepath)

        return jsonify({
            "message": "File processed successfully",
            "parts": [f"/download/{os.path.basename(f)}" for f in output_files]
        }), 200
    else:
        return jsonify({"error": "Invalid file type"}), 400

def split_audio(filepath):
    audio = AudioSegment.from_file(filepath)
    duration = len(audio)  # Duration in milliseconds
    part_duration = duration // 3  # Split into 3 parts

    output_files = []
    filename = os.path.splitext(os.path.basename(filepath))[0]

    for i in range(3):
        start = i * part_duration
        end = start + part_duration if i < 2 else duration  # Last part takes remaining time

        part = audio[start:end]
        output_file = os.path.join(OUTPUT_FOLDER, f"{filename}_part{i+1}.mp3")
        part.export(output_file, format="mp3")
        output_files.append(output_file)

    return output_files

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    return send_from_directory(OUTPUT_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
