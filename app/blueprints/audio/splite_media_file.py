import os
from flask import Flask, request, current_app, jsonify
from pydub import AudioSegment

UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'output'
ALLOWED_EXTENSIONS = {'mp3', 'wav', 'ogg', 'flac', 'm4a'}


def split_audio(filepath):

    current_app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER
    
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


