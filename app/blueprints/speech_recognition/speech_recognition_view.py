

import os
from pathlib import Path
from flask.views import View
from flask import jsonify, make_response, request, send_from_directory
from werkzeug.utils import secure_filename
from flask_restful import reqparse
import re
from app.factory import (
    get_user_parser,
    sanitize_name,
    sanitize_username,
    sanitize_email,
    sanitize_phone,
    sanitize_country
)

from app.blueprints.audio import split_audio

from .prompt_speech_to_text_generator import ConvertAudioSpeechToText

parser = reqparse.RequestParser()
parser.add_argument('languageSelect', required=True, location='form', type=sanitize_name, help="Language cannot be blank!")
parser.add_argument('outputFormat', required=True, location='form', type=sanitize_name, help="Output format cannot be blank!")


class SpeechRecognitionView(View):
    methods = ['POST']

    ALLOWED_EXTENSIONS = {'mp3', 'mp4', 'wav'}

    def __init__(self,template) -> None:
        super().__init__()
        self.template = template
        self._title = "MSpeeText converter"
    
    def dispatch_request(self):
        """
        """

        def get_lang(lang):
                if lang == 'en':
                    return "English"
                elif lang == 'pt':
                    return "Portuguese"
                elif lang == 'fr':
                    return "France"
                elif lang == 'de':
                    return "German"
                elif lang == 'es':
                    return "Spanish"
                elif lang == 'it':
                    return "Italian"
                
        
        def allowed_file(filename):
            ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp3', 'mp4', 'wav'}
            return '.' in filename and \
                filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
        
        UPLOAD_FOLDER = 'app/static/uploads/'
        OUTPUT_FOLDER = 'app/static/output/'

        if request.method =='GET':
            return make_response(jsonify(error="Method not allowed"), 400)
        if request.method == 'POST':
            # check if the post request has the file part
            if 'fileInput' not in request.files:
                return make_response(jsonify(title=self._title, error="No file has been selected", transcription=""), 200)    
            
            data = parser.parse_args()
            output_lang = data.get("languageSelect", "pt")
            outputFormat = data.get("outputFormat", "text")
           
            file = request.files['fileInput']
            #output_lang = request.form.get('output-language', 'pt')
           
            #If the user does not select a file, the browser submits an
            # empty file without a filename.
            if file.filename == '':
                return make_response(jsonify(error="No file has been selected", transcription=""), 200)
                
            #file.save(f"{UPLOAD_FOLDER}{secure_filename(file.filename)}")
            filename = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
            file.save(filename)
            
            if not os.path.exists(filename) or not os.path.isfile(filename):
                return make_response(jsonify(error="File not found",title=self._title, transcription=''), 200)   

            #splited_files = split_audio(filename)
            
           
            #return send_from_directory(OUTPUT_FOLDER, [f for f in splited_files], as_attachment=True)

            convert = ConvertAudioSpeechToText(filename, output_lang)
            status, transcription = convert.generate_transcription()

            if not status:
                return make_response(jsonify(error=transcription,title=self._title), 400)

            message = f"Here is your media speech converted to the text format on {get_lang(output_lang)} language."
            
            # remove the file after processing with secure filename
            os.remove(filename)
            

            #return jsonify({"filename": convert.FILE_NAME, "status": status, "transcription": transcription})
            return make_response(jsonify(title=self._title, transcription=transcription, message=message), 200)   
    

        