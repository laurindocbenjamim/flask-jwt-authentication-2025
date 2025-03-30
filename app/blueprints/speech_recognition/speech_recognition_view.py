

import os
from pathlib import Path
from flask.views import View
from flask import jsonify, make_response, request
from werkzeug.utils import secure_filename

from .prompt_speech_to_text_generator import ConvertAudioSpeechToText

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

        if request.method =='GET':
            return make_response(jsonify(error="Method not allowed"), 400)
        if request.method == 'POST':
            # check if the post request has the file part
            if 'audio' not in request.files:
                return make_response(jsonify(title=self._title, error="No file has been selected", transcription=""), 200)    
                    
            file = request.files['audio']
            output_lang = request.form.get('output-language', 'pt')
           
            #If the user does not select a file, the browser submits an
            # empty file without a filename.
            if file.filename == '':
                return make_response(jsonify(error="No file has been selected", transcription=""), 200)
                
            #file.save(f"{UPLOAD_FOLDER}{secure_filename(file.filename)}")
            filename = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
            file.save(filename)
            
            if not os.path.exists(filename) or not os.path.isfile(filename):
                return make_response(jsonify(error="File not found",title=self._title, transcription=''), 200)   

            


            convert = ConvertAudioSpeechToText(filename, output_lang)
            status, transcription = convert.generate_transcription()
            message = f"Here is your media speech converted to the text format on {get_lang(output_lang)} language."
            
            # remove the file after processing with secure filename
            os.remove(filename)
            

            #return jsonify({"filename": convert.FILE_NAME, "status": status, "transcription": transcription})
            return make_response(jsonify(title=self._title, transcription=transcription, message=message), 200)   
    

        