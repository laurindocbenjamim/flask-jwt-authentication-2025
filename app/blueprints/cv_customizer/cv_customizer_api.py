

import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

from flask_restful import Api, Resource, reqparse, request, current_app
from app.utils import admin_required, upload_file
from .cv_factory import cv_customizer_with_chat_gpt

from app.utils import PdfReaderFactory
from app.utils import DocxFileFactory
from app.utils import MyGeneralFileFactory
from app.utils import handle_ai_response_json

from flask import jsonify, make_response
from flask_jwt_extended import (
    jwt_required,
    current_user,
    get_jwt
)
from datetime import datetime


class CvCustomizerApp(Resource):
    #@jwt_required()
    def get(self):
        return make_response(jsonify(message="Welcome to CV Customizer"), 200)
    
    def post(self):

        #csrf_token = request.headers.get('X-Csrf-Token')
        """try:
            # Convert request headers to a dictionary
            headers_dict = dict(request.headers)

            # Convert the dictionary to a JSON string
            headers_json = json.dumps(headers_dict, indent=4)
            # Use the JSON string in your log message
            log_message = f"Headers: {headers_json}"
            current_app.logger.debug(f"Headers: {log_message}, CSRF-TOKEN: {csrf_token}")

            if not csrf_token:
                raise ValueError("CSRF token is missing")
            
            validate_csrf(csrf_token)
        except Exception as e:
            return jsonify({"status":403, "error": f"Invalid CSRF token: {str(e)}", "csrf-token-received":csrf_token})
        """
        
        #file = request.files['cvUpload']
        
        return make_response(jsonify(sms="Welcome to CV Customizer"), 200)
    
        # Check if the request contains the file part
        if 'contentOrigin' in request.form and request.form['contentOrigin'] =='file':
            if 'cvUpload' not in request.files:
                return jsonify({"status":400, "error": "No file part"})
            elif 'jobRequirements' not in request.files:
                return jsonify({"status":400, "error": "No file part"})

            file = request.files['cvUpload']
            file2 = request.files['jobRequirements']
            
            # Check if a file has been selected
            if file.filename == '' or file2.filename == '':
                return jsonify({"status":400, "error": "No selected file"})

            # Use the save_uploaded_file function from the module
            
            filepath=os.path.join(current_app.root_path, 'static', current_app.config['UPLOAD_FOLDER'])
            #status,result = save_uploaded_file(file,filepath)
            status, filename = upload_file(request_file=request, file_field_name="cvUpload", folder='files')

            if not status:
                return make_response(jsonify(error=f"Failed to upload file. {filename}", transcription=filename), 400)

            if not os.path.exists(filename) or not os.path.isfile(filename):
                return make_response(jsonify(error="File not found",transcription=''), 200)   
            
            MAX_SIZE = current_app.config['MAX_CONTENT_LENGTH']  # 25 MB = 26214400 bytes
            file_size = os.path.getsize(filename)

            if file_size > MAX_SIZE:
                # remove the file after processing with secure filename
                os.remove(filename)
                return make_response(jsonify(error="Maximum content size limit 25MB",status_code=400), 400)
            
            
            files_path={}
           
            files_path['cv_client']=filename

            # Upload the second file
            status, filename2 = upload_file(request_file=request, file_field_name="jobRequirements", folder='files')
            
            if not status:
                return make_response(jsonify(error=f"Failed to upload file. {filename2}", transcription=filename2), 400)

            if not os.path.exists(filename2) or not os.path.isfile(filename2):
                return make_response(jsonify(error="File not found",transcription=''), 200)   
            
            MAX_SIZE = current_app.config['MAX_CONTENT_LENGTH']  # 25 MB = 26214400 bytes
            file_size = os.path.getsize(filename2)

            if file_size > MAX_SIZE:
                # remove the file after processing with secure filename
                os.remove(filename2)
                return make_response(jsonify(error="Maximum content size limit 25MB",status_code=400), 400)
            
            
            files_path['job_requirements_file']=filename2
                
            pdf_reader=PdfReaderFactory()

            # Extract content from files and remove them
            files_path['cv_client_content']=pdf_reader.extract_text_fitz(files_path['cv_client'])
            if os.path.exists(files_path['cv_client']):
                os.remove(files_path['cv_client'])                
                
            files_path['job_requirement_content']= pdf_reader.extract_text_fitz(files_path['job_requirements_file'])

            # Reove the file
            if os.path.exists(files_path['job_requirements_file']):
                os.remove(files_path['job_requirements_file'])
                    
            # Request  the customization to ChatGPT
            status, optimized_cv = cv_customizer_with_chat_gpt(client_cv=files_path['cv_client_content'],
            job_requirement=files_path['job_requirement_content'])

            if 'error' in optimized_cv or '404' in  optimized_cv:
                    return jsonify({"status":404, "error": f"IA assistant Failed to customise the CV. {str(optimized_cv)}"})
                
            # Save the content created to docx
            docx=DocxFileFactory()
                
            #docx.save_to_docx(content=optimized_cv, filepath=filepath, filename="customised_cv.docx")
            # Save to temporary file
            if not status:
                return jsonify({"status":404, "error": f"CV optimisation failed. {str(optimized_cv)}"})
                
            try:
                current_timestamp=datetime.now().strftime('%Y%m%d%H%M%S')

                if not optimized_cv or optimized_cv=='':
                    return jsonify({"status":404, "error": f"Null CV optimisation. {str(optimized_cv)}"})

                # Parse JSON string into a Python dictionary
                json_response_parsed=optimized_cv# json.loads(optimized_cv)               
                file_name=os.path.join(filepath,f'optimized_cv_{current_timestamp}.md')
                file_name_docx_base64=os.path.join(filepath,f'optimized_cv_{current_timestamp}.docx')

                # Creating saving  the plain text into JSON, MD and HTML files
                file_factory=MyGeneralFileFactory()

                json_cleaned = handle_ai_response_json(json_response_parsed)
                file_factory.create(content=json_cleaned, filepath=os.path.join(filepath,f'optimized_cv_{current_timestamp}.json'), type_of='json')
                #return jsonify({"status": 200, "message": "Your CV was optimised successfully!", "JSON": json_response_parsed})

                file_factory.create(content=json_response_parsed, filepath=file_name, type_of='md')
                    
                file_name_html=os.path.join(filepath,f'optimized_cv_{current_timestamp}.html')
                    
                #file_factory.create(content=json_response_parsed['cv_in_plain_text_format'], filepath=file_name_html, type_of='html')
                    
                #file_factory.create(content=json_response_parsed['cv_in_docx_format'], filepath=file_name_docx_base64, type_of='BASE64_ENCODED_STRING_DOCX')

                    
                # Creating saving  the plain text into DOCX and PDF files
                doc_filename=f'cv_optimised_{current_timestamp}'
                pdf_filename=f'{doc_filename}.pdf'
                new_file_path=docx.save_as_docx(optimized_cv=json_response_parsed,file_path=filepath, filename=doc_filename)            
                    
                res=docx.docx_to_pdf(docx_path=new_file_path, pdf_path=os.path.join(filepath,pdf_filename))
                    
                    
                return jsonify({"status": 200, "message": "Your CV was optimised successfully!", 
                    "json": json_cleaned,
                    "docx_file_path": f'api/files-storage/doc/download/{doc_filename}.docx',
                    "pdf_file_path": f'api/files-storage/doc/download/{pdf_filename}',
                    "file_name_html": f'api/files-storage/doc/download/{file_name_html}',
                    "file_name_docx_base64": f'api/files-storage/doc/download/{file_name_docx_base64}',
                }), 200
            except Exception as e:
                return jsonify({"status":400, "error": f"Failed to optimise the CV! {str(e)}"})
        else: 
            return jsonify({"status":404, "error": "The origin field has not been found!"})