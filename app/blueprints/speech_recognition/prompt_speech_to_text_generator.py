import requests
import traceback
import sys

import os
from datetime import datetime
from openai import OpenAI
import openai


from app.utils import get_message as set_logger_message

class ConvertAudioSpeechToText(object):
    """
    This class is used to convert an audio speech to a text.

    In this class we are using the OpenAI API for speech
     
    """
    API_URL = 'https://api.openai.com/v1/audio/speech'
    

    voices = ('alloy', 'echo', 'fable', 'onyx', 'nova', 'shimmer')
    formats = ('mp3', 'opus', 'aac', 'flac', 'wav', 'pcm')
    speeds = None
    INPUT_TEXT = None
    MODEL_VOICE = None
    FORMAT = None
    SPEED = None
    FILE_NAME = None
    def __init__(self, audio_file_path, output_lang):
        """
        COSTRUCTOR PARAMETERS
        
        input_text: is the text from which the audio will be created
        
        model_voice: is the voice used to generate the audio. 
        By default it uses the voice 'alloy'
        but it supports the following voices 
        [alloy, echo, fable, onyx, nova,shimmer]
        
        format: is the output format of the audio. Supported formats 
        (mp3, opus, aac, flac, wav, pcm). 
        By default it retuns an MP3 format
        
        speed: is the speed of the audio generated. 
        it suports speeds from 0.25 to 4.0. By default it uses 1.0 
        
        file_name: It is the name of the audion generated. By default it is 'speech'

        """
        self.FILE_NAME = audio_file_path
        self._output_lang = output_lang

    def generate_transcription(self):
        """
        This is the audio generator method. It requests the audio using the API URL
        """

        if not self.FILE_NAME or self.FILE_NAME =='':
            return False, "File path required"

        try:
            """HEADERS = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer '+ os.environ['OPEN_AI_API_KEY']
            }   
            DATA = {
                "model": "tts-1",
                "input": self.INPUT_TEXT,
                "voice": self.MODEL_VOICE
            }

            response = requests.post(self.API_URL, headers=HEADERS, json=DATA)

            directory = "speechs/"
            
        
            if response.status_code == 200:
                filename = f'{self.FILE_NAME}{datetime.now().strftime("%d-%m-%Y %H-%M-%S")}.{self.FORMAT}'
                # Use the os.path.join to create the full file path
                file_path = os.path.join(directory, filename)

                # Check if the file exists, if true then it create other name for it
                if os.path.exists(file_path):
                    print("The file exists.")

                client = OpenAI(
                api_key=os.environ['OPEN_AI_API_KEY'],  # this is also the default, it can be omitted
                )

                audio_file= open(self.FILE_NAME, "rb")
                transcription = client.audio.transcriptions.create(
                model="whisper-1", 
                file=audio_file,
                response_format="text"
                )
                return True, 200, transcription.text
            else:
                return False, response.status_code, ''
            """

            client = OpenAI(
            api_key=os.environ['OPEN_AI_API_KEY'],  # this is also the default, it can be omitted
            )
            
            audio_file= open(self.FILE_NAME, "rb")

            
            transcription = client.audio.transcriptions.create(
                model="whisper-1", 
                file=audio_file,
                response_format="text",
                language= self._output_lang
            )

            if 'Error code: 413' in transcription:
                return False, "The file is too large. Please try with a smaller file."
            return True, transcription
        except KeyError as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            set_logger_message(f"Error occured on method[generate_transcription]: \n \
                                       KeyError: {str(sys.exc_info())}\
                                       \nFile name: {fname}\
                                       \nExc-instance: {fname}\
                                       \nExc-classe: {exc_type}\
                                       \nLine of error: {exc_tb.tb_lineno}\
                                       \nTB object: {exc_tb}\
                                       \nTraceback object: {str(traceback.format_exc())}\
                                        ") 
            return False, str(e)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            set_logger_message(f"Error occured on method[generate_transcription]: \n \
                                       Exception: {str(sys.exc_info())}\
                                       \nFile name: {fname}\
                                       \nExc-instance: {fname}\
                                       \nExc-classe: {exc_type}\
                                       \nLine of error: {exc_tb.tb_lineno}\
                                       \nTB object: {exc_tb}\
                                       \nTraceback object: {str(traceback.format_exc())}\
                                        ") 
            return False, str(e)
        

    def generate_transcription_v2(self):
        """
        This is the audio generator method. It requests the audio using the API URL
        """

        if not self.FILE_NAME or self.FILE_NAME =='':
            return False, "File path required"
        
        client = OpenAI(
            api_key=os.environ['OPEN_AI_API_KEY'],  # this is also the default, it can be omitted
            )
        audio_file = open(self.FILE_NAME, "rb")

        try:
            transcription = client.audio.transcribe(
                model="whisper-1", 
                file=audio_file,
                response_format="text",
                language=self._output_lang
            )
            return True, transcription

        except openai.OpenAIError as e:
            if "413" in str(e):
                return False, "The file is too large. Please try with a smaller file."
            elif "Invalid file format" in str(e):
                return False, "Invalid file format. Please upload a supported audio format."
            else:
                return False, f"An error occurred: {e}"

        except KeyError as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            set_logger_message(f"Error occured on method[generate_transcription]: \n \
                                       KeyError: {str(sys.exc_info())}\
                                       \nFile name: {fname}\
                                       \nExc-instance: {fname}\
                                       \nExc-classe: {exc_type}\
                                       \nLine of error: {exc_tb.tb_lineno}\
                                       \nTB object: {exc_tb}\
                                       \nTraceback object: {str(traceback.format_exc())}\
                                        ") 
            return False, str(e)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            set_logger_message(f"Error occured on method[generate_transcription]: \n \
                                       Exception: {str(sys.exc_info())}\
                                       \nFile name: {fname}\
                                       \nExc-instance: {fname}\
                                       \nExc-classe: {exc_type}\
                                       \nLine of error: {exc_tb.tb_lineno}\
                                       \nTB object: {exc_tb}\
                                       \nTraceback object: {str(traceback.format_exc())}\
                                        ") 
            return False, str(e)
        
    
    def generate_translation():
        """
        
        """        

        

        