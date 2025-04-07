import os
import uuid
import json, string, secrets
from datetime import datetime
from PIL import Image
from flask import Request, current_app
from werkzeug.utils import secure_filename
import shutil
from PyPDF2 import PdfReader, PdfWriter

root_files_path='static'

def load_content(self, file_type="txt"):
    """Load comments from a JSON file."""

    if file_type == "txt":
        if os.path.exists(self.myFILE_PATH):
            with open(self.myFILE_PATH, "r") as file:
                data = file.read()
                file.close()
                return data
        return []
    elif file_type == "json":
        if os.path.exists(self.myFILE_PATH):
            with open(self.myFILE_PATH, "r") as file:
                data = json.load(file)
                file.close()
                return data
        return []


def read_html_file(file_path):
    """
    Reads an HTML file and parses it into a BeautifulSoup object for easy HTML processing.

    Args:
        file_path (str): The path to the HTML file.

    Returns:
         Parsed HTML content.
    """

    _FILE_PATH = os.path.join(root_files_path, current_app.config['UPLOAD_FOLDER'],file_path)

    try:
        # if not os.path.exists(_FILE_PATH):
        #    return
        with open(_FILE_PATH, "r", encoding="utf-8") as file:
            # Read the entire HTML file content
            html_content = file.read()
            file.close()
            return html_content
    except FileNotFoundError:
        # Open the file in append mode, create if it doesn't exist
        with open(_FILE_PATH, "a+") as file:
            file.write("<pre><h1>Hello, World!</h1></pre>")
        return f"File not found. The file as been created. {_FILE_PATH}"
    except Exception as e:
        return f"An error occurred: {e}"


# Method to save file
def upload_file(request_file: Request.files, file_field_name: str, **kwargs):
    """
    This method is used to upload files
    Parameters:
    => request_file: Request.files is a request files variable that contain a list of files
    => field_name: is the name of the file field
    """
    file = request_file[f"{file_field_name}"]
    filename = ""
    try:
        # filename = secure_filename(file.filename)

        UPLOAD_FOLDER = (
            os.path.join(root_files_path, current_app.config['UPLOAD_FOLDER'], kwargs.get('folder', 'files'))
        )

        # Check if the folder to store the tickets exists, if not, create it
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        # file.save(os.path.join(UPLOAD_FOLDER, filename))
        save_with = kwargs.get('save_with', '')

        if save_with == 'new':
            filename = save_file_with_new_name(file, file.filename, UPLOAD_FOLDER)
        else:
            # Join the file with its path
            filename = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
            file.save(filename)
            # Perform file operations
            file.close()

        return True, filename
    except Exception as e:
        return False, f"Error: {str(e)}"

# Method to remove a directory with content or files
def delete_directory_with_contents(directory):
    
    """
        Deletes the specified directory and all its contents.
        This function attempts to delete the directory specified by the `directory` parameter.
        It first sets the directory permissions to 755 to ensure it can be deleted. If the 
        directory exists, it will be removed along with all its contents. If the directory 
        does not exist, it returns a message indicating so. If an error occurs during the 
        deletion process, it catches the exception and returns an error message.
    Args:
        directory (str): The path to the directory to be deleted.
    Returns:
        tuple: A tuple containing a boolean and a string. The boolean indicates success 
               (True) or failure (False), and the string provides a message with details 
               about the operation.
    """
    try:
        # Set permissions first
        os.chmod(directory, 0o755)
        if os.path.exists(directory):
            shutil.rmtree(directory)
            return True, f"Directory {directory} and its contents have been deleted."
        else:
            return True, f"Directory {directory} does not exist."
    except FileNotFoundError as e:
        return True, f'Error: {str(e)}'
    except Exception as e:
        return False, f"Error: {str(e)}"
#
def save_file_with_new_name(file, original_name, file_path): 
    """
        Save the file with a new name

        return:
               save and return the new name.
    """
    try:
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S') 
        new_name = f"{str(os.path.splitext(original_name)[0]).replace(' ','_')}_{timestamp}{os.path.splitext(original_name)[1]}" 
        file.save(os.path.join(file_path, secure_filename(new_name))) 
        # Perform file operations
        file.close()
        return new_name
    except Exception as e:
        return "Failed to upload file with a new name."


def validate_image_size(file_path, max_size=2): 
    FILE_PATH = os.path.join(root_files_path, current_app.config['UPLOAD_FOLDER'], file_path)
    try: 
        # 
        with Image.open(FILE_PATH) as img: 
            if img.format not in ['JPEG', 'PNG']: 
                return False 
            #This condition checks if the size of the file is greater than 2 MB.
            if os.path.getsize(FILE_PATH) > current_app.config['MAX_CONTENT_LENGTH']: 
                # If the file size exceeds 3 MB, the function returns False
                return False
        return True 
    except Exception as e:  
        return False

def validate_file(request: Request, file_field_name):
    try:
        # check if the post request has the file part
        if f"{file_field_name}" not in request.files:
            return False, f"No {file_field_name} part"

        file = request.files[f"{file_field_name}"]
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == "":
            return False, "No file has been selected"

        if not file:
            return False, f"A {file_field_name} is required"
        if not allowed_file(file.filename):
            return False, "Type file not allowed"

        # Return True if everything is okay
        return True, "OK"
    except Exception as e:
        return False, str(e)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']


def check_or_create_file(file_path):
    FILE_PATH = os.path.join(root_files_path, current_app.config['UPLOAD_FOLDER'], file_path)
    # Check if the folder to store the tickets exists, if not, create it
    if not os.path.exists(FILE_PATH):
        os.makedirs(file_path, exist_ok=True)
    return FILE_PATH


def saveIntoFile(file_directory: str, data):
    file_path = os.path.join(root_files_path, current_app.config['UPLOAD_FOLDER'],file_directory) 

    # Check if the folder to store the tickets exists, if not, create it
    if not os.path.exists(file_path):
        os.makedirs(file_path, exist_ok=True)

    return True


def save_uploaded_file(file, file_directory):
    """Handles the uploading and saving of a file."""

    # Define the upload directory within the Flask static folder
    static_dir = os.path.join(root_files_path)
    upload_dir = os.path.join(static_dir, file_directory)
    
    # Create the directory if it doesn't exist
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir, mode=0o755)

    if file and validate_file(file, current_app.config['ALLOWED_EXTENSIONS']):
        # Generate a unique filename using a short UUID and secure the name
        try:
            name_part, extension = os.path.splitext(file.filename)
            short_uuid = str(uuid.uuid4())[:8]
            unique_filename = f"{name_part.replace(' ','_').lower()}_{short_uuid}{extension}"
            filename = secure_filename(unique_filename)

            # Save the file to the upload directory
            file.save(os.path.join(upload_dir, filename))
            return True, {"status": 200, "message": f"File successfully uploaded.", "file": filename}
        except Exception as e:
            return False, {"status": 400, "error": f"Failed to save file {str(e)}"}
    else:
        return False, {"status": 400, "error": "Invalid file format!"}


def generate_strong_secret_key(length=32): 
    alphabet = string.ascii_letters + string.digits + string.punctuation 
    return ''.join(secrets.choice(alphabet) for _ in range(length))


#
def remove_pdf_protection(input_path, output_path, password):
    reader = PdfReader(input_path)
    if reader.is_encrypted:
        reader.decrypt(password)

    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    with open(output_path, 'wb') as output_pdf:
        writer.write(output_pdf)


#
def remove_edit_protection(input_path, output_path):
    """Remove edit restrictions from a PDF."""
    reader = PdfReader(input_path)
    writer = PdfWriter()

    # Copy all pages to a new PDF
    for page in reader.pages:
        writer.add_page(page)

    # Remove permissions (create an unrestricted PDF)
    writer.add_metadata(reader.metadata)  # Copy metadata if needed
    writer.write(output_path)