
import boto3
import os
from flask import Blueprint, request, current_app, make_response, jsonify
from markupsafe import escape
from flask_restful import Api, Resource
from .cloud_storage_api import CloudStorageApi
from .space_client import client
from .space_client import SpaceBucket

# Documentation: https://docs.digitalocean.com/reference/api/spaces/
# https://docs.digitalocean.com/reference/api/spaces-api/#s3-sdk-examples
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html

cloud_storage_bp_api = Blueprint("cloud_storage", __name__, url_prefix='/api/v1/cloud_storage')
api = Api(cloud_storage_bp_api)



@cloud_storage_bp_api.route('/upload', methods=['POST'])
def upload_file():
    BUCKET = current_app.config["SPACES_BUCKET"]

    file = request.files['file']
    client.upload_fileobj(file, BUCKET, file.filename)
    return jsonify({'message': 'File uploaded successfully'})


@cloud_storage_bp_api.route('/files/<filename>', methods=['GET'])
def get_file(filename):
    filename = escape(filename)

    if not filename:
        return make_response(jsonify(error="File not identified!"))
    
    file_path = f'videos/{filename}'

    BUCKET = current_app.config["SPACES_BUCKET"]

    url = client.generate_presigned_url(
        'get_object',
        Params={'Bucket': BUCKET, 'Key': file_path},
        ExpiresIn=3600  # 1 hour
    )
    return jsonify({'url': url})


@cloud_storage_bp_api.route('/files/<filename>', methods=['DELETE'])
def delete_file(filename):

    BUCKET = current_app.config["SPACES_BUCKET"]

    client.delete_object(Bucket=BUCKET, Key=filename)
    return jsonify({'message': f'{filename} deleted'})


@cloud_storage_bp_api.route('/update/<old_filename>', methods=['POST'])
def update_file(old_filename):

    old_filename = escape(old_filename)

    if not old_filename:
        return make_response(jsonify(error="File not identified!"))
    
    file_path = f'videos/{old_filename}'

    BUCKET = current_app.config["SPACES_BUCKET"]

    # Delete the old one first (or rename logic if you want)
    client.delete_object(Bucket=BUCKET, Key=old_filename)

    new_file = request.files['file']
    client.upload_fileobj(new_file, BUCKET, new_file.filename)

    return jsonify({'message': f'{old_filename} updated to {new_file.filename}'})


