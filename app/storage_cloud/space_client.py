
import os
import boto3
from flask import request

session = boto3.session.Session()
client = session.client(
            's3',
            region_name=os.getenv('SPACES_REGION'),
            endpoint_url=os.getenv('SPACES_ENDPOINT'),
            aws_access_key_id=os.getenv('SPACES_KEY'),
            aws_secret_access_key=os.getenv('SPACES_SECRET')
        )

class SpaceBucket:
    """
    SpaceBucket is a class that provides an interface for interacting with a cloud storage bucket.
    It allows uploading, retrieving, deleting, and updating files in the bucket.
    Attributes:
        BUCKET (str): The name of the bucket, fetched from environment variables.
        FILE_NAME (str): The name of the file to be uploaded, retrieved, or deleted.
        FILE (file-like object): The file object to be uploaded.
        client (boto3.Client): The S3 client used to interact with the cloud storage.
    Methods:
        __init__(file, file_name):
            Initializes the SpaceBucket instance with the provided file and file name.
        create_client():
            Creates and returns an S3 client using the environment variables for configuration.
        upload():
            Uploads the file to the bucket. Returns True if successful, False otherwise.
        get_file():
            Generates a presigned URL for accessing the file in the bucket. Returns the URL if successful, None or False otherwise.
        delete():
            Deletes the file from the bucket. Returns True if successful, False otherwise.
        update(old_filename):
            Updates the file in the bucket by deleting the old file and uploading the new one.
            Returns a tuple of the old and new file names if successful, False otherwise.
    """

    BUCKET = None
    FILE_NAME = None
    FILE = None
    client = None

    def __init__(self, file, file_name):
        self.FILE_NAME = file_name
        self.FILE = file
        self.client = self.create_client()


    def create_client(self):
        """
        Creates and returns an S3 client for interacting with a DigitalOcean Spaces bucket.

        This method initializes an S3 client using the boto3 library and configuration
        values retrieved from environment variables. The client is configured to connect
        to a specific DigitalOcean Spaces bucket.

        Environment Variables:
            SPACES_BUCKET: The name of the Spaces bucket.
            SPACES_REGION: The region where the Spaces bucket is located.
            SPACES_ENDPOINT: The endpoint URL for the Spaces service.
            SPACES_KEY: The access key ID for authentication.
            SPACES_SECRET: The secret access key for authentication.

        Returns:
            botocore.client.S3: A configured S3 client instance.
        """

        self.BUCKET = os.getenv('SPACES_BUCKET')

        session = boto3.session.Session()
        client = session.client(
            's3',
            region_name=os.getenv('SPACES_REGION'),
            endpoint_url=os.getenv('SPACES_ENDPOINT'),
            aws_access_key_id=os.getenv('SPACES_KEY'),
            aws_secret_access_key=os.getenv('SPACES_SECRET')
        )
        return client

    def upload(self):
        """
        Uploads a file to a specified cloud storage bucket.
        This method uploads the file object stored in `self.FILE` to the cloud storage
        bucket specified by `self.BUCKET` with the name `self.FILE_NAME`.
        Returns:
            bool: True if the file was successfully uploaded, False if an error occurred.
            None: If `self.FILE_NAME` is not set.
        Raises:
            Exception: If an unexpected error occurs during the upload process.
        """

        if not self.FILE_NAME:
            return None
        
        try:
            self.client.upload_fileobj(self.FILE, self.BUCKET, self.FILE_NAME)

            return True
        except Exception as e:
            return False
    
    

    def get_file(self):
        """
        Generates a presigned URL to access a file stored in a cloud storage bucket.

        This method checks if the `FILE_NAME` attribute is set. If it is not set, 
        the method returns `None`. If the `FILE_NAME` is set, it attempts to 
        generate a presigned URL using the cloud storage client. The presigned URL 
        allows temporary access to the file for a duration of 1 hour (3600 seconds).

        Returns:
            str: A presigned URL to access the file if successful.
            None: If the `FILE_NAME` attribute is not set or the URL generation fails.
            bool: Returns `False` if an exception occurs during URL generation.

        Raises:
            Exception: Any exception raised during the URL generation process is caught 
                       and results in returning `False`.
        """

        if not self.FILE_NAME:
            return None

        try:
            url = self.client.generate_presigned_url(
                'get_object',
                Params={'Bucket': self.BUCKET, 'Key': self.FILE_NAME},
                ExpiresIn=3600  # 1 hour
            )
            if not url:
                return None
            return url
        except Exception as e:
            return False
    

    def delete(self):
        """
        Deletes an object from the cloud storage bucket.

        This method attempts to delete an object identified by `FILE_NAME` 
        from the specified `BUCKET` using the cloud storage client. If 
        `FILE_NAME` is not set, the method returns `None`. If the deletion 
        is successful, it returns `True`. If an exception occurs during 
        the deletion process, it returns `False`.

        Returns:
            bool or None: 
                - `True` if the object is successfully deleted.
                - `False` if an exception occurs during deletion.
                - `None` if `FILE_NAME` is not set.
        """

        if not self.FILE_NAME:
            return None

        try:
            self.client.delete_object(Bucket=self.BUCKET, Key=self.FILE_NAME)
            return True
        except Exception as e:
            return False
        

    def update(self, old_filename):
        """
        Updates a file in the cloud storage by deleting the old file and uploading a new one.
        Args:
            old_filename (str): The name of the file to be replaced in the cloud storage.
        Returns:
            tuple: A tuple containing the old filename and the new filename if the operation is successful.
            None: If the old filename is not provided.
            bool: Returns False if an exception occurs during the operation.
        Raises:
            Exception: If an error occurs during the deletion or upload process.
        """
        

        if not old_filename:
            return None

        try:
            # Delete the old one first (or rename logic if you want)
            self.client.delete_object(Bucket=self.BUCKET, Key=old_filename)

            self.client.upload_fileobj(self.FILE, self.BUCKET, self.FILE.filename)

            return old_filename, self.FILE.filename

        except Exception as e:
            return False
        