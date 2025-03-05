# Install dependencies as needed:
# pip install kagglehub[pandas-datasets]
import kagglehub
from kagglehub import KaggleDatasetAdapter

import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

from flask_restful import Resource
from app.configs import db

from flask import (jsonify,
    make_response,request, current_app
)

from datetime import datetime
from datetime import timedelta
from datetime import timezone
from flask_jwt_extended import jwt_required
    
from sqlalchemy.sql import func

class LoadDatasetsFromKaggle(Resource):
    @jwt_required(verify_type=False)
    def get(self):

        try:
           
          # Set the path to the file you'd like to load
          file_path = ""

          # Load the latest version
          df = kagglehub.load_dataset(
            KaggleDatasetAdapter.PANDAS,
            "karkavelrajaj/amazon-sales-dataset",
            file_path,
            # Provide any additional arguments like 
            # sql_query or pandas_kwargs. See the 
            # documenation for more information:
            # https://github.com/Kaggle/kagglehub/blob/main/README.md#kaggledatasetadapterpandas
          )

          response = jsonify(msg="Dataset loaded successfully", data=df, head=df.head())
        except Exception as e:
            return jsonify(error=str(e))        
        
        #unset_jwt_cookies(response)
        return make_response(response, 200)
 


