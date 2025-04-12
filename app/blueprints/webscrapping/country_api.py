
import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

from flask_restful import Api, Resource, reqparse
from app.utils import db
from app.models import User, TokenBlocklist, TokenBlocklist2

from flask import (
    Blueprint, jsonify,
    make_response,request, current_app
)

from datetime import datetime
from datetime import timedelta
from datetime import timezone

from sqlalchemy.sql import func
from app.blueprints.webscrapping.extract_countries_data import extract_countries


class CountryApi(Resource):
    def get(self, country_name=None):
        phonenumberULR = (
            "https://worldpopulationreview.com/country-rankings/phone-number-length-by-country"
        )
        with_length = "https://www.iban.com/dialing-codes"
        url = "https://countrycode.org/"

        web_font=with_length
        df = extract_countries(web_font)
        #serialized_data = df.to_json(orient='records', date_format='iso')
        data = []

        if not country_name:
            for i, row in df.iterrows():
                data.append(dict(row))
        else:
            data = df.loc[df['Country'] == country_name].to_dict('records')
        
        return jsonify({"EXTRACTED_FROM": web_font, "ELEMENTS_or_SIZE": len(data),  "OBJECTS":  data })
        