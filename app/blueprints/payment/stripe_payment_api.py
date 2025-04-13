


import os
import stripe


import sys
import os

sys.path.append(os.path.abspath("flask-jwt-authentication-2025"))

from flask_restful import Api, Resource, reqparse, url_for, current_app
from app.utils import admin_required, upload_file

from app.utils import PdfReaderFactory
from app.utils import DocxFileFactory
from app.utils import MyGeneralFileFactory
from app.utils import handle_ai_response_json
from app.utils import db

from flask import jsonify, make_response
from flask_jwt_extended import (
    jwt_required,
    current_user,
    get_jwt
)
from datetime import datetime
from ...models.paymentModel import PaymentModel

class StripePaymentApi(Resource):

    public_key = None

    def __init__(self):
        stripe.api_key = current_app.config['STRIPE_SECRET_KEY']
    
    def get(self):
        try:
            self.public_key = current_app.config['STRIPE_PK']

            if not self.public_key:
                return None
            return self.public_key
        except KeyError as e:
            current_app.logger.error(f"Missing configuration key: {e}")
            return None #make_response(jsonify({"error": "Configuration key missing"}), 500)
        except Exception as e:
            current_app.logger.error(f"An unexpected error occurred: {e}")
            return None # make_response(jsonify({"error": "An unexpected error occurred"}), 500)
    

    def post(self):
        # Define supported currencies with their respective countries
        currencies = {
            'usd': 'United States',
            'eur': 'European Union',
            'aoa': 'Angola',
            'brl': 'Brazil',
            'jpy': 'Japan',
            'gbp': 'United Kingdom'
        }

        # Define product details
        products = [
            {
                'name': 'Perfume: EBONY WOOD EDP 100 ML (3.4 FL.OZ).',
                'description': 'A luxurious fragrance with notes of jasmine and sandalwood.',
                'image': 'https://static.zara.net/assets/public/282c/99c4/72d64c7fb1ad/5dac6403b3b6/20110671999-e1/20110671999-e1.jpg?ts=1730996811877&w=750',
                'amounts': {
                    'usd': 100  # Amounts are in the smallest currency unit (e.g., cents)
                    
                }
            }
        ]

        # Example: Selecting currency and product
        selected_currency = 'usd'  # This can be dynamically set based on user preference
        selected_product = products[0]

        try:
            # Create a new Checkout Session
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': selected_currency,
                        'product_data': {
                            'name': selected_product['name'],
                            'description': selected_product['description'],
                            'images': [selected_product['image']]
                        },
                        'unit_amount': selected_product['amounts'][selected_currency],
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=url_for('payment_app.payment_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=url_for('payment_app.payment_cancel', _external=True),
            )

            # Record the payment session in your database
            payment = PaymentModel(
                session_id=session.id,
                amount=selected_product['amounts'][selected_currency],
                currency=selected_currency,
                status='created'
            )
            db.session.add(payment)
            db.session.commit()

            # Return the session ID to the frontend
            return jsonify(id=session.id)

        except Exception as e:
            return jsonify(error=str(e))

    """def post(self):
        
        payment_method = ['card']
        currencies = ['usd', 'eur', 'aoa', 'brl', 'jpy', 'gbp']
        products = ['Perfume']
        amount = [100, 2000, 20, 30, 50]

        try:
            session = stripe.checkout.Session.create(
                payment_method_types=[payment_method[0]],
                line_items=[
                    {
                        'price_data': {
                            'currency': currencies[1],
                            'product_data': {
                                'name': products[0]
                            },
                            'unit_amount': amount[0],  # Amount in cents
                        },
                        'quantity':1,
                    }
                ],
                mode='payment',
                success_url=url_for('payment_app.payment_success', _external=True)+'?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=url_for('payment_app.payment_cancel', _external=True),
            )

            payment = PaymentModel(session_id=session.id, amount=amount[1], currency=currencies[0], status='created')
            db.session.add(payment)
            db.session.commit()

            #return make_response(jsonify(id=session.id), 200)
            return jsonify(id=session.id)

        except Exception as e:
            return jsonify(error=str(e))"""
    



    