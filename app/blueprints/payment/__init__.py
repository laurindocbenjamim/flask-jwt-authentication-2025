
import os
from flask import Blueprint, request, current_app, render_template, make_response, jsonify
from flask_restful import Api
import stripe
from ...models.paymentModel import PaymentModel
from .stripe_payment_api import StripePaymentApi
from flask_cors import cross_origin
from app.utils import db

payment_bp_api = Blueprint("payment_app", __name__, url_prefix="/api/v1/pay/")
api = Api(payment_bp_api)


api.add_resource(StripePaymentApi,'/stripe')


@payment_bp_api.route('/success', methods=['GET'])
#@cross_origin(methods=['GET'])
def payment_success():

    stripe.api_key = current_app.config['STRIPE_SECRET_KEY']

    session_id = request.args.get('session_id')
   
    session = stripe.checkout.Session.retrieve(session_id)

    payment = PaymentModel.query.filter(PaymentModel.session_id == session_id).first()
    if not payment:
        #return make_response(jsonify(error=f"No payment found"), 404)
        message_type = 'danger'
        return make_response(render_template('payment_status.html', title="Failed", message='No payment found', message_type='danger'))
    if session.payment_status == 'paid':
        payment.update(session_id=session_id, status='paid')
        #return make_response(jsonify(message="Payment created successfull!"), 200)
        return make_response(render_template('payment_status.html', title="Success", message='Payment created successfull!', message_type='success'), 200)
    #return make_response(jsonify(message="Failed to create payment!"), 403)
    return make_response(render_template('payment_status.html', title="Failed", message="Failed to create payment!", message_type='danger'), 403)

@payment_bp_api.route('/cancel', methods=['GET'])
#@cross_origin(methods=['GET'])
def payment_cancel():
    #return make_response(jsonify(message="Payment canceled successfull!"), 200)
    return make_response(render_template('payment_status.html', title="Canceled", message="Payment canceled successfull!", message_type='warning'), 403)
    

