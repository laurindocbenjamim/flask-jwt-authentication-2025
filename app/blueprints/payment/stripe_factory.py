
import stripe
from flask import url_for

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


def stripe_simple_form():
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

def stripe_with_user_data(user_id, email):
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'usd',
                'unit_amount': 2000,
                'product_data': {
                    'name': 'Perfume',
                    'description': 'A luxurious fragrance.',
                    'images': ['https://yourdomain.com/static/images/perfume.jpg'],
                },
            },
            'quantity': 1,
        }],
        mode='payment',
        success_url='https://yourdomain.com/success?session_id={CHECKOUT_SESSION_ID}',
        cancel_url='https://yourdomain.com/cancel',
        metadata={
            'user_id': user_id,
            'product_variant': 'luxury'
        }
    )

def stripe_enable_tax():
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'eur',
                'unit_amount': 2500,
                'product_data': {
                    'name': 'Perfume',
                    'description': 'A luxurious fragrance.',
                    'images': ['https://yourdomain.com/static/images/perfume.jpg'],
                },
            },
            'quantity': 1,
        }],
        mode='payment',
        success_url='https://yourdomain.com/success?session_id={CHECKOUT_SESSION_ID}',
        cancel_url='https://yourdomain.com/cancel',
        tax_id_collection={'enabled': True}
    )


def stripe_customized_brand():
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'usd',
                'unit_amount': 2000,
                'product_data': {
                    'name': 'Perfume',
                    'description': 'A luxurious fragrance.',
                    'images': ['https://yourdomain.com/static/images/perfume.jpg'],
                },
            },
            'quantity': 1,
        }],
        mode='payment',
        success_url='https://yourdomain.com/success?session_id={CHECKOUT_SESSION_ID}',
        cancel_url='https://yourdomain.com/cancel',
        payment_intent_data={
            'metadata': {'order_id': '6735'}
        },
        payment_method_types=['card'],
        shipping_address_collection={'allowed_countries': ['US', 'CA']},
        phone_number_collection={'enabled': True},
        customer_email='customer@example.com',  # Optional: Pre-fill customer email
        customer_creation='always',  # Optional: Create a new customer object
        metadata={
            'user_id': '12345',
            'product_variant': 'luxury'
        }
    )
