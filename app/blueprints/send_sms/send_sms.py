# app.py
import random
from flask import Flask, render_template, request, session, redirect, url_for
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_here' # Replace with a strong, random secret key for production

# In a real application, you would use a database or a more persistent cache
# to store codes, potentially with user IDs.
# For simplicity, we'll use a dictionary: {phone_number: {'code': '...', 'timestamp': '...'}}
confirmation_codes = {}

@app.route('/')
def index():
    """Renders the main page where the user can request an SMS code."""
    return render_template('index.html')

@app.route('/send_code', methods=['POST'])
def send_code():
    """
    Handles the request to send a confirmation code.
    Generates a code, stores it, and simulates sending an SMS.
    """
    phone_number = request.form['phone_number']

    if not phone_number:
        # Basic validation
        return render_template('index.html', error="Please enter a phone number.")

    # Generate a 6-digit random code
    code = str(random.randint(100000, 999999))
    # Store the code with a timestamp for expiration (e.g., 5 minutes)
    confirmation_codes[phone_number] = {
        'code': code,
        'timestamp': datetime.now() + timedelta(minutes=5) # Code expires in 5 minutes
    }
    session['phone_number'] = phone_number # Store phone number in session for verification

    # --- SMS Sending Simulation ---
    print(f"--- SIMULATING SMS SEND ---")
    print(f"To: {phone_number}")
    print(f"Code: {code}")
    print(f"--- END SMS SIMULATION ---")
    # In a real app, you would integrate with an SMS API here (e.g., Twilio)
    # try:
    #     client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    #     message = client.messages.create(
    #         to=phone_number,
    #         from_=TWILIO_PHONE_NUMBER, # Your Twilio number
    #         body=f"Your confirmation code is: {code}"
    #     )
    #     print(f"SMS sent successfully! SID: {message.sid}")
    # except Exception as e:
    #     print(f"Error sending SMS: {e}")
    #     return render_template('index.html', error="Failed to send SMS. Please try again.")

    return render_template('index.html', success=f"Confirmation code sent to {phone_number}! (Simulated: Check console for code)", show_verify_form=True)

@app.route('/verify_code', methods=['POST'])
def verify_code():
    """
    Verifies the confirmation code entered by the user.
    """
    user_entered_code = request.form['confirmation_code']
    phone_number = session.get('phone_number') # Get phone number from session

    if not phone_number:
        return redirect(url_for('index', error="No phone number in session. Please request a new code."))

    stored_data = confirmation_codes.get(phone_number)

    if stored_data:
        stored_code = stored_data['code']
        expiration_time = stored_data['timestamp']

        if datetime.now() > expiration_time:
            # Code expired
            del confirmation_codes[phone_number] # Remove expired code
            return render_template('index.html', error="The confirmation code has expired. Please request a new one.", show_verify_form=True)

        if user_entered_code == stored_code:
            # Code matched and is not expired
            del confirmation_codes[phone_number] # Invalidate code after successful use
            session.pop('phone_number', None) # Clear phone number from session
            return render_template('index.html', success="Phone number successfully verified!", verification_complete=True)
        else:
            # Code did not match
            return render_template('index.html', error="Invalid confirmation code. Please try again.", show_verify_form=True)
    else:
        # No code stored for this phone number
        return render_template('index.html', error="No pending confirmation code for this number. Please request a new one.", show_verify_form=True)

if __name__ == '__main__':
    # To run: Save this as app.py, install flask (`pip install flask`), then run `python app.py`
    # Ensure you have a 'templates' folder in the same directory as app.py
    # and put the 'index.html' file inside it.
    app.run(debug=True) # debug=True allows automatic reloading and provides detailed error messages
