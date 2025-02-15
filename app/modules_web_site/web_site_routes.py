from flask import Blueprint, render_template, make_response, jsonify, url_for
from markupsafe import escape

web_site_app = Blueprint("web_site", __name__)

@web_site_app.route('/about-us')
def about_us():
    welcome_title = "Welcome to Data Tuning"
    welcome_message = "Empowering learners with cutting-edge online education"
    response = make_response(render_template('about.html', title='About Us', welcome_title=welcome_title,  welcome_message=welcome_message))
    return response

@web_site_app.route('/contact-us')
def contact_us():
    welcome_title = "Welcome to Data Tuning"
    welcome_message = "Empowering learners with cutting-edge online education"
    response = make_response(render_template('contact.html', title='Contact Us', welcome_title=welcome_title,  welcome_message=welcome_message))
    return response

@web_site_app.route('/courses')
def courses():
    welcome_title = "Welcome to Data Tuning"
    welcome_message = "Empowering learners with cutting-edge online education"
    response = make_response(render_template('contact.html', title='Courses', welcome_title=welcome_title,  welcome_message=welcome_message))
    return response