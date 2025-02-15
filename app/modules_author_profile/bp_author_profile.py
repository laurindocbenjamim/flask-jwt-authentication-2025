
from flask import Blueprint,  render_template, redirect, jsonify
from flask_cors import cross_origin

bp_author = Blueprint('profile', __name__, url_prefix='/profile')


@bp_author.route('/laurindo-c-benjamim/projects')
@cross_origin(methods=['GET'])
def author_projects():
    return render_template('author_profile/projects.html', title="Projects")

@bp_author.route('/laurindo-c-benjamim/experiences')
@cross_origin(methods=['GET'])
def author_experiences():
    return render_template('author_profile/experiences.html', title="Experiences")

from .author_profile_view import AuthorProfileView

bp_author.add_url_rule("/laurindo-c-benjamim", view_func=AuthorProfileView.as_view('laurindo_c_benjamim', 'author_profile/about.html'))