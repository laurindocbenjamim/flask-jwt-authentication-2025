
from flask import render_template, redirect
from flask.views import View

class AuthorProfileView(View):
    methods=['GET']

    def __init__(self, template) -> None:
        self._template = template

    def dispatch_request(self):
        return render_template(self._template, title="About me")