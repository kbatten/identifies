from flask import Flask, render_template_string

from werkzeug.contrib.fixers import ProxyFix


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)


@app.route('/browserid/sign_in.html')
def sign_in():
    return render_template_string('<h1>signin</h1>')

@app.route('/browserid/provision.html')
def provision():
    return render_template_string('<h1>provision</h1>')
