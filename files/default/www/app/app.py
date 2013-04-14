from flask import Flask, render_template_string

from werkzeug.contrib.fixers import ProxyFix


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)


@app.route('/api/<cmd>', methods=['GET'])
def api_get(cmd):
    if cmd == "whoami":
        return "stan+southpark@identifi.es"

@app.route('/api/<cmd>', methods=['POST'])
def api_post(cmd):
    if cmd == "cert_key":
        return
