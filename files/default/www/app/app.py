'''
identifi.es flask app for the api
'''

from flask import Flask
from werkzeug.contrib.fixers import ProxyFix


# pylint: disable-msg=C0103
app = Flask(__name__)
# pylint: enable-msg=C0103
app.wsgi_app = ProxyFix(app.wsgi_app)


@app.route('/api/<cmd>', methods=['GET'])
def api_get(cmd):
    '''
    api GETs
    '''
    if cmd == "whoami":
        return "stan+southpark@identifi.es"


@app.route('/api/<cmd>', methods=['POST'])
def api_post(cmd):
    '''
    api POSTs
    '''
    if cmd == "cert_key":
        return
