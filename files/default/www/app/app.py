'''
identifi.es flask app for the api
'''


import json
import base64
import time
import logging

from Crypto.PublicKey import DSA, RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

from flask import Flask, session, request
from werkzeug.contrib.fixers import ProxyFix


def sign(payload, secret_key):
    '''
    sign some data with a private key
    from jwcrypto
    '''
    if 'n' in secret_key.keydata:
        # RSA
        header = {'algorithm': 'RS'}
    elif 'q' in secret_key.keydata:
        # DSA
        header = {'algorithm': 'DS'}
    alg_bytes = base64.urlsafe_b64encode(json.dumps(header))
    json_bytes = base64.urlsafe_b64encode(json.dumps(payload))

    signer = PKCS1_v1_5.new(secret_key)
    data_hash = SHA.new(alg_bytes + '.' + json_bytes)
    signature = signer.sign(data_hash)
    signature_bytes = base64.urlsafe_b64encode(signature)

    return alg_bytes + '.' + json_bytes + '.' + signature_bytes


def load_json_key(key_json, base):
    '''
    load a json private key into a DSA or RSA object
    '''
    key = None
    if key_json['algorithm'] == 'DS':
        tup = [int(key_json['y'], base),
               int(key_json['g'], base),
               int(key_json['p'], base),
               int(key_json['q'], base)]
        if 'x' in key_json:
            tup.append(int(key_json['x'], base))
        key = DSA.construct(tup)
    elif key_json['algorithm'] == 'RS':
        tup = [long(key_json['n'], base),
               long(key_json['e'], base)]
        if 'd' in key_json:
            tup.append(int(key_json['d'], base))
        key = RSA.construct(tup)
    return key


# pylint: disable-msg=C0103
app = Flask(__name__)
# pylint: enable-msg=C0103
app.wsgi_app = ProxyFix(app.wsgi_app)
logging.basicConfig(level=logging.DEBUG)

# 192 bit key file for session
with open('session.key') as session_keyfile:
    app.secret_key = session_keyfile.read()

# 256 RSA key file for browserid verification
# use node.js jwcrypto $generate-keypair -a rsa -k 256
with open('browserid.key') as browserid_keyfile:
    BROWSERID_PRIVATEKEY = load_json_key(json.loads(browserid_keyfile.read()),
                                         10)

ISSUER = 'identifi.es'


@app.route('/api/whoami', methods=['GET'])
def whoami():
    '''
    get current session userid
    '''
    userid = ''
    if 'userid' in session:
        userid = session['userid']
    app.logger.debug('/api/whoami -> "%s"' % userid)
    return userid


@app.route('/api/cert_key', methods=['POST'])
def cert_key():
    '''
    certify the key by signing it with our private key
    '''
    certificate = {}
    app.logger.debug(request.headers)
    app.logger.debug('/api/cert_key <- "%s"' % request.form)
    if 'pubkey' in request.form and \
            'duration' in request.form and \
            'userid' in session:
        userid = session['userid']
        pubkey = json.loads(request.form['pubkey'])
        issued_at = int(time.time())
        expires_at = issued_at + int(request.form['duration'])
        claim = {'public-key': pubkey,
                 'principal': {'email': userid},
                 'issuer': ISSUER,
                 'issuedat': issued_at,
                 'expiresat': expires_at}
        app.logger.debug(claim)
        certificate = sign(claim, BROWSERID_PRIVATEKEY)
    else:
        app.logger.warning('invalid request')
        if not 'pubkey' in request.form:
            app.logger.debug('missing pubkey')
            app.logger.debug(request.form['pubkey[algorithm]'])
        if not 'duration' in request.form:
            app.logger.debug('missing duration')
        if not 'userid' in session:
            app.logger.debug('missing userid')
    app.logger.debug('/api/cert_key -> "%s"' % certificate)
    return certificate


@app.route('/api/loginasstan', methods=['GET', 'POST'])
def loginasstan():
    '''
    log in as test user

    GET and POST so its easy to call from a webbrowser
    '''
    session['userid'] = 'stan_southpark@' + ISSUER
    return ''


@app.route('/api/logout', methods=['GET', 'POST'])
def logout():
    '''
    log out of session

    GET and POST so its easy to call from a webbrowser
    '''
    session.pop('userid', None)
    return ''


@app.route('/api/log', methods=['POST'])
def log():
    '''
    server side log
    '''
    if 'log' in request.form:
        app.logger.debug('<remote> ' + request.form['log'])
    return ''


def debug_mode():
    '''
    main
    '''
    app.run(debug=False, port=8000)


if __name__ == '__main__':
    debug_mode()
