'''
identifi.es flask app
'''


import json
import time
import logging

from binascii import hexlify
from base64 import urlsafe_b64encode, urlsafe_b64decode

from Crypto.PublicKey import DSA, RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

from flask import Flask, session, request, jsonify, escape
from werkzeug.contrib.fixers import ProxyFix


def sign(payload, secret_key):
    '''
    sign some data with a private key
    from jwcrypto
    '''
    if 'n' in secret_key.keydata:
        # RSA
        header = {'alg': 'RS256'}
    else:
        return
    header_string = ''.join(json.dumps(header).split(' '))
    alg_bytes = urlsafe_b64encode(header_string).strip('=')
    payload_string = ''.join(json.dumps(payload).split(' '))
    json_bytes = urlsafe_b64encode(payload_string).strip('=')

    signer = PKCS1_v1_5.new(secret_key)
    data_hash = SHA256.new(alg_bytes + '.' + json_bytes)
    signature = signer.sign(data_hash)
    signature_bytes = urlsafe_b64encode(signature).strip('=')

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
logging.basicConfig(level=logging.INFO)

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
def api_whoami():
    '''
    get current session userid
    '''
    userid = ''
    if 'userid' in session:
        userid = escape(session['userid'])
    app.logger.debug('/api/whoami --> "%s"' % {'userid': userid})
    return jsonify({'userid': userid})


@app.route('/api/certkey', methods=['POST'])
def api_certkey():
    '''
    certify the key by signing it with our private key
    '''
    certificate = ''
    app.logger.debug('/api/certkey <-- "%s"' % request.form)
    if 'pubkey' in request.form and \
            'duration' in request.form and \
            'userid' in session:
        userid = escape(session['userid'])
        pubkey = json.loads(request.form['pubkey'])
        # certificate time is in ms
        issued_at = int(time.time() * 1000)
        expires_at = issued_at + int(request.form['duration']) * 1000
        claim = {'public-key': pubkey,
                 'principal': {'email': userid},
                 'iss': ISSUER,
                 'iat': issued_at,
                 'exp': expires_at}
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
    cert_parts = certificate.split('.')
    if len(cert_parts) == 3:
        app.logger.debug('/api/certkey <-> "%s"' %
                         urlsafe_b64decode(cert_parts[0] + '=='))
        app.logger.debug('/api/certkey <-> "%s"' %
                         urlsafe_b64decode(cert_parts[1] + '=='))
        app.logger.debug('/api/certkey <-> "%s"' %
                         hexlify(urlsafe_b64decode(cert_parts[2] + '==')))
    app.logger.debug('/api/certkey --> "%s"' % {'cert': certificate})
    return jsonify({'cert': certificate})


@app.route('/api/loginasstan', methods=['POST'])
def api_loginasstan():
    '''
    log in as test user
    '''
    session['userid'] = 'stan_southpark@' + ISSUER
    return ''


@app.route('/api/logout', methods=['GET', 'POST'])
def api_logout():
    '''
    log out of session
    '''
    session.pop('userid', None)
    return ''


def debug_mode():
    '''
    main
    '''
    app.run(debug=False, port=8000)


if __name__ == '__main__':
    debug_mode()
