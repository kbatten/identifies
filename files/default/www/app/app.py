'''
identifi.es flask app
'''


import json
import time
import logging

from binascii import hexlify
from base64 import urlsafe_b64encode, urlsafe_b64decode

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Random.random import getrandbits

from flask import Flask, request, jsonify, escape, session, render_template
from werkzeug.contrib.fixers import ProxyFix


def load_json_key(key_json, base):
    '''
    load a json private key into an RSA object
    format is from jwcrypto - generate_keypair
    '''
    key = None
    if key_json['algorithm'] == 'RS':
        tup = [long(key_json['n'], base),
               long(key_json['e'], base)]
        if 'd' in key_json:
            tup.append(int(key_json['d'], base))
        key = RSA.construct(tup)
    return key


ISSUER = 'identifi.es'

logging.basicConfig(level=logging.DEBUG)
# pylint: disable-msg=C0103
app = Flask(__name__)
# pylint: enable-msg=C0103
app.wsgi_app = ProxyFix(app.wsgi_app)

# 192 bit key file for session
with open('session.key') as session_keyfile:
    SESSION_PRIVATEKEY_RAW = session_keyfile.read()
app.secret_key = SESSION_PRIVATEKEY_RAW

# 256 RSA key file for browserid verification
# use node.js jwcrypto $generate-keypair -a rsa -k 256
with open('browserid.key') as browserid_keyfile:
    BROWSERID_PRIVATEKEY_RAW = browserid_keyfile.read()
BROWSERID_PRIVATEKEY = load_json_key(json.loads(BROWSERID_PRIVATEKEY_RAW), 10)

# 256 RSA key file for anti-forgery tokens
with open('token.key') as token_keyfile:
    TOKEN_PRIVATEKEY_RAW = token_keyfile.read()
TOKEN_PRIVATEKEY = load_json_key(json.loads(TOKEN_PRIVATEKEY_RAW), 10)
TOKEN_EXPIRATION_MS = 10 * 1000  # 10s

LOGIN_EXPIRATION = 60


def getrandbits_str(k):
    '''
    get a string of randbits
    '''
    bits = getrandbits(k)
    hex_bits = hex(bits)[2:].strip('L')
    if len(hex_bits) % 2 == 1:
        hex_bits = '0' + hex_bits
    return hex_bits.decode('hex')


def get_user(email):
    '''
    retrieve a user dict based on an email
    '''
    if not email:
        return False
    userid = email.split('@')[0].split('+')[0]
    user = {'userid': userid, 'email': email}

    app.logger.debug(user)

    if userid == 'stan':
        user.update({'salt': getrandbits_str(256)})
        user.update({'passhash': SHA256.new(user['salt'] +
                                            'w'.encode('utf-8'))})
    elif userid == 'kyle':
        user.update({'salt': getrandbits_str(256)})
        user.update({'passhash': SHA256.new(user['salt'] +
                                            '1234'.encode('utf-8'))})
    elif userid == 'cartman':
        user.update({'salt': getrandbits_str(256)})
        user.update({'passhash': SHA256.new(user['salt'] +
                                            'q'.encode('utf-8'))})
    else:
        user = {}

    return user


def verify_or_create_user(email, password):
    '''
    if user exists, verify the password
    if user doesn't exist, create with password
    '''
    if not email or not password:
        return False

    user = get_user(email)
    if not user:
        return False

    pw1_hash = user['passhash'].digest()
    pw2_hash = SHA256.new(user['salt'] + password.encode('utf-8')).digest()

    return pw1_hash == pw2_hash


def jwcrypto_sign_json(payload, secret_key):
    '''
    sign some json data with a private key
    outputs b64 encoded (plus "."s)
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


def token_required(key, exp):
    '''stub '''
    key = key
    exp = exp

    def decorator(fun):
        '''stub '''
        return fun
    return decorator


@app.route('/api/certkey', methods=['POST'])
@token_required(TOKEN_PRIVATEKEY, TOKEN_EXPIRATION_MS)
def api_certkey():
    '''
    certify the key by signing it with our private key
    '''
   # pop the email, its only good for one cert request
    email = session.pop('email', None)
    exp = int(session.pop('exp', 0))
    token = session.pop('token', None)
    if exp < int(time.time()):
        # login session expired
        app.logger.debug('login session expired')
        return '', 401
    request_token = escape(request.form.get('token', None))
    if not request_token or token != request_token:
        # mismatch token
        app.logger.debug('mismatch token %s != %s' % (request_token, token))
        return '', 401
    request_email = escape(request.form.get('email', None))
    if not get_user(email) or email != request_email:
        # no user logged in
        # or user not found
        # or current logged in email is not who made the request
        app.logger.debug('no valid user found')
        return '', 401
    certificate = ''
    app.logger.debug('/api/certkey <-- "%s"' % request.form)
    if 'pubkey' in request.form and 'duration' in request.form:
        pubkey = json.loads(request.form['pubkey'])
        # certificate time is in ms
        issued_at = int(time.time() * 1000)
        duration = int(request.form['duration'])
        # max cert duration of one hour
        if duration < 0 or duration > 3600:
            return '', 400
        expires_at = issued_at + duration * 1000
        claim = {'public-key': pubkey,
                 'principal': {'email': email},
                 'iss': ISSUER,
                 'iat': issued_at,
                 'exp': expires_at}
        certificate = jwcrypto_sign_json(claim, BROWSERID_PRIVATEKEY)
    else:
        app.logger.warning('invalid request')
        if not 'pubkey' in request.form:
            app.logger.debug('missing pubkey')
            app.logger.debug(request.form['pubkey[algorithm]'])
        if not 'duration' in request.form:
            app.logger.debug('missing duration')
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


@app.route('/api/login', methods=['POST'])
def api_login():
    '''
    log in as user
    '''
    email = escape(request.form.get('email', None))
    password = escape(request.form.get('password', None))

    app.logger.debug({'email': email, 'password': password})

    if verify_or_create_user(email, password):
        session['email'] = email
        session['exp'] = int(time.time()) + LOGIN_EXPIRATION
        session['token'] = urlsafe_b64encode(getrandbits_str(256))
        return jsonify({'token': session['token']})

    app.logger.debug('password mismatch for email: %s' % email)
    return '', 401


@app.route('/browserid/provision.html')
def browserid_provision():
    '''
    provision needs the token
    '''
    token = session.get('token', None)
    return render_template('provision.html', token=token)


def debug_mode():
    '''
    main
    '''
    app.run(debug=False, port=8000)


if __name__ == '__main__':
    debug_mode()
