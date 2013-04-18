'''
identifi.es flask app
'''


import json
import time
import logging

from binascii import unhexlify
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


def getrandbytes(k):
    '''
    get an ascii string of randbits
    '''
    bits = getrandbits(k * 8)
    hex_bits = hex(bits)[2:].strip('L')
    if len(hex_bits) % 2 == 1:
        hex_bits = '0' + hex_bits
    return unhexlify(hex_bits)


###############################
# TOQU: save this stuff to a DB
app.users = {}
try:
    with open('users.json') as users_jsonfile:
        app.users = json.loads(users_jsonfile.read())
except IOError:
    pass
except ValueError:
    pass
###############################


def hash_password(salt, password):
    '''
    salt and hash the password
    '''
    saltpass = "".join([chr(ord(c)) for c in salt] +
                       [chr(ord(c)) for c in password])
    return SHA256.new(saltpass).digest()


def get_user(email):
    '''
    retrieve a user dict based on an email
    '''
    if not email:
        return False
    userid = email.split('@')[0].split('+')[0]

    user = {}
    if userid in app.users:
        user = {'userid': userid, 'email': email}
        user.update(app.users[userid])
    return user


def create_user(email, password):
    '''
    create a new user
    '''
    if not email:
        return False
    userid = email.split('@')[0].split('+')[0]

    salt = getrandbytes(32)
    salt_encode = urlsafe_b64encode(salt)
    passhash = hash_password(salt, password)
    passhash_encode = urlsafe_b64encode(passhash)
    app.users[userid] = {'salt': salt_encode, 'passhash': passhash_encode}

    user = {
        'salt': salt_encode,
        'passhash': passhash_encode,
        'email': email,
        'userid': userid}

###############################
# TOQU: save this stuff to a DB
    with open('users.json', 'w+') as users_jsonfile_w:
        users_jsonfile_w.write(json.dumps(app.users))
###############################

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
        user = create_user(email, password)

    salt = urlsafe_b64decode(user['salt'].encode('ascii'))
    pw1_hash = urlsafe_b64decode(user['passhash'].encode('ascii'))
    pw2_hash = hash_password(salt, password)

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
    email = session.pop('email', '')
    exp = int(session.pop('exp', 0))
    token = session.pop('token', '')
    if exp < int(time.time()):
        # login session expired
        return '', 401
    request_token = escape(request.form.get('token', ''))
    if not request_token or token != request_token:
        # mismatch token
        app.logger.info('mismatch token: %s' % email)
        return '', 401
    request_email = escape(request.form.get('email', ''))
    if not get_user(email) or email != request_email:
        # no user logged in
        # or user not found
        # or current logged in email is not who made the request
        app.logger.debug('no valid user: %s, %s' % (email, request_email))
        return '', 401
    certificate = ''
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
            app.logger.debug('missing pubkey: %s' % email)
            app.logger.debug(request.form['pubkey[algorithm]'])
        if not 'duration' in request.form:
            app.logger.debug('missing duration: %s' % email)
    return jsonify({'cert': certificate})


@app.route('/api/login', methods=['POST'])
def api_login():
    '''
    log in as user
    '''
    email = escape(request.form.get('email', ''))
    password = escape(request.form.get('password', ''))

    if verify_or_create_user(email, password):
        session['email'] = email
        session['exp'] = int(time.time()) + LOGIN_EXPIRATION
        session['token'] = urlsafe_b64encode(getrandbytes(32))
        return jsonify({'token': session['token']})
    return '', 401


@app.route('/browserid/provision.html')
def browserid_provision():
    '''
    provision needs the token
    '''
    token = session.get('token', '')
    return render_template('provision.html', token=token)


def debug_mode():
    '''
    main
    '''
    app.run(debug=False, port=8000)


if __name__ == '__main__':
    debug_mode()
