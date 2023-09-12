import os
import re
from datetime import datetime, timedelta, timezone
from logging.config import dictConfig
from pathlib import Path

import jwt
from flask import Flask, Response, abort, jsonify, make_response, request
from passlib.hash import pbkdf2_sha512

from .utils import strtobool

AUTH_ENABLED = strtobool(os.getenv('BREWBLOX_AUTH_ENABLED', 'True'))
AUTH_IGNORE = re.compile(os.getenv('BREWBLOX_AUTH_IGNORE', ''))
AUTH_JWT_SECRET = os.getenv('BREWBLOX_AUTH_JWT_SECRET')
AUTH_PASSWD_FILE = Path(os.getenv('BREWBLOX_AUTH_PASSWD_FILE')).resolve()

COOKIE_NAME = 'Authorization'
VALID_DURATION = timedelta(days=7)


dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

app = Flask(__name__)


def read_users():
    try:
        return app.config['users']
    except KeyError:
        with open(AUTH_PASSWD_FILE) as f:
            users = {
                name: hashed
                for (name, hashed)
                in [line.strip().split(':', 1)
                    for line in f.readlines()
                    if ':' in line]
            }

        app.config['users'] = users
        return users


def make_token_response(username: str) -> Response:
    expires = datetime.now(tz=timezone.utc) + VALID_DURATION
    token = jwt.encode(
        {
            'username': username,
            'exp': int(expires.timestamp()),
        },
        AUTH_JWT_SECRET)
    resp = jsonify(username=username,
                   token=token,
                   enabled=AUTH_ENABLED)
    resp.set_cookie('Authorization',
                    token,
                    expires=expires,
                    secure=True)

    return resp


@app.route('/auth/verify')
def verify():
    method = request.headers.get('X-Forwarded-Method', '')
    uri = request.headers.get('X-Forwarded-Uri', '')

    if not AUTH_ENABLED:
        return ''

    # Some requests should not be checked
    # These include:
    # - CORS preflight requests. The actual request will be checked.
    # - Requests to this service.
    # - Requests to endpoints marked as ignored by configuration.
    if method == 'OPTIONS' \
        or uri.startswith('/auth/') \
            or re.fullmatch(AUTH_IGNORE, uri):
        return ''

    token = request.cookies.get(COOKIE_NAME)
    if not token:
        abort(401)

    try:
        jwt.decode(token.encode(), AUTH_JWT_SECRET, algorithms=['HS256'])
        return ''
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        abort(401)


@app.route('/auth/login', methods=['POST'])
def login():
    args = request.get_json()

    username = args.get('username')
    password = args.get('password')
    stored = read_users().get(username)

    # User does not exist
    if stored is None:
        abort(401)

    # Password does not match
    if not pbkdf2_sha512.verify(password, stored):
        abort(401)

    return make_token_response(username)


@app.route('/auth/refresh')
def refresh():
    if not AUTH_ENABLED:
        return jsonify(username=None,
                       token=None,
                       enable=AUTH_ENABLED)

    token = request.cookies.get(COOKIE_NAME)
    if not token:
        abort(401)

    try:
        decoded = jwt.decode(token.encode(), AUTH_JWT_SECRET, algorithms=['HS256'])
        username = decoded['username']

        # Check if user is still listed
        if username not in read_users():
            abort(401)

        return make_token_response(username)
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        abort(401)


@app.route('/auth/logout')
def logout():
    resp = make_response('')
    resp.delete_cookie(COOKIE_NAME, secure=True)
    return resp
