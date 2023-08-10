import os
import re
from datetime import datetime, timedelta, timezone
from logging.config import dictConfig

import jwt
from flask import Flask, Response, abort, make_response, request

JWT_SECRET = os.getenv('BREWBLOX_AUTH_JWT_SECRET')
VERIFY_IGNORE = os.getenv('BREWBLOX_AUTH_VERIFY_IGNORE', '')

VERIFY_IGNORE_EXP = re.compile(VERIFY_IGNORE.replace(',', '|'))
VALID_DURATION = timedelta(hours=1)


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


def make_token_response(username: str) -> Response:
    expires = datetime.now(tz=timezone.utc) + VALID_DURATION
    token = jwt.encode(
        {
            'username': username,
            'exp': int(expires.timestamp()),
        },
        JWT_SECRET)
    resp = make_response(token)
    resp.set_cookie('Authorization',
                    token,
                    expires=expires,
                    secure=True)

    return resp


@app.route('/auth/verify')
def verify():
    method = request.headers.get('X-Forwarded-Method', '')
    uri = request.headers.get('X-Forwarded-Uri', '')

    # Some requests should not be checked
    # These include:
    # - CORS preflight requests. The actual request will be checked.
    # - Requests to this service.
    # - Requests to endpoints marked as ignored by configuration.
    if method == 'OPTIONS' \
        or uri.startswith('/auth/') \
            or re.fullmatch(VERIFY_IGNORE_EXP, uri):
        app.logger.info(f'skip: {uri}')
        return ''

    token = request.cookies.get('Authorization')
    if not token:
        app.logger.warning(f'no token: {uri} \n{request.headers}')
        abort(401)

    try:
        jwt.decode(token.encode(), JWT_SECRET, algorithms=['HS256'])
        app.logger.info(f'pass: {uri}')
        return ''
    except (jwt.DecodeError, jwt.ExpiredSignatureError) as ex:
        app.logger.warning(f'fail: {uri} \n{ex}\n{request.headers}')
        abort(401)


@app.route('/auth/refresh')
def refresh():
    token = request.cookies.get('Authorization')
    if not token:
        app.logger.warning(f'No token! \n{request.headers}')
        abort(401)

    try:
        decoded = jwt.decode(token.encode(), JWT_SECRET, algorithms=['HS256'])
        username = decoded['username']
        app.logger.info(f'refresh: {username}')
        return make_token_response(username)
    except (jwt.DecodeError, jwt.ExpiredSignatureError) as ex:
        app.logger.warning(str(ex))
        abort(401)


@app.route('/auth/login', methods=['POST'])
def login():
    args = request.get_json()

    username = args.get('username')
    password = args.get('password')

    # TODO: actual implementation
    if username != 'username' or password != 'password':
        abort(401)

    app.logger.info(f'login: {username}')
    return make_token_response(username)
