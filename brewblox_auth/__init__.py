from datetime import datetime, timedelta, timezone
from logging.config import dictConfig

import jwt
from flask import Flask, abort, request
from flask_cors import CORS

JWT_SECRET_KEY = 'JWT secret key'
VALIDITY = timedelta(seconds=1800)

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
CORS(app)


@app.route('/auth/verify')
def verify():
    protocol = request.headers.get('X-Forwarded-Proto')
    method = request.headers.get('X-Forwarded-Method')

    # Authentication is not supported for HTTP
    # Local requests are trusted by default
    if protocol == 'http':
        return ''

    # Always forward the preflight request
    # We'll check the actual request anyway
    if method == 'OPTIONS':
        return ''

    token = request.headers.get('Authorization')
    if not token:
        abort(401)

    try:
        decoded = jwt.decode(token.encode(), JWT_SECRET_KEY, algorithms=['HS256'])
        app.logger.info(decoded)
        return ''
    except jwt.DecodeError as ex:
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

    expires = datetime.now(tz=timezone.utc) + VALIDITY
    token = jwt.encode(
        {
            'username': username,
            'exp': int(expires.timestamp()),
        },
        JWT_SECRET_KEY)

    return token
