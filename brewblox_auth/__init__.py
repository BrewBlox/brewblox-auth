import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

import jwt
from fastapi import Cookie, FastAPI, Header, HTTPException, Request, Response
from passlib.hash import pbkdf2_sha512
from pydantic import BaseModel

from .utils import strtobool

AUTH_ENABLED = strtobool(os.getenv('BREWBLOX_AUTH_ENABLED', 'True'))
AUTH_IGNORE = re.compile(os.getenv('BREWBLOX_AUTH_IGNORE', ''))
AUTH_JWT_SECRET = os.getenv('BREWBLOX_AUTH_JWT_SECRET')
AUTH_PASSWD_FILE = Path(os.getenv('BREWBLOX_AUTH_PASSWD_FILE')).resolve()

COOKIE_NAME = 'Authorization'
VALID_DURATION = timedelta(days=7)


class LoginData(BaseModel):
    username: str
    password: str


class JwtData(BaseModel):
    username: str | None
    token: str | None
    expires: datetime | None
    enabled: bool


app = FastAPI(docs_url='/auth/api/doc',
              redoc_url='/auth/api/redoc',
              openapi_url='/auth/openapi.json')


@app.on_event('startup')
def load_users():
    with open(AUTH_PASSWD_FILE) as f:
        app.state.users = {
            name: hashed
            for (name, hashed)
            in [line.strip().split(':', 1)
                for line in f.readlines()
                if ':' in line]
        }


def make_token(username: str) -> JwtData:
    expires = datetime.now(tz=timezone.utc) + VALID_DURATION
    token = jwt.encode(
        {
            'username': username,
            'exp': int(expires.timestamp()),
        },
        AUTH_JWT_SECRET)

    return JwtData(username=username,
                   token=token,
                   expires=expires,
                   enabled=AUTH_ENABLED)


@app.get('/auth/verify')
async def verify(method: Annotated[str | None, Header(alias='X-Forwarded-Method')] = None,
                 uri: Annotated[str | None, Header(alias='X-Forwarded-Uri')] = None,
                 token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None):
    if not AUTH_ENABLED:
        return

    # Some requests should not be checked
    # These include:
    # - CORS preflight requests. The actual request will be checked.
    # - Requests to this service.
    # - Requests to endpoints marked as ignored by configuration.
    if method == 'OPTIONS' \
        or uri.startswith('/') \
            or re.fullmatch(AUTH_IGNORE, uri):
        return

    if not token:
        raise HTTPException(401)

    try:
        jwt.decode(token.encode(), AUTH_JWT_SECRET, algorithms=['HS256'])
        return
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        raise HTTPException(401)


@app.post('/auth/login')
async def login(request: Request, response: Response, data: LoginData) -> JwtData:
    if not AUTH_ENABLED:
        return JwtData(username=None,
                       token=None,
                       expires=None,
                       enabled=False)

    stored = request.app.state.users.get(data.username)

    # User does not exist
    if stored is None:
        raise HTTPException(401)

    # Password does not match
    if not pbkdf2_sha512.verify(data.password, stored):
        raise HTTPException(401)

    result = make_token(data.username)

    response.set_cookie(COOKIE_NAME,
                        value=result.token,
                        expires=result.expires,
                        secure=True)

    return result


@app.get('/auth/refresh')
async def refresh(request: Request,
                  response: Response,
                  token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
                  ) -> JwtData:
    if not AUTH_ENABLED:
        return JwtData(username=None,
                       token=None,
                       expires=None,
                       enabled=False)

    if token is None:
        raise HTTPException(401)

    try:
        decoded = jwt.decode(token.encode(), AUTH_JWT_SECRET, algorithms=['HS256'])
        username = decoded['username']

        # Check if user is still listed
        if username not in request.app.state.users:
            raise HTTPException(401)

        result = make_token(username)

        response.set_cookie(COOKIE_NAME,
                            value=result.token,
                            expires=result.expires,
                            secure=True)

        return result
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        raise HTTPException(401)


@app.get('/auth/logout')
async def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, secure=True)
    return
