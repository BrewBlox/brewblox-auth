import logging
import re
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Annotated

import jwt
from fastapi import (APIRouter, Cookie, FastAPI, Header, HTTPException,
                     Request, Response)
from passlib.hash import pbkdf2_sha512
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

COOKIE_NAME = 'Authorization'

LOGGER = logging.getLogger(__name__)
CV_USERS: ContextVar[dict[str, str]] = ContextVar('users')

router = APIRouter()


class AuthStatus(BaseModel):
    enabled: bool
    valid_duration: timedelta


class LoginData(BaseModel):
    username: str
    password: str


class JwtData(BaseModel):
    username: str | None
    token: str | None
    expires: datetime | None
    enabled: bool


class ServiceConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_file='.appenv',
        env_prefix='brewblox_auth_',
        case_sensitive=False,
        json_schema_extra='ignore',
    )

    name: str = 'auth'
    debug: bool = False
    enabled: bool = True
    ignore: str = ''
    jwt_secret: str
    passwd_file: Path
    valid_duration: timedelta = timedelta(days=7)


@lru_cache
def get_config() -> ServiceConfig:
    return ServiceConfig()


def setup_logging(debug: bool):
    level = logging.DEBUG if debug else logging.INFO
    unimportant_level = logging.INFO if debug else logging.WARN
    format = '%(asctime)s.%(msecs)03d [%(levelname).1s:%(name)s:%(lineno)d] %(message)s'
    datefmt = '%Y/%m/%d %H:%M:%S'

    logging.basicConfig(level=level, format=format, datefmt=datefmt)
    logging.captureWarnings(True)

    logging.getLogger('uvicorn.access').setLevel(unimportant_level)
    logging.getLogger('uvicorn.error').disabled = True


def create_app() -> FastAPI:
    config = get_config()
    setup_logging(config.debug)

    with open(config.passwd_file) as f:
        CV_USERS.set({
            name: hashed
            for (name, hashed)
            in [line.strip().split(':', 1)
                for line in f.readlines()
                if ':' in line]
        })

    prefix = f'/{config.name}'
    app = FastAPI(docs_url=f'{prefix}/api/doc',
                  redoc_url=f'{prefix}/api/redoc',
                  openapi_url=f'{prefix}/openapi.json')

    app.include_router(router, prefix=prefix)

    return app


def make_token(username: str) -> JwtData:
    config = get_config()

    expires = datetime.now(tz=timezone.utc) + config.valid_duration
    token = jwt.encode(
        {
            'username': username,
            'exp': int(expires.timestamp()),
        },
        config.jwt_secret)

    return JwtData(username=username,
                   token=token,
                   expires=expires,
                   enabled=config.enabled)


@router.get('/status')
async def status() -> AuthStatus:
    config = get_config()
    return AuthStatus(enabled=config.enabled,
                      valid_duration=config.valid_duration)


@router.get('/verify')
async def verify(method: Annotated[str | None, Header(alias='X-Forwarded-Method')] = None,
                 uri: Annotated[str | None, Header(alias='X-Forwarded-Uri')] = None,
                 token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None):
    config = get_config()

    if not config.enabled:
        return

    # Some requests should not be checked
    # These include:
    # - CORS preflight requests. The actual request will be checked.
    # - Requests to this service.
    # - Requests to endpoints marked as ignored by configuration.
    if method == 'OPTIONS' \
        or uri.startswith('/') \
            or re.fullmatch(config.ignore, uri):
        return

    if not token:
        raise HTTPException(401)

    try:
        jwt.decode(token.encode(), config.jwt_secret, algorithms=['HS256'])
        return
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        raise HTTPException(401)


@router.post('/login')
async def login(request: Request, response: Response, data: LoginData) -> JwtData:
    config = get_config()

    if not config.enabled:
        return JwtData(username=None,
                       token=None,
                       expires=None,
                       enabled=False)

    stored = CV_USERS.get().get(data.username)

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


@router.get('/refresh')
async def refresh(request: Request,
                  response: Response,
                  token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
                  ) -> JwtData:
    config = get_config()

    if not config.enabled:
        return JwtData(username=None,
                       token=None,
                       expires=None,
                       enabled=False)

    if token is None:
        raise HTTPException(401)

    try:
        decoded = jwt.decode(token.encode(), config.jwt_secret, algorithms=['HS256'])
        username = decoded['username']

        # Check if user is still listed
        if username not in CV_USERS.get():
            raise HTTPException(401)

        result = make_token(username)

        response.set_cookie(COOKIE_NAME,
                            value=result.token,
                            expires=result.expires,
                            secure=True)

        return result
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        raise HTTPException(401)


@router.get('/logout')
async def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, secure=True)
    return
