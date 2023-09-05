# Brewblox-auth

User authentication middleware for Brewblox.

Implements a webserver with multiple endpoints:

- `/auth/verify` checks for the presence of a valid JSON Web Token (JWT) in the request cookies. This is intended to be used as endpoint for the ForwardAuth Traefik middleware.
- `/auth/refresh` checks for the presence of a valid authorization JWT in the request cookies. If present, a new token (with updated expiry) is generated and placed in cookies.
- `/auth/login` checks provided username / password against the password file. If verification is successful, a JWT is placed in cookies.
- `/auth/logout` removes the cookie if present.

The password file (./data/users.passwd) contains a `:`-separated username and hashed password per line.
Password hashing is done using the `pbkdf2_sha512` function of the Python `passlib` module.

Whenever the password file is changed on disk, the webserver workers are reloaded.

The secret for the JWT validation is a random string that is generated on container start.
When the service (and not just a worker) restarts, all active sessions are invalidated.
