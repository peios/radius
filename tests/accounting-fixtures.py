#!/usr/bin/env python3
"""Independent standard-library RFC 2866/3579 vectors for the native probe."""
import hashlib
import hmac
from pathlib import Path
import struct
import sys
import time

SECRET = b"native-accounting-test-secret"

def attr(kind, value):
    return bytes((kind, len(value) + 2)) + value

def number(kind, value):
    return attr(kind, struct.pack("!I", value))

def vector(identifier, status, session, stamp, classes=True, delay=0):
    body = number(40, status) + attr(44, session) + attr(32, b"nas-a")
    body += number(55, stamp) + number(41, delay) + attr(1, b"reported-name")
    body += number(42, 1234) + number(52, 1) + number(43, 99)
    if classes:
        body += attr(25, b"accounting-native-grant")
    proxy = attr(33, b"relay-opaque")
    body += proxy
    prefix = bytes((4, identifier)) + struct.pack("!H", len(body) + 38)
    message_authenticator = hmac.digest(SECRET, prefix + bytes(16) + body + attr(80, bytes(16)), "md5")
    body += attr(80, message_authenticator)
    request_authenticator = hashlib.md5(prefix + bytes(16) + body + SECRET).digest()
    request = prefix + request_authenticator + body
    prefix = bytes((5, identifier)) + struct.pack("!H", len(proxy) + 38)
    ma = hmac.digest(SECRET, prefix + request_authenticator + proxy + attr(80, bytes(16)), "md5")
    body = proxy + attr(80, ma)
    response = prefix + hashlib.md5(prefix + request_authenticator + body + SECRET).digest() + body
    return request, response

def main(directory):
    directory.mkdir(exist_ok=False)
    stamp = int(time.time())
    cases = [("start", 1, 1, b"session-a", stamp, True, 0),
             ("retry", 91, 1, b"session-a", stamp, True, 20),
             ("unverified", 2, 1, b"session-b", stamp, False, 0),
             ("stop", 3, 2, b"session-a", stamp + 1, True, 0)]
    for name, *values in cases:
        request, response = vector(*values)
        (directory / f"{name}.request").write_bytes(request)
        (directory / f"{name}.response").write_bytes(response)
    broken = bytearray((directory / "start.request").read_bytes())
    broken[-1] ^= 1
    (directory / "tampered.request").write_bytes(broken)
    (directory / "tampered.response").write_bytes(b"")
    (directory / "secret").write_bytes(SECRET)

if __name__ == "__main__":
    main(Path(sys.argv[1]))
