#!/usr/bin/env python3
"""Read-only GXWI/RADIUS deployment check, including actual shell surfaces."""

import argparse
import base64
import hashlib
import html.parser
from http.cookies import SimpleCookie
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import time
import urllib.parse


class Inputs(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}
        self.password = None
        self.live_socket = None

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag == "input" and "name" in attributes:
            self.fields[attributes["name"]] = attributes.get("value", "")
            if attributes.get("type") == "password":
                self.password = attributes["name"]
        if tag == "main":
            self.live_socket = attributes.get("data-socket")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Session:
    def __init__(self, url, fingerprint):
        self.url = urllib.parse.urlsplit(url)
        require(self.url.scheme == "https" and self.url.hostname, "Use an HTTPS URL")
        require(not self.url.username and not self.url.password, "Do not put credentials in the URL")
        require(self.url.path in ("", "/") and not self.url.query and not self.url.fragment,
                "Use the desktop root URL")
        self.fingerprint = fingerprint.replace(":", "").lower()
        require(len(self.fingerprint) == 64 and all(c in "0123456789abcdef" for c in self.fingerprint),
                "Supply the certificate's SHA-256 fingerprint")
        self.cookies = SimpleCookie()

    def connect(self):
        connection = http.client.HTTPSConnection(
            self.url.hostname, self.url.port or 443,
            context=ssl._create_unverified_context(), timeout=15,
        )
        try:
            connection.connect()
            actual = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
            require(actual == self.fingerprint, "Desktop certificate fingerprint differs")
            return connection
        except BaseException:
            connection.close()
            raise

    def headers(self):
        return {"Cookie": "; ".join(f"{name}={value.value}" for name, value in self.cookies.items())}

    def request(self, method, path="/", fields=None):
        require(path.startswith("/") and not path.startswith("//"), "Unexpected off-machine path")
        connection = self.connect()
        try:
            headers = self.headers()
            body = None
            if fields is not None:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                body = urllib.parse.urlencode(fields)
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            for name, value in response.getheaders():
                if name.lower() == "set-cookie":
                    self.cookies.load(value)
            content = response.read(4 * 1024 * 1024 + 1)
            require(len(content) <= 4 * 1024 * 1024, "Oversized desktop document")
            return response.status, dict(response.getheaders()), content.decode("utf-8")
        finally:
            connection.close()

    def sign_in(self, credential_file):
        credentials = json.loads(credential_file.read_text())
        status, _, page = self.request("POST", fields={"username": credentials["username"]})
        require(status == 401, "Username did not produce a credential form")
        form = Inputs()
        form.feed(page)
        require(form.password and form.fields.get("t"), "No password prompt and form token")
        form.fields[form.password] = credentials["password"]
        status, _, _ = self.request("POST", fields=form.fields)
        require(status == 303, "Password sign-in did not create a desktop session")
        status, _, _ = self.request("GET")
        require(status == 200, "Signed-in desktop document is unavailable")

    def message(self, path, wanted):
        """Read the first selected JSON message from the public desktop protocol."""
        connection = self.connect()
        try:
            nonce = base64.b64encode(os.urandom(16)).decode()
            headers = self.headers()
            headers.update({"Connection": "Upgrade", "Upgrade": "websocket",
                            "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": nonce})
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            require(response.status == 101, "Desktop WebSocket upgrade was refused")
            expected = base64.b64encode(hashlib.sha1(
                (nonce + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()).decode()
            require(response.getheader("Sec-WebSocket-Accept") == expected, "Invalid WebSocket upgrade")

            def exact(length):
                data = response.fp.read(length)
                require(len(data) == length, "Desktop WebSocket ended early")
                return data

            accumulated = bytearray()
            for _ in range(64):
                first, second = exact(2)
                require(not first & 0x70 and not second & 0x80, "Unexpected WebSocket frame flags")
                opcode, length = first & 15, second & 127
                if length == 126:
                    length = struct.unpack("!H", exact(2))[0]
                elif length == 127:
                    length = struct.unpack("!Q", exact(8))[0]
                require(length <= 4 * 1024 * 1024 - len(accumulated), "Oversized WebSocket message")
                require(opcode in (0, 1), "Unexpected desktop WebSocket message")
                accumulated.extend(exact(length))
                if first & 128:
                    message = json.loads(accumulated)
                    accumulated.clear()
                    if message.get("type") == wanted:
                        return message
            raise RuntimeError("Expected desktop message did not arrive")
        finally:
            connection.close()

    def radius_document(self):
        deadline = time.monotonic() + 15
        while True:
            snapshot = self.message("/.fenestra/desktop", "snapshot")
            surfaces = snapshot.get("surfaces", [])
            panel = any(s.get("role") == "panel" and s.get("shell") for s in surfaces)
            launcher = any(s.get("role") == "overlay" and s.get("shell") for s in surfaces)
            windows = [s for s in surfaces if s.get("application", {}).get("id") == "dev.peios.radius"]
            if panel and launcher and windows:
                break
            require(time.monotonic() < deadline,
                    "Desktop surfaces did not become ready: "
                    f"taskbar={panel}, launcher={launcher}, RADIUS={bool(windows)}")
            time.sleep(0.2)
        status, headers, _ = self.request("GET", windows[0]["url"])
        require(status == 303, "App origin entry did not redirect")
        path = headers.get("location") or headers.get("Location")
        require(path and path.startswith("/.gxwi/a/"), "Unexpected app origin redirect")
        status, _, page = self.request("GET", path)
        require(status == 200, "RADIUS live surface is unavailable")
        document = Inputs()
        document.feed(page)
        require(document.live_socket, "RADIUS page has no live socket")
        live = urllib.parse.urljoin(path, document.live_socket)
        require(live.startswith("/.gxwi/a/"), "Live socket escaped the app origin")
        return self.message(live, "render")["html"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="GXWI HTTPS root URL")
    parser.add_argument("--certificate-sha256", required=True)
    parser.add_argument("--administrator-file", required=True, type=Path,
                        help="Private JSON file containing username and password")
    parser.add_argument("--unprivileged-file", required=True, type=Path,
                        help="Private JSON file containing a non-administrator's credentials")
    args = parser.parse_args()
    for administrative, credential_file in ((True, args.administrator_file), (False, args.unprivileged_file)):
        session = Session(args.url, args.certificate_sha256)
        session.sign_in(credential_file)
        page = session.radius_document()
        denied = "Permission denied" in page or "radiusd did not authorize the status query" in page
        if administrative:
            require(not denied and "Running" in page and "Not confirmed active" not in page,
                    "Administrator cannot read active RADIUS configuration and status")
            print("PASS: administrator desktop has taskbar, launcher and usable active RADIUS Overview")
        else:
            require(denied and "Not confirmed active" in page,
                    "Unprivileged account unexpectedly reads RADIUS management state")
            print("PASS: non-administrator has the shell but RADIUS management is denied")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, http.client.HTTPException, socket.timeout) as error:
        # No response bodies, cookies, origin secrets, credentials or keys.
        raise SystemExit(f"Desktop qualification failed: {type(error).__name__}: {error}") from None
