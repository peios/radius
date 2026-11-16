#!/usr/bin/env python3
"""Required independent TTLS/PAP qualification. Missing tools are errors.

Only loopback UDP is used. Fixture secrets, TLS keys and supplicant output live
in a temporary directory or memory and are removed when the run completes.
"""
import argparse
import hashlib
import hmac
import os
from pathlib import Path
import select
import shutil
import socket
import struct
import subprocess
import tempfile
import threading


def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def certificates(directory):
    def request(name, subject):
        key = directory / f"{name}.key"
        csr = directory / f"{name}.csr"
        command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout",
                str(key), "-out", str(csr), "-subj", f"/CN={subject}")
        return key, csr

    root_key, root_csr = request("root", "Protocol fixture root")
    root = directory / "root.pem"
    root_ext = directory / "root.ext"
    root_ext.write_text("basicConstraints=critical,CA:TRUE,pathlen:2\n"
                        "keyUsage=critical,keyCertSign,cRLSign\n")
    command("openssl", "x509", "-req", "-in", str(root_csr), "-signkey", str(root_key),
            "-days", "1", "-extfile", str(root_ext), "-out", str(root))
    intermediate_key, intermediate_csr = request("intermediate", "Protocol fixture intermediate")
    intermediate = directory / "intermediate.pem"
    intermediate_ext = directory / "intermediate.ext"
    intermediate_ext.write_text("basicConstraints=critical,CA:TRUE,pathlen:0\n"
                                "keyUsage=critical,keyCertSign,cRLSign\n")
    command("openssl", "x509", "-req", "-in", str(intermediate_csr), "-CA", str(root),
            "-CAkey", str(root_key), "-CAcreateserial", "-days", "1", "-extfile",
            str(intermediate_ext), "-out", str(intermediate))
    key, csr = request("server", "radius.test")
    leaf = directory / "server.pem"
    ext = directory / "server.ext"
    names = ["DNS:radius.test"] + [f"DNS:padding-{n:03d}.radius.test" for n in range(120)]
    ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                   "extendedKeyUsage=serverAuth\nsubjectAltName=" + ",".join(names) + "\n")
    command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(intermediate),
            "-CAkey", str(intermediate_key), "-CAcreateserial", "-days", "1", "-extfile",
            str(ext), "-out", str(leaf))
    wrong_key, wrong_csr = request("wrong", "Untrusted fixture root")
    wrong = directory / "wrong.pem"
    command("openssl", "x509", "-req", "-in", str(wrong_csr), "-signkey", str(wrong_key),
            "-days", "1", "-extfile", str(root_ext), "-out", str(wrong))
    for name in ["server", "intermediate"]:
        command("openssl", "x509", "-in", str(directory / f"{name}.pem"), "-outform", "DER",
                "-out", str(directory / f"{name}.der"))
    command("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(key), "-outform", "DER",
            "-out", str(directory / "key.der"))
    assert (directory / "server.der").stat().st_size > 3000


class Relay:
    """Duplicate requests and suppress one response, using only test loopback."""
    def __init__(self, server):
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind(("127.0.0.1", 0))
        self.back.bind(("127.0.0.1", 0))
        self.server = server
        self.stopped = threading.Event()
        self.peer = None
        self.suppressed = False
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stopped.is_set():
            readable, _, _ = select.select([self.front, self.back], [], [], 0.1)
            for sock in readable:
                packet, address = sock.recvfrom(65536)
                if sock is self.front:
                    self.peer = address
                    self.back.sendto(packet, self.server)
                    self.back.sendto(packet, self.server)
                elif self.peer is not None:
                    if not self.suppressed:
                        self.suppressed = True
                        continue
                    self.front.sendto(packet, self.peer)

    def close(self):
        self.stopped.set()
        self.thread.join(timeout=2)
        self.front.close()
        self.back.close()


def signed_identity(secret, authenticator=b"0123456789abcdef"):
    eap = b"\x02\x00\x00\x0e\x01anonymous"
    attrs = b"\x50\x12" + bytes(16) + bytes([79, len(eap) + 2]) + eap
    packet = bytearray(bytes([1, 7]) + struct.pack("!H", 20 + len(attrs)) + authenticator + attrs)
    packet[22:38] = hmac.digest(secret, packet, "md5")
    return bytes(packet)


def raw_checks(address, secret):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        packet = signed_identity(secret)
        sock.sendto(packet, address)
        first = sock.recv(4096)
        sock.sendto(packet, address)
        second = sock.recv(4096)
        assert first == second and first[0] == 11, "retransmission changed the challenge"
        expected = hashlib.md5(first[:4] + packet[4:20] + first[20:] + secret).digest()
        assert hmac.compare_digest(first[4:20], expected), "bad Response Authenticator"
        signed = bytearray(first)
        signed[4:20] = packet[4:20]
        signed[22:38] = bytes(16)
        assert hmac.compare_digest(first[22:38], hmac.digest(secret, signed, "md5")), "bad reply MA"
        altered = bytearray(packet)
        altered[-1] ^= 1
        sock.sendto(altered, address)
        sock.settimeout(0.2)
        try:
            sock.recv(4096)
        except TimeoutError:
            pass
        else:
            raise AssertionError("tampered request received a response")


def case(server, eapol, directory, name, *, tls="1.2", user="jack", password="correct horse",
         outer="anonymous", trust="root.pem", domain="radius.test", deny=False, relay=False):
    secret = b"fixture-radius-secret-32-bytes!!!"
    (directory / "secret").write_bytes(secret)
    (directory / "password").write_bytes(b"correct horse")
    args = [server, "--cert", str(directory / "server.der"), "--cert",
            str(directory / "intermediate.der"), "--key", str(directory / "key.der"),
            "--secret-file", str(directory / "secret"), "--password-file",
            str(directory / "password"), "--user", "jack", "--frame-payload", "128"]
    if deny:
        args.append("--deny")
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    proxy = None
    try:
        readable, _, _ = select.select([process.stdout], [], [], 5)
        assert readable, f"{name}: fixture startup timed out"
        line = process.stdout.readline().strip()
        assert line.startswith("LISTEN="), f"{name}: fixture startup failed"
        host, port = line[7:].rsplit(":", 1)
        address = (host, int(port))
        if name == "tls12":
            raw_checks(address, secret)
        if relay:
            proxy = Relay(address)
            address = proxy.front.getsockname()
        phase1 = "tls_disable_tlsv1_3=1" if tls == "1.2" else "tls_disable_tlsv1_2=1 tls_disable_tlsv1_3=0"
        config = directory / "client.conf"
        config.write_text(f'''network={{
    key_mgmt=IEEE8021X
    eap=TTLS
    identity="{user}"
    anonymous_identity="{outer}"
    password="{password}"
    ca_cert="{directory / trust}"
    domain_suffix_match="{domain}"
    phase1="{phase1}"
    phase2="auth=PAP"
    fragment_size=128
}}
''')
        result = subprocess.run([eapol, "-c", str(config), "-a", address[0], "-p", str(address[1]),
                                 "-s", secret.decode(), "-t", "12", "-r", "0"],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=18)
        should_pass = password == "correct horse" and user == "jack" and not deny and trust == "root.pem" and domain == "radius.test"
        if should_pass:
            assert result.returncode == 0 and "SUCCESS" in result.stdout, f"{name}: supplicant did not succeed"
            assert "MPPE keys OK: 1  mismatch: 0" in result.stdout, f"{name}: key agreement was not checked"
            assert f"TLSv{tls}" in result.stdout, f"{name}: requested TLS version was not exercised"
        else:
            assert result.returncode != 0 and "SUCCESS" not in result.stdout, f"{name}: rejection unexpectedly succeeded"
            assert "EAP authentication failed" in result.stdout, f"{name}: no actual authentication rejection"
        print(f"PASS {name}", flush=True)
    finally:
        if proxy:
            proxy.close()
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    parser.add_argument("--eapol-test", default=os.environ.get("EAPOL_TEST", "eapol_test"))
    args = parser.parse_args()
    tool = shutil.which(args.eapol_test)
    if not tool or not shutil.which("openssl"):
        parser.error("eapol_test and openssl are required; no interoperability test was run")
    server = str(Path(args.server).resolve(strict=True))
    root = Path(__file__).resolve().parents[1]
    scratch = root / "target"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="interop-", dir=scratch) as temporary:
        directory = Path(temporary)
        certificates(directory)
        for name, options in [
            ("tls12", {}), ("tls13", {"tls": "1.3"}),
            ("real-outer-name", {"outer": "jack"}),
            ("misleading-outer-name", {"outer": "admin"}),
            ("wrong-password", {"password": "incorrect"}),
            ("unknown-user", {"user": "nobody"}),
            ("admission-denied", {"deny": True}),
            ("untrusted-certificate", {"trust": "wrong.pem"}),
            ("wrong-server-name", {"domain": "other.test"}),
            ("duplicate-and-loss", {"relay": True}),
            ("tls13-wrong-password", {"tls": "1.3", "password": "incorrect"}),
            ("tls13-admission-denied", {"tls": "1.3", "deny": True}),
            ("tls13-untrusted-certificate", {"tls": "1.3", "trust": "wrong.pem"}),
            ("tls13-wrong-server-name", {"tls": "1.3", "domain": "other.test"}),
        ]:
            case(server, tool, directory, name, **options)
    print("Independent TTLS/PAP qualification passed.")


if __name__ == "__main__":
    main()
