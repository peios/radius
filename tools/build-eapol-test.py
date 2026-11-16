#!/usr/bin/env python3
"""Build the pinned independent supplicant tool, leaving no source tree."""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

URL = "https://w1.fi/releases/wpa_supplicant-2.12.tar.gz"
SHA256 = "08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 16:
        parser.error("--jobs must be between 1 and 16")
    destination = Path(args.out).resolve()
    if destination.exists():
        parser.error("output already exists; preserve or remove it explicitly first")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="eapol-build-", dir=destination.parent) as directory:
        directory = Path(directory)
        archive = directory / "source.tar.gz"
        with urllib.request.urlopen(URL, timeout=30) as response:
            data = response.read(12 * 1024 * 1024 + 1)
        if len(data) > 12 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != SHA256:
            raise SystemExit("supplicant source failed the size/hash check")
        archive.write_bytes(data)
        with tarfile.open(archive, "r:gz") as source:
            source.extractall(directory, filter="data")
        work = directory / "wpa_supplicant-2.12" / "wpa_supplicant"
        (work / ".config").write_text("CONFIG_EAPOL_TEST=y\nCONFIG_IEEE8021X_EAPOL=y\n"
                                     "CONFIG_EAP_TLS=y\nCONFIG_EAP_TTLS=y\nCONFIG_EAP_PEAP=y\n"
                                     "CONFIG_EAP_MSCHAPV2=y\nCONFIG_TLS=openssl\n"
                                     "CONFIG_CTRL_IFACE=y\nCFLAGS += -std=gnu11\n")
        subprocess.run(["make", f"-j{args.jobs}", "eapol_test"], cwd=work, check=True)
        shutil.copy2(work / "eapol_test", destination)
    print(f"Built {destination} from wpa_supplicant 2.12 ({SHA256}).")


if __name__ == "__main__":
    main()
