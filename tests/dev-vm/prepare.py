#!/usr/bin/env python3
"""Prepare fixtures for a fresh offline VM, never real network credentials."""

import argparse
import importlib.util
from pathlib import Path
import shutil
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm", type=Path, required=True)
    parser.add_argument("--authd", type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    share = args.vm.resolve(strict=True) / "share"
    if (share / "proof-credentials").exists() or (share / "proof-policy").exists():
        raise SystemExit("proof inputs already exist; use a fresh offline VM")
    policies = [args.authd / "registry.d" / name for name in
                ["authd-policy.reg", "lpsd-authd-registration.reg"]]
    for path in policies:
        path.resolve(strict=True)
    spec = importlib.util.spec_from_file_location("interop", here.parent / "interop.py")
    interop = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(interop)
    # The existing protocol-test helper owns certificate construction. Keep
    # its CA keys transient and export only the daemon's required credentials.
    with tempfile.TemporaryDirectory(prefix=".proof-", dir=args.vm) as directory:
        scratch = Path(directory)
        interop.certificates(scratch)
        credentials = share / "proof-credentials"
        credentials.mkdir(mode=0o700)
        for name in ["server.der", "intermediate.der", "key.der"]:
            shutil.copyfile(scratch / name, credentials / name)
        (credentials / "secret").write_bytes(b"offline-vm-proof-secret")
    (share / "proof-policy").mkdir()
    for path in policies:
        shutil.copyfile(path, share / "proof-policy" / path.name)
    for name in ["setup", "check"]:
        shutil.copyfile(here / f"{name}.sh", share / f"proof-{name}.sh")
    print("Prepared offline-only proof inputs; no VM or network settings changed.")


if __name__ == "__main__":
    main()
