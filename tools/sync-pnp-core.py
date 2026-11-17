#!/usr/bin/env python3
"""Refresh the small, explicit PNP source snapshot from a reviewed kernel tree."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("kernel", type=Path)
args = parser.parse_args()
source = args.kernel.resolve()
root = Path(__file__).resolve().parents[1]
target = root / "vendor/kernel"
files = [Path("security/pkm/kacs/peios_uapi.rs"), Path("security/pkm/kacs/kacs_core/claim_name.rs")]
files += [Path("LICENSES/preferred/MIT"),Path("LICENSES/dual/Apache-2.0")]
for directory in ("security/pkm/pnp_core", "peios/rust/pnp-core", "peios/rust/peios-uapi"):
    folder = source / directory
    files += [p.relative_to(source) for p in folder.glob("*.rs")]
    if (folder / "Cargo.toml").exists():
        files.append(Path(directory) / "Cargo.toml")
hashes = {}
for relative in sorted(set(files)):
    destination = target / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source / relative, destination)
    hashes[str(relative)] = hashlib.sha256(destination.read_bytes()).hexdigest()
provenance = {
    "repository": "https://github.com/peios/kernel.git",
    "base_revision": subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip(),
    "source_dirty": bool(subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True)),
    "ownership": "Kernel-owned snapshot. Refresh with tools/sync-pnp-core.py; edit semantic sources in the kernel repository.",
    "files": hashes,
}
(target / "ORIGIN.json").write_text(json.dumps(provenance, indent=2) + "\n")
old = target / "provenance.json"
if old.exists():
    old.unlink()  # Obsolete output of this generator, not a source input.
