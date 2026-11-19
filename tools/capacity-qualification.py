#!/usr/bin/env python3
"""Measure bounded synthetic component workloads with explicit host context."""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--scratch-parent", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    scratch = args.scratch_parent.resolve(strict=True)
    args.out.mkdir(parents=True, exist_ok=False)
    output = args.out.resolve()
    cases = [
        ("auth-serial", ["auth", "--requests", "1024", "--concurrency", "1"]),
        ("auth-window32", ["auth", "--requests", "4096", "--concurrency", "32"]),
        ("auth-window128", ["auth", "--requests", "4096", "--concurrency", "128"]),
        ("auth-overload", ["auth", "--requests", "4096", "--clients", "2", "--concurrency", "64", "--attempts", "4", "--per-client", "2", "--allow-overload"]),
        ("accounting-batch16", ["accounting", "--requests", "2048", "--concurrency", "64", "--batch", "16"]),
        ("accounting-batch128", ["accounting", "--requests", "2048", "--concurrency", "256", "--batch", "128"]),
        ("accounting-batch512", ["accounting", "--requests", "2048", "--concurrency", "1024", "--batch", "512"]),
        ("accounting-timer", ["accounting", "--requests", "128", "--concurrency", "64"]),
        ("accounting-overload", ["accounting", "--requests", "4096", "--concurrency", "1024", "--queue", "4", "--batch", "4", "--allow-overload"]),
    ]
    with binary.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    report = {"schema": 1, "binary_sha256": digest, "platform": platform.platform(),
              "machine": platform.machine(), "logical_cpus": os.cpu_count(),
              "cpu_affinity": sorted(os.sched_getaffinity(0)),
              "cpu_model": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), None),
              "load_average_at_start": os.getloadavg(),
              "scratch_parent": str(scratch), "filesystem": subprocess.check_output(
                  ["stat", "-f", "-c", "%T", str(scratch)], text=True).strip(),
              "exclusive_host": False, "results": []}
    failed = False
    for name, options in cases:
        command = [str(binary), *options, "--scratch-parent", str(scratch)]
        began = time.monotonic()
        try:
            result = subprocess.run(command, capture_output=True, timeout=180, check=False)
            (output / f"{name}.stdout").write_bytes(result.stdout)
            (output / f"{name}.stderr").write_bytes(result.stderr)
            entry = {"name": name, "command": command, "exit": result.returncode,
                     "elapsed_seconds": time.monotonic() - began}
            if result.returncode == 0:
                entry["report"] = json.loads(result.stdout)
            else:
                failed = True
        except subprocess.TimeoutExpired as error:
            failed = True
            entry = {"name": name, "command": command, "exit": "controller-timeout"}
            (output / f"{name}.stderr").write_bytes(error.stderr or b"")
        report["results"].append(entry)
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"{name}: exit={entry['exit']}", flush=True)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
