#!/usr/bin/env python3
"""Run bounded, local libFuzzer campaigns in a new evidence directory."""
import argparse
import hashlib
import json
import platform
import re
import subprocess
import time
from pathlib import Path

LIMITS = {"packets": 8192, "engine_sequences": 4096,
          "driver_sequences": 2048, "ledger_sequences": 1024, "control_sequences": 1024}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--seed", type=int, default=1729)
    parser.add_argument("--rss-mb", type=int, default=1024)
    parser.add_argument("--target", choices=LIMITS, action="append")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 3600 or not 256 <= args.rss_mb <= 4096:
        parser.error("seconds must be 1..3600 and rss-mb 256..4096")
    binaries = args.binary_dir.resolve()
    targets = args.target or list(LIMITS)
    for target in targets:
        if not (binaries / target).is_file():
            parser.error(f"missing instrumented binary: {target}")
    args.out.mkdir(parents=True, exist_ok=False)
    output = args.out.resolve()
    root = Path(__file__).resolve().parent.parent
    seeds = json.loads((root / "fuzz/seeds.json").read_text())
    source = hashlib.sha256()
    paths = subprocess.check_output(["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=root).split(b"\0")
    for path in sorted(set(paths) - {b""}):
        source.update(path + b"\0")
        source.update((root / path.decode()).read_bytes())
    report = {"schema": 1, "platform": platform.platform(), "seed": args.seed,
              "seconds_per_target": args.seconds, "rss_limit_mb": args.rss_mb,
              "source_files_sha256": source.hexdigest(),
              "source_head": subprocess.check_output(
                  ["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(), "targets": []}
    for target in targets:
        case = output / target
        corpus = case / "corpus"
        corpus.mkdir(parents=True)
        for item in seeds["shared"] + seeds.get(target, []):
            data = bytes.fromhex(item["hex"]) if "hex" in item else item["text"].encode()
            (corpus / hashlib.sha256(data).hexdigest()).write_bytes(data)
        artifacts = case / "artifacts"
        artifacts.mkdir()
        binary = binaries / target
        command = [str(binary), str(corpus), f"-max_total_time={args.seconds}",
                   f"-seed={args.seed}", f"-max_len={LIMITS[target]}",
                   f"-rss_limit_mb={args.rss_mb}", "-timeout=10",
                   f"-artifact_prefix={artifacts}/", "-print_final_stats=1"]
        began = time.monotonic()
        with (case / "run.log").open("w") as log:
            try:
                status = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                        timeout=args.seconds + 45, check=False).returncode
            except subprocess.TimeoutExpired:
                status = "controller-timeout"
        text = (case / "run.log").read_text(errors="replace")
        executions = re.findall(r"stat::number_of_executed_units:\s*(\d+)", text)
        coverage = re.findall(r"cov:\s*(\d+)\s+ft:\s*(\d+)", text)
        report["targets"].append({"target": target, "command": command,
            "binary_sha256": hashlib.file_digest(binary.open("rb"), "sha256").hexdigest(),
            "exit": status, "elapsed_seconds": time.monotonic() - began,
            "executions": int(executions[-1]) if executions else None,
            "coverage_edges": int(coverage[-1][0]) if coverage else None,
            "features": int(coverage[-1][1]) if coverage else None,
            "corpus_files": len(list(corpus.iterdir())),
            "artifacts": sorted(p.name for p in artifacts.iterdir())})
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"{target}: exit={status}; evidence={case}", flush=True)
    return int(any(item["exit"] != 0 for item in report["targets"]))


if __name__ == "__main__":
    raise SystemExit(main())
