#!/usr/bin/env python3
"""Persistent RADIUS development VM with optional LAN attachment."""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import uuid


FILES = (
    "bin/peinit2", "bin/svctl", "bin/authd", "bin/lpsd", "bin/lps",
    "bin/radiusd", "lib/libpeios.so.0", "lib/libauth.so.1",
)
NETWORK_FILES = ("bin/netd", "bin/net", "lib/libnetd.so.1")
HERE = Path(__file__).resolve().parent


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stop(signum, _frame):
    raise SystemExit(128 + signum)


def run_vm(command):
    previous = signal.signal(signal.SIGTERM, stop)
    process = None
    try:
        process = subprocess.Popen(command)
        status = process.wait()
        if status:
            raise SystemExit(status)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        signal.signal(signal.SIGTERM, previous)


def name(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
        raise argparse.ArgumentTypeError("use a simple set name, up to 64 characters")
    return value


def interface_name(value):
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,14}", value):
        raise argparse.ArgumentTypeError("use an interface name of at most 15 characters")
    return value


def configure_lan(args):
    configuration = {"bridge": args.bridge, "tap": args.tap,
                     "mac": "52:54:00:" + ":".join(f"{v:02x}" for v in secrets.token_bytes(3))}
    with (args.vm.resolve(strict=True) / "network.json").open("x") as output:
        output.write(json.dumps(configuration, indent=2) + "\n")
    print("Saved the VM's stable virtual MAC and host attachment; host networking is unchanged.")


@contextmanager
def lan_attachment(vm):
    configuration = json.loads((vm / "network.json").read_text())
    bridge = interface_name(configuration["bridge"])
    tap = interface_name(configuration["tap"])
    mac = configuration["mac"]
    if not re.fullmatch(r"52:54:00(:[0-9a-f]{2}){3}", mac):
        raise SystemExit("invalid VM MAC address")
    if not (Path("/sys/class/net") / bridge / "bridge").is_dir():
        raise SystemExit(f"host bridge is unavailable: {bridge}")
    if (Path("/sys/class/net") / tap).exists():
        raise SystemExit(f"TAP name is already in use: {tap}")
    identifier = str(uuid.uuid4())
    created = False
    try:
        run("nmcli", "connection", "add", "save", "no", "type", "tun",
            "con-name", f"peios-vm-{identifier}", "connection.uuid", identifier,
            "ifname", tap, "mode", "tap", "owner", str(os.getuid()),
            "controller", bridge, "port-type", "bridge", "connection.autoconnect", "no",
            "tun.pi", "no", "tun.vnet-hdr", "no")
        created = True
        run("nmcli", "--wait", "15", "connection", "up", "uuid", identifier)
        yield ["-netdev", f"tap,id=lan,ifname={tap},script=no,downscript=no,vnet_hdr=off",
               "-device", f"virtio-net-pci,netdev=lan,mac={mac}"]
    finally:
        if created:
            run("nmcli", "--wait", "15", "connection", "delete", "uuid", identifier)


def archive(files):
    """A small uncompressed newc archive appended to the existing initramfs."""
    result = bytearray()
    for index, (path, data, mode) in enumerate([*files, ("TRAILER!!!", b"", 0)], 1):
        encoded = path.encode() + b"\0"
        fields = (index, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0)
        result.extend(b"070701" + "".join(f"{v:08x}" for v in fields).encode())
        result.extend(encoded)
        result.extend(b"\0" * (-len(result) % 4))
        result.extend(data)
        result.extend(b"\0" * (-len(result) % 4))
    return result


def prepare(args):
    vm = args.vm.resolve()
    vm.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = vm / "boot"
    if target.exists():
        raise SystemExit("boot assets already exist; use a new VM directory")
    iso = args.iso.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix=".prepare-", dir=vm) as scratch:
        scratch = Path(scratch)
        run("xorriso", "-osirrox", "on", "-indev", str(iso), "-extract",
            "/boot/efi.img", str(scratch / "efi.img"))
        run("mcopy", "-i", str(scratch / "efi.img"), "::/EFI/BOOT/BOOTX64.EFI",
            str(scratch / "boot.efi"))
        boot = scratch / "boot"
        boot.mkdir()
        run("objcopy", f"--dump-section=.linux={boot / 'kernel'}",
            f"--dump-section=.initrd={scratch / 'original-initrd'}", str(scratch / "boot.efi"))
        # Read just the existing sequence; reject an unfamiliar layout rather
        # than silently discard the image's root-assembly strategy.
        raw = run("zstd", "-dc", str(scratch / "original-initrd"), stdout=subprocess.PIPE).stdout
        sequence = run("cpio", "-i", "--to-stdout", "system/prelude/hooks.seq.2",
                       input=raw, stdout=subprocess.PIPE).stdout
        if not sequence.startswith(b"hookseq 2\n") or b"provides rootfs-ready\n" not in sequence:
            raise SystemExit("image has no supported rootfs-ready hook sequence")
        sequence = sequence.rstrip() + b"\nhook /usr/libexec/prelude/radius-dev-handoff\nrequires rootfs-ready\n"
        extra = archive([
            ("system/prelude/hooks.seq.2", sequence, 0o100644),
            ("usr/libexec/prelude/radius-dev-handoff", (HERE / "handoff.sh").read_bytes(), 0o100755),
            ("usr/libexec/prelude/radius-dev-boot", (HERE / "boot.sh").read_bytes(), 0o100755),
        ])
        with (boot / "initrd").open("wb") as output:
            with (scratch / "original-initrd").open("rb") as source:
                shutil.copyfileobj(source, output)
            output.write(b"\0" * (-output.tell() % 4))
            output.write(extra)
        metadata = {"iso": str(iso), "iso_sha256": digest(iso),
                    "kernel_sha256": digest(boot / "kernel"), "initrd_sha256": digest(boot / "initrd")}
        (boot / "source.json").write_text(json.dumps(metadata, indent=2) + "\n")
        boot.rename(target)
    (vm / "share" / "sets").mkdir(parents=True, exist_ok=True)
    for helper in ["activate.sh", "provision-network.sh"]:
        shutil.copyfile(HERE / helper, vm / "share" / helper)
    print(f"Prepared boot assets in {target}; source ISO unchanged.")


def create_state(args):
    disk = args.vm.resolve() / "state.img"
    # Exclusive creation: this command must never format an existing image.
    with disk.open("xb") as stream:
        stream.truncate(512 * 1024 * 1024)
    run("mkfs.ext4", "-q", "-L", "radius-dev-state", str(disk))
    print("Created a new 512 MiB sparse state image. First boot requires --initialize.")


def stage(args):
    source = args.source.resolve(strict=True)
    sets = args.vm.resolve() / "share" / "sets"
    target = sets / args.name
    if target.exists():
        raise SystemExit("set already exists; stage updates under a new name")
    # Validate the whole input before making anything visible to the VM.
    network = [file for file in NETWORK_FILES if (source / file).is_file()]
    if network and len(network) != len(NETWORK_FILES):
        raise SystemExit("network runtime requires netd, net, and libnetd together")
    files = (*FILES, *network)
    for relative in files:
        if not (source / relative).is_file():
            raise SystemExit(f"missing runtime file: {relative}")
    with tempfile.TemporaryDirectory(prefix=".stage-", dir=sets) as scratch:
        scratch = Path(scratch)
        result = scratch / args.name
        for relative in files:
            target_file = result / relative
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / relative, target_file)
            target_file.chmod(0o755 if relative.startswith("bin/") else 0o644)
        manifest = "".join(f"{digest(result / relative)}  {relative}\n" for relative in files)
        (result / "SHA256SUMS").write_text(manifest)
        result.rename(target)
    print(f"Staged {args.name}; the running VM is unchanged.")


def boot(args):
    vm = args.vm.resolve(strict=True)
    if "," in str(vm):
        raise SystemExit("QEMU VM paths must not contain commas")
    disk = vm / "state.img"
    if not disk.is_file():
        raise SystemExit("required state disk is missing; run create-state explicitly")
    if not (vm / "share" / "sets" / args.name / "SHA256SUMS").is_file():
        raise SystemExit("selected runtime set is missing")
    if args.lan and not (vm / "network.json").is_file():
        raise SystemExit("save the VM attachment with configure-lan before a LAN boot")
    if args.lan or (vm / "network.json").exists():
        if any(not (vm / "share" / "sets" / args.name / file).is_file() for file in NETWORK_FILES):
            raise SystemExit("configured networking requires a complete network runtime set")
    # Serialize boots: never share one state image or selection between VMs.
    import fcntl
    with (vm / "run.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        metadata = json.loads((vm / "boot" / "source.json").read_text())
        if digest(Path(metadata["iso"])) != metadata["iso_sha256"]:
            raise SystemExit("source ISO changed; prepare fresh boot assets")
        for relative, expected in (("kernel", metadata["kernel_sha256"]),
                                   ("initrd", metadata["initrd_sha256"])):
            if digest(vm / "boot" / relative) != expected:
                raise SystemExit(f"boot asset changed: {relative}; prepare a fresh boot directory")
        (vm / "share" / "selection").write_text(args.name + "\n")
        cmdline = "console=ttyS0 init=/run/radius-dev-boot"
        if args.initialize:
            cmdline += " radiusdev.initialize=1"
        command = ["qemu-system-x86_64", "-machine", "q35,accel=kvm:tcg", "-cpu", "max",
                   "-m", "1536", "-smp", "2", "-nographic", "-no-reboot",
                   "-kernel", str(vm / "boot" / "kernel"), "-initrd", str(vm / "boot" / "initrd"),
                   "-append", cmdline, "-cdrom", metadata["iso"],
                   "-drive", f"if=virtio,format=raw,file={disk}",
                   "-virtfs", f"local,path={vm / 'share'},mount_tag=dev,security_model=none,readonly=on"]
        # Keep the lock open while QEMU runs; no daemon/background process.
        if args.lan:
            with lan_attachment(vm) as network:
                run_vm([*command, *network])
        else:
            run_vm([*command, "-nic", "none"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("iso", type=Path)
    prepare_parser.set_defaults(function=prepare)
    commands.add_parser("create-state").set_defaults(function=create_state)
    lan_parser = commands.add_parser("configure-lan")
    lan_parser.add_argument("--bridge", type=interface_name, required=True)
    lan_parser.add_argument("--tap", type=interface_name, default="tap-radius")
    lan_parser.set_defaults(function=configure_lan)
    stage_parser = commands.add_parser("stage")
    stage_parser.add_argument("name", type=name)
    stage_parser.add_argument("source", type=Path)
    stage_parser.set_defaults(function=stage)
    boot_parser = commands.add_parser("run")
    boot_parser.add_argument("name", type=name)
    boot_parser.add_argument("--initialize", action="store_true")
    boot_parser.add_argument("--lan", action="store_true")
    boot_parser.set_defaults(function=boot)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, stop)
    args.function(args)


if __name__ == "__main__":
    main()
