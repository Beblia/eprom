#!/usr/bin/env python3
"""Read-only hashboard EEPROM dump for Andrey's Windows PC (Desktop-2026).

UNTESTED AGAINST HARDWARE.

Python 3 and paramiko are the runner: getpass keeps the password off the
command line, exec_command sends one allowlisted read at a time, and binary
sysfs reads come back as bytes. Install once with:

    py -3 -m pip install -r requirements.txt

Password comes from the prompt or EPROM_SSH_PASSWORD. --password works and
is visible to other users on the PC, so the prompt is the better input.
The script does not read SSH keys or an agent.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import eprom_read as er


def _load_paramiko():
    try:
        import paramiko
    except ImportError:
        print(
            "paramiko is not installed. On Desktop-2026 run: "
            "py -3 -m pip install -r requirements.txt",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return paramiko


def _normalize_fingerprint(value: str) -> str:
    text = value.strip()
    prefix = "SHA256:"
    if text.startswith(prefix):
        text = text[len(prefix) :]
    return prefix + text.rstrip("=")


def _fingerprint(key) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    encoded = base64.b64encode(digest).decode("ascii").rstrip("=")
    return "SHA256:" + encoded


def _parse_boards(text: str) -> tuple[int, ...]:
    try:
        return tuple(int(piece) for piece in text.split(",") if piece != "")
    except ValueError as exc:
        raise argparse.ArgumentTypeError("boards are 0, 1, 2") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read Antminer hashboard EEPROMs over SSH. "
            "No write path. UNTESTED AGAINST HARDWARE."
        ),
        epilog=(
            "examples:\n"
            "  py -3 tools/dump_eeprom.py plan --host 192.168.1.20 --user root --model S21-Pro\n"
            "  py -3 tools/dump_eeprom.py preflight --host 192.168.1.20 --user root --accept-new-host\n"
            "  py -3 tools/dump_eeprom.py dump --host 192.168.1.20 --user root --model S21-Pro "
            "--host-key SHA256:...\n"
            "\n"
            "Set EPROM_SSH_HOST, EPROM_SSH_USER, EPROM_SSH_PASSWORD, or EPROM_HOST_KEY "
            "in the environment if you would rather not pass them as arguments. "
            "Nothing in this repo stores those values."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    def common(command: argparse.ArgumentParser, dumping: bool) -> None:
        command.add_argument("--host", default=os.environ.get("EPROM_SSH_HOST"))
        command.add_argument("--user", default=os.environ.get("EPROM_SSH_USER"))
        command.add_argument("--port", type=int, default=22)
        command.add_argument("--bus", type=int, default=0)
        command.add_argument("--only", dest="boards", type=_parse_boards, default=(0, 1, 2))
        command.add_argument("--output", type=Path, default=Path("dumps"))
        command.add_argument("--password", default=None, help="Prefer the prompt or EPROM_SSH_PASSWORD")
        command.add_argument(
            "--host-key",
            default=os.environ.get("EPROM_HOST_KEY"),
            help="SHA256 fingerprint to pin before the session starts",
        )
        command.add_argument(
            "--accept-new-host",
            action="store_true",
            help="Accept an unseen host key for this run and print its fingerprint",
        )
        command.add_argument("--length", type=int, default=256)
        command.add_argument("--addr-bytes", type=int, default=1, choices=(1, 2))
        command.add_argument("--confirm-16bit-read", action="store_true")
        command.add_argument(
            "--force-i2c",
            action="store_true",
            help="Use i2ctransfer -f and skip the sysfs eeprom node",
        )
        if dumping:
            command.add_argument("--model", default="")
            command.add_argument("--serial", default=None)
            command.add_argument("--allow-absent", action="store_true")
            command.add_argument("--reader", default=None, help="Local static eeprom-read binary")
            command.add_argument(
                "--allow-tmp-upload",
                action="store_true",
                help="Copy --reader to /tmp/eprom-eeprom-read on the miner",
            )

    plan = sub.add_parser("plan", help="Print the read commands and do not connect")
    common(plan, dumping=True)
    preflight = sub.add_parser("preflight", help="SSH, root, i2c, and probe checks only")
    common(preflight, dumping=False)
    preflight.add_argument(
        "--skip-probe",
        action="store_true",
        help="Stop after identity, /dev/i2c-0, and tool checks",
    )
    dump = sub.add_parser("dump", help="Read each present EEPROM twice and store the capture")
    common(dump, dumping=True)
    return parser


def _target_from_args(args: argparse.Namespace) -> er.Target:
    if not args.host or not args.user:
        raise er.GateError("pass --host and --user, or set EPROM_SSH_HOST and EPROM_SSH_USER")
    reader = getattr(args, "reader", None)
    allow_upload = bool(getattr(args, "allow_tmp_upload", False))
    if allow_upload:
        if not reader:
            raise er.GateError("--allow-tmp-upload requires --reader")
        if not Path(reader).is_file():
            raise er.GateError(f"reader not found: {reader}")
    return er.Target(
        host=args.host,
        user=args.user,
        model=getattr(args, "model", "") or "",
        serial=getattr(args, "serial", None) or None,
        bus=args.bus,
        length=args.length,
        addr_bytes=args.addr_bytes,
        confirm_16bit=bool(args.confirm_16bit_read),
        force_i2c=bool(args.force_i2c),
        boards=tuple(args.boards),
        skip_probe=bool(getattr(args, "skip_probe", False)),
        allow_absent=bool(getattr(args, "allow_absent", False)),
        allow_tmp_upload=allow_upload,
        reader_local_path=reader,
    )


def _password(args: argparse.Namespace) -> str:
    if args.password:
        print(
            "warning: --password is visible in the process list. "
            "Use the prompt or EPROM_SSH_PASSWORD.",
            file=sys.stderr,
        )
        secret = args.password
    else:
        secret = os.environ.get("EPROM_SSH_PASSWORD") or ""
        if not secret:
            secret = getpass.getpass("SSH password: ")
    if not secret:
        raise er.GateError("empty SSH password")
    return secret


def _connect(target: er.Target, password: str, port: int, accept_new: bool, expected: str | None):
    paramiko = _load_paramiko()

    class _Policy(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            seen = _fingerprint(key)
            pinned = _normalize_fingerprint(expected) if expected else None
            if pinned and _normalize_fingerprint(seen) == pinned:
                client.get_host_keys().add(hostname, key.get_name(), key)
                print(f"host key matches {seen}", file=sys.stderr)
                return
            if pinned:
                raise paramiko.SSHException(f"host key {seen} does not match {pinned}")
            if accept_new:
                client.get_host_keys().add(hostname, key.get_name(), key)
                print(f"accepted new host key {seen}", file=sys.stderr)
                print("pin it next time with --host-key", file=sys.stderr)
                return
            raise paramiko.SSHException(
                f"unknown host key {seen}. Re-run with --accept-new-host "
                f"after you check it, or pass --host-key {seen}"
            )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(_Policy())
    client.connect(
        hostname=target.host,
        port=port,
        username=target.user,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=20,
        auth_timeout=20,
        banner_timeout=20,
    )
    transport = client.get_transport()
    if transport is not None:
        transport.set_keepalive(15)
        remote = transport.get_remote_server_key()
        fingerprint = _fingerprint(remote)
    else:
        fingerprint = None
    return client, fingerprint


def _session(client, target: er.Target) -> er.CommandSession:
    def runner(command: str, binary: bool) -> tuple[int, bytes, str]:
        del binary
        _stdin, stdout, stderr = client.exec_command(command, timeout=60)
        _stdin.close()
        data = stdout.read()
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
        return code, data, err

    uploader = None
    if target.allow_tmp_upload:
        def uploader(local_path: str) -> None:
            sftp = client.open_sftp()
            try:
                sftp.put(local_path, er.READER_REMOTE)
                sftp.chmod(er.READER_REMOTE, 0o755)
            finally:
                sftp.close()

    return er.CommandSession(
        runner=runner,
        allow_16bit=target.confirm_16bit,
        uploader=uploader,
    )


def _print_result(result: er.RunResult) -> None:
    print(f"status: {result.status}")
    print(f"directory: {result.directory}")
    for board in result.metadata.get("boards") or []:
        digest = board.get("sha256") or "-"
        print(
            f"hb{board['hashboard_index']} {board['i2c_address']} "
            f"match={board['reads_match']} sha256={digest}"
        )
    for warning in result.metadata.get("warnings") or []:
        print(f"warning: {warning}", file=sys.stderr)
    for blocker in result.metadata.get("blockers") or []:
        print(f"blocker: {blocker}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    print(er.UNTESTED_NOTICE, file=sys.stderr)
    try:
        target = _target_from_args(args)
        er.validate_target(target)
    except (er.GateError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.mode == "plan":
        if not target.model.strip():
            print("error: plan requires --model", file=sys.stderr)
            return 1
        for line in er.plan_lines(target):
            print(line)
        return 0

    if args.mode == "dump" and not target.model.strip():
        print("error: dump requires --model", file=sys.stderr)
        return 1

    try:
        password = _password(args)
    except er.GateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    client = None
    try:
        client, fingerprint = _connect(
            target,
            password,
            args.port,
            bool(args.accept_new_host),
            args.host_key,
        )
        password = ""
        target.host_key_fingerprint = fingerprint
        session = _session(client, target)
        now = datetime.now(timezone.utc)
        if args.mode == "preflight":
            result = er.execute_preflight(session, target, args.output, now)
        else:
            result = er.execute_dump(session, target, args.output, now)
        _print_result(result)
        return result.exit_code
    except er.GateError as exc:
        print(f"not ready: {exc}", file=sys.stderr)
        return 2
    except er.ReadOnlyViolation as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        # paramiko is imported lazily; match by class name so --help needs no install.
        if exc.__class__.__name__ in {"SSHException", "AuthenticationException", "NoValidConnectionsError"}:
            print(f"ssh failed: {exc}", file=sys.stderr)
            return 4
        raise
    finally:
        if client is not None:
            client.close()


if __name__ == "__main__":
    sys.exit(main())
