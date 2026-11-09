"""Read-only Antminer hashboard EEPROM capture over SSH.

UNTESTED AGAINST HARDWARE. This module has no EEPROM write path.
A 16-bit word address is built only when the caller sets confirm_16bit,
because on an 8-bit chip the second byte is stored as data.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

UNTESTED_NOTICE = (
    "UNTESTED AGAINST HARDWARE. Read-only tool. "
    "No miner was attached when this was written."
)

CHIP_SIZE_NOTE = (
    "Default image is 256 bytes with an 8-bit word address. "
    "skot/amlogic-cb-tools hashboard_s19jpro.rs sets EEPROM_LEN to 256 and "
    "reads 0x50, 0x51, 0x52 on /dev/i2c-0 (that binary's decode path is the "
    "S19j Pro XXTEA layout). Alex20129/eeprom_tool i2c_eeprom.c reads a 24C02 "
    "(256 bytes) at 0x50+board index, and eeprom_structure.h sizes its S21+ "
    "struct at 256 bytes. D-Central's generation table lists S21-era parts as "
    "AT24C16 or AT24C32. One AT24C16 occupies 0x50-0x57, so it cannot be three "
    "separate chips at 0x50, 0x51, and 0x52 on one bus. Physical size of "
    "S21 Pro / S21 XP is unconfirmed. A 16-bit pointer is sent only with "
    "--addr-bytes 2 --confirm-16bit-read, because on an 8-bit chip the second "
    "byte is a data write. A readable sysfs eeprom node is preferred: the "
    "kernel driver already knows the address width, and the script only reads "
    "that file."
)

BOARD_ADDR = {0: 0x50, 1: 0x51, 2: 0x52}
READER_REMOTE = "/tmp/eprom-eeprom-read"
CHUNK = 32
SYSFS_CAP = 8192

FIRMWARE_PATHS = (
    "/etc/os-release",
    "/etc/issue",
    "/etc/vnish_version",
    "/etc/vnish-version",
    "/etc/miner_version",
    "/opt/vnish/version",
)
TOOL_NAMES = (
    "i2cdetect",
    "i2cdump",
    "i2cget",
    "i2ctransfer",
    "dd",
    "sha256sum",
    "busybox",
)

LS_I2C = "ls -l /dev/i2c*"
LS_SYSFS = "ls -l /sys/bus/i2c/devices"
CAT_MODEL = "cat /proc/device-tree/model"
CAT_COMPAT = "cat /proc/device-tree/compatible"

TOOL_SCRIPT = (
    "for t in "
    + " ".join(TOOL_NAMES)
    + "; do "
    + 'p=$(command -v "$t" || true); '
    + 'if [ -n "$p" ]; then echo "TOOL $t $p"; else echo "TOOL $t MISSING"; fi; '
    + "done"
)
FIRMWARE_SCRIPT = (
    "for f in "
    + " ".join(FIRMWARE_PATHS)
    + "; do "
    + 'if [ -r "$f" ]; then echo "===== $f"; cat "$f"; else echo "===== $f MISSING"; fi; '
    + "done"
)

EXACT_COMMANDS = frozenset(
    {
        "id",
        "uname -a",
        LS_I2C,
        LS_SYSFS,
        CAT_MODEL,
        CAT_COMPAT,
        TOOL_SCRIPT,
        FIRMWARE_SCRIPT,
    }
)

_BANNED = (
    "i2cset",
    "i2cput",
    " of=",
    ">>",
    " tee ",
    "mkfs",
    "reboot",
    "poweroff",
    "flashrom",
    "chmod",
    "chown",
    " rm ",
    "wget",
    "curl",
)
_REDIRECT = re.compile(r"(^|[^>])>([^>]|$)")
_W1 = re.compile(
    r"^i2ctransfer( -f)? -y [0-7] w1@0x(50|51|52) 0x[0-9a-f]{2} "
    r"r([1-9]|[12][0-9]|3[0-2])$"
)
_W2 = re.compile(
    r"^i2ctransfer( -f)? -y [0-7] w2@0x(50|51|52) "
    r"0x[0-9a-f]{2} 0x[0-9a-f]{2} r([1-9]|[12][0-9]|3[0-2])$"
)
_PROBE = re.compile(r"^i2ctransfer( -f)? -y [0-7] r1@0x(50|51|52)$")
_I2CGET = re.compile(r"^i2cget -y [0-7] 0x(50|51|52)$")
_I2CDUMP = re.compile(r"^i2cdump -y -r 0-255 [0-7] 0x(50|51|52) b$")
_TEST = re.compile(r"^test -r /sys/bus/i2c/devices/[0-7]-00(50|51|52)/eeprom$")
_DD = re.compile(
    r"^dd if=/sys/bus/i2c/devices/[0-7]-00(50|51|52)/eeprom bs=256 count=32$"
)
_READER = re.compile(
    r"^/tmp/eprom-eeprom-read [0-7] 0x(50|51|52) "
    r"(256|512|1024|2048|4096|8192) ([12])( confirm-16bit)?$"
)
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_USER = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$")

Runner = Callable[[str, bool], tuple[int, bytes, str]]
Uploader = Callable[[str], None]


class ReadOnlyViolation(Exception):
    """A command is outside the read-only allowlist."""


class GateError(Exception):
    """SSH worked and the miner is not in a state this tool will dump."""


class ReadError(Exception):
    """One EEPROM read failed or returned a short image."""


@dataclass
class Target:
    host: str
    user: str
    model: str = ""
    serial: str | None = None
    bus: int = 0
    length: int = 256
    addr_bytes: int = 1
    confirm_16bit: bool = False
    force_i2c: bool = False
    boards: tuple[int, ...] = (0, 1, 2)
    skip_probe: bool = False
    allow_absent: bool = False
    allow_tmp_upload: bool = False
    reader_local_path: str | None = None
    host_key_fingerprint: str | None = None


@dataclass
class Completed:
    code: int
    data: bytes
    err: str

    @property
    def text(self) -> str:
        return self.data.decode("utf-8", "replace").replace("\x00", "")


@dataclass
class CommandSession:
    runner: Runner
    allow_16bit: bool = False
    uploader: Uploader | None = None
    transcript: list[dict] = field(default_factory=list)
    uploaded: bool = False

    def run(self, command: str, binary: bool = False) -> Completed:
        assert_read_only_command(command, allow_16bit=self.allow_16bit)
        code, data, err = self.runner(command, binary)
        if not isinstance(data, (bytes, bytearray)):
            raise ReadOnlyViolation("runner returned non-bytes")
        data = bytes(data)
        completed = Completed(code=code, data=data, err=err or "")
        entry = {
            "command": command,
            "exit_code": code,
            "stderr": completed.err[:2000],
            "stdout_bytes": len(data),
        }
        if not binary:
            entry["stdout"] = completed.text[:16000]
        self.transcript.append(entry)
        return completed

    def ensure_reader(self, local_path: str) -> None:
        if self.uploaded:
            return
        if self.uploader is None:
            raise GateError(
                "static reader requested and --allow-tmp-upload was not set"
            )
        self.uploader(local_path)
        self.uploaded = True
        self.transcript.append(
            {
                "command": "sftp put " + READER_REMOTE,
                "exit_code": 0,
                "stderr": "",
                "stdout": "filesystem upload of the read-only helper; EEPROM is not written",
                "stdout_bytes": 0,
            }
        )


@dataclass
class RunResult:
    directory: Path
    status: str
    exit_code: int
    metadata: dict


def assert_read_only_command(command: str, *, allow_16bit: bool = False) -> None:
    if not isinstance(command, str) or command == "" or "\x00" in command:
        raise ReadOnlyViolation("empty command")
    lowered = command.lower()
    for banned in _BANNED:
        if banned in lowered:
            raise ReadOnlyViolation(command)
    if _REDIRECT.search(command):
        raise ReadOnlyViolation(command)
    if command in EXACT_COMMANDS:
        return
    if any(token in command for token in (";", "&", "|", "`", "$", "\n", "\\", "'", '"')):
        raise ReadOnlyViolation(command)
    if (
        _PROBE.fullmatch(command)
        or _I2CGET.fullmatch(command)
        or _TEST.fullmatch(command)
        or _DD.fullmatch(command)
        or _I2CDUMP.fullmatch(command)
        or _W1.fullmatch(command)
    ):
        return
    if _W2.fullmatch(command):
        if not allow_16bit:
            raise ReadOnlyViolation("16-bit pointer blocked")
        return
    match = _READER.fullmatch(command)
    if match:
        _check_reader(match, allow_16bit)
        return
    raise ReadOnlyViolation(command)


def _check_reader(match: re.Match[str], allow_16bit: bool) -> None:
    length = int(match.group(2))
    addr_bytes = int(match.group(3))
    confirm = match.group(4) is not None
    if addr_bytes == 2:
        if not allow_16bit or not confirm or length == 256:
            raise ReadOnlyViolation("16-bit reader blocked")
        return
    if confirm or length != 256:
        raise ReadOnlyViolation("8-bit reader must read 256 bytes")


def validate_host(host: str) -> str:
    if not isinstance(host, str) or not _HOST.fullmatch(host) or ".." in host:
        raise ValueError("host must be an IPv4 address or a plain hostname")
    return host


def validate_user(user: str) -> str:
    if not isinstance(user, str) or not _USER.fullmatch(user):
        raise ValueError("ssh user must be a short login name")
    return user


def validate_target(target: Target) -> None:
    validate_host(target.host)
    validate_user(target.user)
    if target.bus not in range(8):
        raise ValueError("bus must be 0-7")
    if not target.boards or any(board not in BOARD_ADDR for board in target.boards):
        raise ValueError("boards must be chosen from 0, 1, 2")
    if len(set(target.boards)) != len(target.boards):
        raise ValueError("duplicate hashboard index")
    if target.addr_bytes not in (1, 2):
        raise ValueError("addr_bytes must be 1 or 2")
    if target.addr_bytes == 1:
        if target.length != 256:
            raise ValueError(
                "an 8-bit read is 256 bytes; a longer raw transfer wraps, "
                "and a second address byte can program the chip"
            )
        if target.confirm_16bit:
            raise ValueError("confirm_16bit applies only to --addr-bytes 2")
    else:
        if target.length not in (512, 1024, 2048, 4096, 8192):
            raise ValueError("16-bit length must be 512, 1024, 2048, 4096, or 8192")
        if not target.confirm_16bit:
            raise ValueError("16-bit read requires confirm_16bit")
    if target.allow_tmp_upload and not target.reader_local_path:
        raise ValueError("allow_tmp_upload requires a reader path")


def sanitize_component(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    cleaned = cleaned.strip("._")
    if not cleaned:
        raise ValueError("path component is empty")
    return cleaned[:64]


def selected_boards(target: Target) -> list[tuple[int, int]]:
    return [(index, BOARD_ADDR[index]) for index in target.boards]


def iter_chunks(length: int, chunk: int = CHUNK) -> Iterable[tuple[int, int]]:
    if length < 1 or chunk < 1:
        raise ValueError("length")
    offset = 0
    while offset < length:
        size = min(chunk, length - offset)
        yield offset, size
        offset += size


def _force(force: bool) -> str:
    return " -f" if force else ""


def sysfs_node(bus: int, addr: int) -> str:
    if bus not in range(8) or addr not in BOARD_ADDR.values():
        raise ValueError("sysfs address")
    return f"/sys/bus/i2c/devices/{bus}-{addr:04x}/eeprom"


def sysfs_test_command(bus: int, addr: int) -> str:
    command = f"test -r {sysfs_node(bus, addr)}"
    assert_read_only_command(command)
    return command


def sysfs_dd_command(bus: int, addr: int) -> str:
    command = f"dd if={sysfs_node(bus, addr)} bs=256 count=32"
    assert_read_only_command(command)
    return command


def probe_command(bus: int, addr: int, force: bool, use_transfer: bool) -> str:
    if bus not in range(8) or addr not in BOARD_ADDR.values():
        raise ValueError("probe address")
    if use_transfer:
        command = f"i2ctransfer{_force(force)} -y {bus} r1@0x{addr:02x}"
    else:
        if force:
            raise ReadOnlyViolation("i2cget has no force flag in this tool")
        command = f"i2cget -y {bus} 0x{addr:02x}"
    assert_read_only_command(command)
    return command


def transfer_command(
    bus: int,
    addr: int,
    offset: int,
    length: int,
    addr_bytes: int,
    force: bool,
    confirm_16bit: bool,
) -> str:
    if bus not in range(8) or addr not in BOARD_ADDR.values():
        raise ValueError("transfer address")
    if length < 1 or length > CHUNK:
        raise ValueError("chunk length")
    if addr_bytes == 1:
        if offset < 0 or offset > 0xFF:
            raise ValueError("8-bit offset")
        payload = f"0x{offset:02x}"
        width = 1
    elif addr_bytes == 2:
        if not confirm_16bit:
            raise ReadOnlyViolation("16-bit pointer requires confirm_16bit")
        if offset < 0 or offset > 0xFFFF:
            raise ValueError("16-bit offset")
        payload = f"0x{(offset >> 8) & 0xFF:02x} 0x{offset & 0xFF:02x}"
        width = 2
    else:
        raise ValueError("addr_bytes")
    command = (
        f"i2ctransfer{_force(force)} -y {bus} w{width}@0x{addr:02x} "
        f"{payload} r{length}"
    )
    assert_read_only_command(command, allow_16bit=addr_bytes == 2)
    return command


def i2cdump_command(bus: int, addr: int) -> str:
    if bus not in range(8) or addr not in BOARD_ADDR.values():
        raise ValueError("i2cdump address")
    command = f"i2cdump -y -r 0-255 {bus} 0x{addr:02x} b"
    assert_read_only_command(command)
    return command


def reader_command(
    bus: int, addr: int, length: int, addr_bytes: int, confirm_16bit: bool
) -> str:
    if bus not in range(8) or addr not in BOARD_ADDR.values():
        raise ValueError("reader address")
    if addr_bytes == 2 and not confirm_16bit:
        raise ReadOnlyViolation("16-bit reader requires confirm_16bit")
    suffix = " confirm-16bit" if addr_bytes == 2 else ""
    command = f"{READER_REMOTE} {bus} 0x{addr:02x} {length} {addr_bytes}{suffix}"
    assert_read_only_command(command, allow_16bit=addr_bytes == 2)
    return command


def plan_lines(target: Target) -> list[str]:
    validate_target(target)
    lines = [
        "# UNTESTED AGAINST HARDWARE. Local plan only. No SSH in plan mode.",
        "# A live dump prefers a readable sysfs eeprom node over i2ctransfer.",
        "# i2cdetect is not executed. Each probe is one read at 0x50, 0x51, or 0x52.",
        "id",
        "uname -a",
        LS_I2C,
        LS_SYSFS,
        TOOL_SCRIPT,
        FIRMWARE_SCRIPT,
        CAT_MODEL,
        CAT_COMPAT,
    ]
    for _index, addr in selected_boards(target):
        lines.append(sysfs_test_command(target.bus, addr))
        lines.append(probe_command(target.bus, addr, target.force_i2c, True))
        for _pass in (1, 2):
            for offset, size in iter_chunks(target.length):
                lines.append(
                    transfer_command(
                        target.bus,
                        addr,
                        offset,
                        size,
                        target.addr_bytes,
                        target.force_i2c,
                        target.confirm_16bit,
                    )
                )
    for line in lines:
        if not line.startswith("#"):
            assert_read_only_command(line, allow_16bit=target.confirm_16bit)
    return lines


def parse_is_root(text: str) -> bool:
    return re.search(r"\buid=0\b", text) is not None


def parse_tools(text: str) -> dict[str, str | None]:
    found: dict[str, str | None] = {}
    for line in text.splitlines():
        if not line.startswith("TOOL "):
            continue
        parts = line.split(" ", 2)
        if len(parts) != 3:
            continue
        _tag, name, status = parts
        found[name] = None if status == "MISSING" else status
    return found


def parse_firmware(text: str) -> dict[str, str | None]:
    files: dict[str, str | None] = {}
    current: str | None = None
    buf: list[str] = []

    def flush() -> None:
        nonlocal current, buf
        if current is not None:
            body = "\n".join(buf).strip()
            if len(body) > 4000:
                body = body[:4000] + "\n...truncated"
            files[current] = body or None
        current = None
        buf = []

    for line in text.splitlines():
        if line.startswith("===== "):
            flush()
            rest = line[6:]
            if rest.endswith(" MISSING"):
                files[rest[: -len(" MISSING")]] = None
            else:
                current = rest
                buf = []
        elif current is not None:
            buf.append(line)
    flush()
    return files


def best_firmware_version(files: dict[str, str | None]) -> str | None:
    for path in FIRMWARE_PATHS:
        body = files.get(path)
        if not body:
            continue
        for line in body.splitlines():
            stripped = line.strip()
            if stripped:
                return stripped[:200]
    return None


def parse_hex_bytes(text: str, expected: int) -> bytes:
    tokens = re.findall(r"0x([0-9a-fA-F]{2})", text)
    if len(tokens) != expected:
        raise ReadError(
            f"expected {expected} bytes, parsed {len(tokens)} from {text[:180]!r}"
        )
    return bytes(int(token, 16) for token in tokens)


def parse_i2cdump(text: str) -> bytes:
    data: dict[int, int] = {}
    for line in text.splitlines():
        match = re.match(r"^([0-9a-fA-F]{2}):\s+(.*)$", line.strip())
        if not match:
            continue
        offset = int(match.group(1), 16)
        rest = re.split(r"\s{2,}", match.group(2), maxsplit=1)[0]
        for index, token in enumerate(rest.split()):
            if token == "XX":
                raise ReadError(f"i2cdump missed byte {offset + index}")
            if not re.fullmatch(r"[0-9a-fA-F]{2}", token):
                break
            data[offset + index] = int(token, 16)
    missing = [index for index in range(256) if index not in data]
    if missing:
        raise ReadError(f"i2cdump incomplete, first missing {missing[:8]}")
    return bytes(data[index] for index in range(256))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_bytes(path: Path, data: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _atomic_text(path: Path, text: str) -> None:
    _atomic_bytes(path, text.encode("utf-8"))


def allocate_dump_dir(root: Path, model: str, path_id: str, now: datetime) -> Path:
    root = Path(root)
    base = root / sanitize_component(model) / sanitize_component(path_id)
    day = base / now.strftime("%Y-%m-%d")
    path = day if not day.exists() else base / now.strftime("%Y-%m-%dT%H%M%SZ")
    if path.exists():
        raise FileExistsError(path)
    path.mkdir(parents=True)
    return path


def allocate_preflight_dir(root: Path, host: str, now: datetime) -> Path:
    root = Path(root)
    path = (
        root
        / "_preflight"
        / sanitize_component(host)
        / now.strftime("%Y-%m-%dT%H%M%SZ")
    )
    if path.exists():
        raise FileExistsError(path)
    path.mkdir(parents=True)
    return path


def collect_facts(session: CommandSession) -> dict:
    identity = session.run("id")
    uname = session.run("uname -a")
    i2c = session.run(LS_I2C)
    sysfs = session.run(LS_SYSFS)
    tools_run = session.run(TOOL_SCRIPT)
    firmware_run = session.run(FIRMWARE_SCRIPT)
    model = session.run(CAT_MODEL)
    compatible = session.run(CAT_COMPAT)
    files = parse_firmware(firmware_run.text)
    return {
        "id": identity.text.strip(),
        "uname": uname.text.strip(),
        "is_root": parse_is_root(identity.text),
        "i2c_devices": i2c.text.strip(),
        "has_i2c0": "/dev/i2c-0" in i2c.text,
        "sysfs_devices": sysfs.text.strip(),
        "tools": parse_tools(tools_run.text),
        "firmware_files": files,
        "firmware_version": best_firmware_version(files),
        "device_tree_model": model.text.strip() if model.code == 0 else None,
        "device_tree_compatible": compatible.text.strip() if compatible.code == 0 else None,
    }


def probe_boards(session: CommandSession, target: Target, tools: dict) -> list[dict]:
    have_transfer = bool(tools.get("i2ctransfer"))
    have_get = bool(tools.get("i2cget"))
    probes = []
    for index, addr in selected_boards(target):
        test = session.run(sysfs_test_command(target.bus, addr))
        sysfs_ok = test.code == 0
        probed = False
        present = False
        if target.skip_probe:
            present = sysfs_ok
            detail = "probe skipped; presence follows the sysfs node"
        elif have_transfer or have_get:
            probed = True
            try:
                command = probe_command(
                    target.bus, addr, target.force_i2c, have_transfer
                )
            except ReadOnlyViolation as exc:
                present = False
                detail = str(exc)
            else:
                result = session.run(command)
                present = result.code == 0
                detail = "ack" if present else (
                    result.err.strip() or result.text.strip() or f"exit {result.code}"
                )
        elif sysfs_ok:
            present = True
            detail = "sysfs eeprom node is readable"
        else:
            detail = "no probe tool and no sysfs eeprom node"
        probes.append(
            {
                "hashboard_index": index,
                "i2c_address": f"0x{addr:02x}",
                "sysfs_readable": sysfs_ok,
                "probed": probed,
                "present": present,
                "detail": detail[:500],
            }
        )
    return probes


def readiness(facts: dict, probes: list[dict], target: Target) -> tuple[bool, list[str]]:
    reasons = []
    if not facts.get("is_root"):
        reasons.append("ssh login is not uid 0")
    if not facts.get("has_i2c0"):
        reasons.append("/dev/i2c-0 is absent")
    tools = facts.get("tools") or {}
    methods = []
    if any(probe["sysfs_readable"] for probe in probes) and not target.force_i2c:
        methods.append("sysfs")
    if tools.get("i2ctransfer"):
        methods.append("i2ctransfer")
    if tools.get("i2cdump") and target.length == 256 and target.addr_bytes == 1:
        methods.append("i2cdump")
    if target.allow_tmp_upload and target.reader_local_path:
        methods.append("static-reader")
    if not methods:
        reasons.append("no read method (sysfs eeprom, i2ctransfer, i2cdump, or static reader)")
    if not target.skip_probe and probes and not any(probe["present"] for probe in probes):
        reasons.append("no ACK at the selected EEPROM addresses")
    return (not reasons), reasons


def _choose_method(target: Target, tools: dict, sysfs_ok: bool) -> str:
    if sysfs_ok and not target.force_i2c:
        return "sysfs"
    if tools.get("i2ctransfer"):
        return "i2ctransfer"
    if (
        tools.get("i2cdump")
        and target.length == 256
        and target.addr_bytes == 1
        and not target.force_i2c
    ):
        return "i2cdump"
    if target.allow_tmp_upload and target.reader_local_path:
        return "static-reader"
    raise GateError("no read method for this board")


def _read_once(
    session: CommandSession, target: Target, addr: int, method: str
) -> bytes:
    if method == "sysfs":
        result = session.run(sysfs_dd_command(target.bus, addr), binary=True)
        if result.code != 0 or not result.data:
            raise ReadError(result.err.strip() or "sysfs eeprom read failed")
        if len(result.data) > SYSFS_CAP:
            raise ReadError("sysfs read exceeded 8192 bytes")
        return result.data
    if method == "i2ctransfer":
        chunks = []
        for offset, size in iter_chunks(target.length):
            result = session.run(
                transfer_command(
                    target.bus,
                    addr,
                    offset,
                    size,
                    target.addr_bytes,
                    target.force_i2c,
                    target.confirm_16bit,
                )
            )
            if result.code != 0:
                raise ReadError(result.err.strip() or result.text.strip() or "i2ctransfer failed")
            chunks.append(parse_hex_bytes(result.text, size))
        return b"".join(chunks)
    if method == "i2cdump":
        result = session.run(i2cdump_command(target.bus, addr))
        if result.code != 0:
            raise ReadError(result.err.strip() or "i2cdump failed")
        return parse_i2cdump(result.text)
    if method == "static-reader":
        if not target.reader_local_path:
            raise GateError("reader path is empty")
        session.ensure_reader(target.reader_local_path)
        result = session.run(
            reader_command(
                target.bus,
                addr,
                target.length,
                target.addr_bytes,
                target.confirm_16bit,
            ),
            binary=True,
        )
        if result.code != 0 or len(result.data) != target.length:
            raise ReadError(
                result.err.strip()
                or f"static reader returned {len(result.data)} bytes"
            )
        return result.data
    raise ReadError(f"unknown method {method}")


def _save_named(directory: Path, name: str, data: bytes) -> str:
    path = directory / name
    _atomic_bytes(path, data)
    digest = sha256_hex(data)
    if name.endswith(".bin"):
        sidecar_name = name[: -len(".bin")] + ".sha256"
    else:
        sidecar_name = name + ".sha256"
    _atomic_text(directory / sidecar_name, f"{digest}  {name}\n")
    return digest


def _board_record(
    index: int,
    addr: int,
    method: str | None,
    requested: int,
    first: bytes | None,
    second: bytes | None,
    error: str | None,
    present: bool,
) -> dict:
    record = {
        "hashboard_index": index,
        "i2c_address": f"0x{addr:02x}",
        "present": present,
        "method": method,
        "requested_length": requested,
        "reads_match": False,
        "sha256": None,
        "sha256_read1": sha256_hex(first) if first is not None else None,
        "sha256_read2": sha256_hex(second) if second is not None else None,
        "file": None,
        "read1_file": None,
        "read2_file": None,
        "actual_length": len(first) if first is not None else None,
        "header_hex": first[:16].hex() if first is not None else None,
        "error": error,
    }
    if first is not None and second is not None and first == second and error is None:
        record["reads_match"] = True
        record["sha256"] = record["sha256_read1"]
    return record


def _write_sums(directory: Path) -> None:
    lines = []
    for path in sorted(directory.glob("*.bin")):
        lines.append(f"{sha256_hex(path.read_bytes())}  {path.name}\n")
    _atomic_text(directory / "SHA256SUMS", "".join(lines))


def _base_metadata(target: Target, now: datetime, facts: dict, probes: list[dict]) -> dict:
    path_id = target.serial or target.host
    warnings = []
    if facts["tools"].get("i2cdetect"):
        warnings.append("i2cdetect is installed and was not executed")
    if not facts["tools"].get("sha256sum"):
        warnings.append("miner has no sha256sum; hashes were computed locally")
    return {
        "schema_version": 1,
        "hardware_tested": False,
        "read_only": True,
        "untested_notice": UNTESTED_NOTICE,
        "captured_at": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": target.host,
        "ssh_user": target.user,
        "ssh_host_key": target.host_key_fingerprint,
        "operator_hostname": socket.gethostname(),
        "model": target.model or None,
        "serial": target.serial,
        "path_id": path_id,
        "firmware_version": facts.get("firmware_version"),
        "firmware_files": facts.get("firmware_files"),
        "chip_size_note": CHIP_SIZE_NOTE,
        "bus": target.bus,
        "requested_length": target.length,
        "address_bytes": target.addr_bytes,
        "identity": {
            "id": facts.get("id"),
            "uname": facts.get("uname"),
            "is_root": facts.get("is_root"),
            "i2c_devices": facts.get("i2c_devices"),
            "has_i2c0": facts.get("has_i2c0"),
            "sysfs_devices": facts.get("sysfs_devices"),
            "device_tree_model": facts.get("device_tree_model"),
            "device_tree_compatible": facts.get("device_tree_compatible"),
        },
        "tools": facts.get("tools"),
        "probes": probes,
        "warnings": warnings,
    }


def _status(records: list[dict], target: Target) -> str:
    if any(record.get("error") for record in records):
        return "incomplete"
    if any(record["present"] and not record["reads_match"] for record in records):
        return "mismatch"
    present = [record for record in records if record["present"]]
    if not present:
        return "incomplete"
    if not target.allow_absent and any(not record["present"] for record in records):
        return "incomplete"
    if all(record["reads_match"] for record in present):
        return "ok"
    return "incomplete"


def _exit_for(status: str) -> int:
    if status == "ok":
        return 0
    if status == "mismatch":
        return 3
    return 2


def execute_preflight(
    session: CommandSession, target: Target, output_dir: Path, now: datetime
) -> RunResult:
    validate_target(target)
    facts = collect_facts(session)
    probes = probe_boards(session, target, facts["tools"])
    ready, reasons = readiness(facts, probes, target)
    directory = allocate_preflight_dir(output_dir, target.host, now)
    metadata = _base_metadata(target, now, facts, probes)
    metadata["mode"] = "preflight"
    metadata["ready_to_dump"] = ready
    metadata["blockers"] = reasons
    metadata["status"] = "ready" if ready else "not-ready"
    metadata["commands_run"] = session.transcript
    _atomic_text(directory / "preflight.json", json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return RunResult(
        directory=directory,
        status=metadata["status"],
        exit_code=0 if ready else 2,
        metadata=metadata,
    )


def execute_dump(
    session: CommandSession, target: Target, output_dir: Path, now: datetime
) -> RunResult:
    validate_target(target)
    if not target.model.strip():
        raise ValueError("dump requires a model name")
    if target.skip_probe:
        raise ValueError("dump always probes; skip_probe is preflight-only")
    facts = collect_facts(session)
    probes = probe_boards(session, target, facts["tools"])
    ready, reasons = readiness(facts, probes, target)
    if not ready:
        preflight = execute_preflight_from_facts(
            session, target, output_dir, now, facts, probes, reasons
        )
        raise GateError(
            "; ".join(reasons) + f". Preflight written to {preflight.directory}"
        )

    path_id = target.serial or target.host
    directory = allocate_dump_dir(output_dir, target.model, path_id, now)
    by_index = {probe["hashboard_index"]: probe for probe in probes}
    records = []
    try:
        for index, addr in selected_boards(target):
            probe = by_index[index]
            if not probe["present"]:
                records.append(
                    _board_record(index, addr, None, target.length, None, None, None, False)
                )
                continue
            method = None
            try:
                method = _choose_method(target, facts["tools"], probe["sysfs_readable"])
                first = _read_once(session, target, addr, method)
                second = _read_once(session, target, addr, method)
            except (ReadError, GateError) as exc:
                records.append(
                    _board_record(index, addr, method, target.length, None, None, str(exc), True)
                )
                continue
            record = _board_record(index, addr, method, target.length, first, second, None, True)
            if record["reads_match"]:
                name = f"hb{index}-0x{addr:02x}.bin"
                record["file"] = name
                record["sha256"] = _save_named(directory, name, first)
                if len(first) != target.length and method == "sysfs":
                    facts_warning = (
                        f"hb{index} sysfs length {len(first)} differs from requested {target.length}"
                    )
                    record["length_note"] = facts_warning
            else:
                read1 = f"hb{index}-0x{addr:02x}.read1.bin"
                read2 = f"hb{index}-0x{addr:02x}.read2.bin"
                record["read1_file"] = read1
                record["read2_file"] = read2
                record["sha256_read1"] = _save_named(directory, read1, first)
                record["sha256_read2"] = _save_named(directory, read2, second)
            records.append(record)
    finally:
        status = _status(records, target)
        metadata = _base_metadata(target, now, facts, probes)
        metadata["mode"] = "dump"
        metadata["status"] = status
        metadata["boards"] = records
        for record in records:
            note = record.get("length_note")
            if note and note not in metadata["warnings"]:
                metadata["warnings"].append(note)
        metadata["commands_run"] = list(session.transcript)
        _write_sums(directory)
        _atomic_text(
            directory / "metadata.json",
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        )
    return RunResult(
        directory=directory,
        status=status,
        exit_code=_exit_for(status),
        metadata=metadata,
    )


def execute_preflight_from_facts(
    session: CommandSession,
    target: Target,
    output_dir: Path,
    now: datetime,
    facts: dict,
    probes: list[dict],
    reasons: list[str],
) -> RunResult:
    directory = allocate_preflight_dir(output_dir, target.host, now)
    metadata = _base_metadata(target, now, facts, probes)
    metadata["mode"] = "preflight"
    metadata["ready_to_dump"] = False
    metadata["blockers"] = reasons
    metadata["status"] = "not-ready"
    metadata["commands_run"] = session.transcript
    _atomic_text(directory / "preflight.json", json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return RunResult(directory, "not-ready", 2, metadata)
