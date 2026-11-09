"""Local tests for the read-only dump allowlist. No miner, no network."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import eprom_read as er


NOW = datetime(2026, 11, 9, 15, 30, tzinfo=timezone.utc)
SECRET = "s3cret-password"


def target(**kwargs) -> er.Target:
    base = dict(host="192.168.1.20", user="root", model="S21-Pro")
    base.update(kwargs)
    return er.Target(**base)


def identity(command: str) -> tuple[int, bytes, str] | None:
    if command == "id":
        return 0, b"uid=0(root) gid=0(root) groups=0(root)\n", ""
    if command == "uname -a":
        return 0, b"Linux miner 5.4.0 aarch64 GNU/Linux\n", ""
    if command == er.LS_I2C:
        return 0, b"crw------- 1 root root 89, 0 Nov 9 /dev/i2c-0\n", ""
    if command == er.LS_SYSFS:
        return 0, b"0-0050\n0-0051\n0-0052\n", ""
    if command == er.TOOL_SCRIPT:
        text = "\n".join(
            [
                "TOOL i2cdetect MISSING",
                "TOOL i2cdump /usr/sbin/i2cdump",
                "TOOL i2cget /usr/sbin/i2cget",
                "TOOL i2ctransfer /usr/sbin/i2ctransfer",
                "TOOL dd /bin/dd",
                "TOOL sha256sum MISSING",
                "TOOL busybox /bin/busybox",
            ]
        )
        return 0, text.encode() + b"\n", ""
    if command == er.FIRMWARE_SCRIPT:
        text = "===== /etc/os-release\nNAME=VNish-test\n===== /etc/issue MISSING\n"
        return 0, text.encode(), ""
    if command == er.CAT_MODEL:
        return 0, b"Amlogic S21 test\x00", ""
    if command == er.CAT_COMPAT:
        return 0, b"amlogic,a113d\x00", ""
    return None


class ScriptedMiner:
    def __init__(self, image: bytes, second: bytes | None = None, present=(0, 1, 2), sysfs=False):
        self.image = image
        self.second = image if second is None else second
        self.present = set(present)
        self.sysfs = sysfs
        self.commands: list[str] = []
        self.uploads: list[str] = []
        self.transfer_counts: dict[str, int] = {}
        self.dd_counts: dict[str, int] = {}

    def runner(self, command: str, binary: bool) -> tuple[int, bytes, str]:
        del binary
        er.assert_read_only_command(command, allow_16bit=False)
        self.commands.append(command)
        known = identity(command)
        if known is not None:
            return known
        if command.startswith("test -r "):
            addr = command[-len("/eeprom") - 4 : -len("/eeprom")]
            index = { "0050": 0, "0051": 1, "0052": 2 }[addr]
            if self.sysfs and index in self.present:
                return 0, b"", ""
            return 1, b"", ""
        if command.startswith("i2cget "):
            addr = int(command.split()[-1], 16)
            index = {0x50: 0, 0x51: 1, 0x52: 2}[addr]
            if index in self.present:
                return 0, b"0x00\n", ""
            return 1, b"", "Error: No such device or address"
        if command.startswith("i2ctransfer") and " r1@" in command:
            addr = int(command.rsplit("@", 1)[1], 16)
            index = {0x50: 0, 0x51: 1, 0x52: 2}[addr]
            if index in self.present:
                return 0, b"0x00\n", ""
            return 1, b"", "Error: No such device or address"
        if " w1@" in command:
            addr = command.split("w1@", 1)[1][:4]
            self.transfer_counts[addr] = self.transfer_counts.get(addr, 0) + 1
            pass_no = (self.transfer_counts[addr] - 1) // 8
            payload = self.image if pass_no == 0 else self.second
            offset = int(command.split(" w1@" + addr + " ", 1)[1].split()[0], 16)
            size = int(command.rsplit(" r", 1)[1])
            chunk = payload[offset : offset + size]
            text = " ".join(f"0x{byte:02x}" for byte in chunk)
            return 0, text.encode(), ""
        if command.startswith("dd if="):
            addr = command.split("/eeprom", 1)[0][-4:]
            self.dd_counts[addr] = self.dd_counts.get(addr, 0) + 1
            payload = self.image if self.dd_counts[addr] % 2 else self.second
            return 0, payload, ""
        if command.startswith(er.READER_REMOTE):
            return 0, self.image, ""
        raise AssertionError(command)

    def upload(self, local_path: str) -> None:
        self.uploads.append(local_path)


class AllowlistTests(unittest.TestCase):
    def test_default_transfer_is_one_address_byte(self):
        command = er.transfer_command(0, 0x50, 0x20, 32, 1, False, False)
        self.assertEqual(command, "i2ctransfer -y 0 w1@0x50 0x20 r32")
        er.assert_read_only_command(command)

    def test_extra_data_byte_and_writes_are_rejected(self):
        rejected = [
            "i2ctransfer -y 0 w1@0x50 0x00 0xff r1",
            "i2ctransfer -y 0 w3@0x50 0x00 0x00 0x00 r1",
            "i2cset -y 0 0x50 0x00 0x00",
            "dd if=/dev/zero of=/sys/bus/i2c/devices/0-0050/eeprom",
            "dd if=/sys/bus/i2c/devices/0-0050/eeprom bs=256 count=32; rm -rf /",
            "i2cdetect -y -r 0",
            "i2cdetect -y -q 0",
            "i2cdump -y 0 0x50",
            "i2cget -y 0 0x50 0x00",
            "echo x > /tmp/x",
            "id; id",
        ]
        for command in rejected:
            with self.subTest(command=command):
                with self.assertRaises(er.ReadOnlyViolation):
                    er.assert_read_only_command(command)

    def test_sixteen_bit_pointer_is_opt_in(self):
        with self.assertRaises(er.ReadOnlyViolation):
            er.transfer_command(0, 0x50, 0x100, 32, 2, False, False)
        command = er.transfer_command(0, 0x51, 0x100, 32, 2, False, True)
        self.assertEqual(command, "i2ctransfer -y 0 w2@0x51 0x01 0x00 r32")
        with self.assertRaises(er.ReadOnlyViolation):
            er.assert_read_only_command(command, allow_16bit=False)
        er.assert_read_only_command(command, allow_16bit=True)

    def test_length_rules(self):
        with self.assertRaises(ValueError):
            er.validate_target(target(length=512, addr_bytes=1))
        with self.assertRaises(ValueError):
            er.validate_target(target(length=4096, addr_bytes=2, confirm_16bit=False))
        er.validate_target(target(length=4096, addr_bytes=2, confirm_16bit=True))

    def test_tool_check_mentions_i2cdetect_without_running_it(self):
        er.assert_read_only_command(er.TOOL_SCRIPT)
        self.assertIn("i2cdetect", er.TOOL_SCRIPT)
        self.assertNotIn("i2cdetect -", er.TOOL_SCRIPT)

    def test_plan_is_read_only_and_doubled(self):
        lines = [line for line in er.plan_lines(target()) if not line.startswith("#")]
        for line in lines:
            er.assert_read_only_command(line)
        self.assertTrue(all("w2@" not in line for line in lines))
        self.assertEqual(sum(1 for line in lines if line == "i2ctransfer -y 0 w1@0x50 0x00 r32"), 2)
        self.assertTrue(all("i2cdetect" not in line or line == er.TOOL_SCRIPT for line in lines))
        joined = "\n".join(lines)
        self.assertNotIn(SECRET, joined)

    def test_path_layout_does_not_overwrite(self):
        root = Path(self.id().replace(".", "_"))
        # Use a temp dir under the system temp via unittest.
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first = er.allocate_dump_dir(root, "S21 Pro", "192.168.1.20", NOW)
            self.assertEqual(first, root / "S21_Pro" / "192.168.1.20" / "2026-11-09")
            second = er.allocate_dump_dir(root, "S21 Pro", "192.168.1.20", NOW)
            self.assertEqual(
                second,
                root / "S21_Pro" / "192.168.1.20" / "2026-11-09T153000Z",
            )
            self.assertEqual(er.sanitize_component("../etc"), "etc")
            with self.assertRaises(ValueError):
                er.sanitize_component("...")
            with self.assertRaises(ValueError):
                er.validate_host("192.168.1.20;reboot")


class DumpFlowTests(unittest.TestCase):
    def test_matching_reads_write_metadata_and_checksums(self):
        image = bytes(range(256))
        miner = ScriptedMiner(image)
        session = er.CommandSession(miner.runner, allow_16bit=False)
        with self._tmp() as root:
            result = er.execute_dump(session, target(), root, NOW)
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.status, "ok")
            self.assertFalse(result.metadata["hardware_tested"])
            self.assertTrue(result.metadata["read_only"])
            blob = json.dumps(result.metadata)
            self.assertNotIn(SECRET, blob)
            self.assertNotIn("i2cset", blob)
            board = result.metadata["boards"][0]
            self.assertEqual(board["hashboard_index"], 0)
            self.assertEqual(board["i2c_address"], "0x50")
            self.assertEqual(board["sha256"], hashlib.sha256(image).hexdigest())
            saved = (result.directory / "hb0-0x50.bin").read_bytes()
            self.assertEqual(saved, image)
            sums = (result.directory / "SHA256SUMS").read_text()
            self.assertIn(board["sha256"], sums)
            self.assertEqual(result.metadata["firmware_version"], "NAME=VNish-test")
            self.assertEqual(result.metadata["identity"]["device_tree_model"], "Amlogic S21 test")
            self.assertTrue(result.metadata["identity"]["is_root"])
            self.assertEqual(miner.transfer_counts["0x50"], 16)
            self.assertFalse(any("w2@" in command for command in miner.commands))
            self.assertFalse(any(command.startswith("i2cdetect") for command in miner.commands))

    def test_mismatch_keeps_both_copies(self):
        image = bytes(range(256))
        other = bytearray(image)
        other[0] = 0xFF
        miner = ScriptedMiner(image, bytes(other), present=(0,))
        session = er.CommandSession(miner.runner)
        with self._tmp() as root:
            result = er.execute_dump(session, target(boards=(0,)), root, NOW)
            self.assertEqual(result.exit_code, 3)
            self.assertEqual(result.status, "mismatch")
            self.assertFalse((result.directory / "hb0-0x50.bin").exists())
            self.assertEqual((result.directory / "hb0-0x50.read1.bin").read_bytes(), image)
            self.assertEqual((result.directory / "hb0-0x50.read2.bin").read_bytes(), bytes(other))

    def test_sysfs_is_preferred_over_raw_transfers(self):
        image = bytes([0x05]) + bytes(255)
        miner = ScriptedMiner(image, sysfs=True, present=(0,))
        session = er.CommandSession(miner.runner)
        with self._tmp() as root:
            result = er.execute_dump(session, target(boards=(0,)), root, NOW)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.metadata["boards"][0]["method"], "sysfs")
        self.assertEqual(miner.dd_counts["0050"], 2)
        self.assertFalse(any(" w1@" in command for command in miner.commands))
        self.assertEqual(miner.uploads, [])

    def test_absent_board_fails_closed_unless_allowed(self):
        image = bytes(range(256))
        miner = ScriptedMiner(image, present=(0,))
        session = er.CommandSession(miner.runner)
        with self._tmp() as root:
            result = er.execute_dump(session, target(), root, NOW)
            self.assertEqual(result.exit_code, 2)
            self.assertTrue((result.directory / "hb0-0x50.bin").exists())
            self.assertFalse((result.directory / "hb1-0x51.bin").exists())

        miner = ScriptedMiner(image, present=(0,))
        session = er.CommandSession(miner.runner)
        later = NOW.replace(minute=31)
        with self._tmp() as root:
            result = er.execute_dump(session, target(allow_absent=True), root, later)
        self.assertEqual(result.exit_code, 0)

    def test_static_reader_uploads_only_when_asked(self):
        image = bytes(range(256))
        miner = ScriptedMiner(image, present=(0,))
        # Hide i2ctransfer and i2cdump by wrapping the runner.
        def runner(command, binary):
            if command == er.TOOL_SCRIPT:
                text = "\n".join(
                    [
                        "TOOL i2cdetect MISSING",
                        "TOOL i2cdump MISSING",
                        "TOOL i2cget /usr/sbin/i2cget",
                        "TOOL i2ctransfer MISSING",
                        "TOOL dd /bin/dd",
                        "TOOL sha256sum MISSING",
                        "TOOL busybox /bin/busybox",
                    ]
                )
                miner.commands.append(command)
                return 0, text.encode() + b"\n", ""
            return miner.runner(command, binary)

        session = er.CommandSession(runner, uploader=miner.upload)
        spec = target(
            boards=(0,),
            allow_tmp_upload=True,
            reader_local_path="/opt/build/eeprom-read-aarch64",
        )
        with self._tmp() as root:
            result = er.execute_dump(session, spec, root, NOW)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.metadata["boards"][0]["method"], "static-reader")
        self.assertEqual(miner.uploads, ["/opt/build/eeprom-read-aarch64"])
        self.assertTrue(any(command.startswith(er.READER_REMOTE + " ") for command in miner.commands))
        self.assertFalse(any("i2cset" in command for command in miner.commands))

    def test_preflight_skips_eeprom_bytes(self):
        miner = ScriptedMiner(bytes(range(256)))
        session = er.CommandSession(miner.runner)
        with self._tmp() as root:
            result = er.execute_preflight(session, target(skip_probe=True), root, NOW)
            self.assertEqual(result.exit_code, 0)
            self.assertTrue((result.directory / "preflight.json").is_file())
            self.assertFalse(any(path.suffix == ".bin" for path in result.directory.iterdir()))
            self.assertFalse(any(" w1@" in command for command in miner.commands))
            self.assertIn("uid=0", result.metadata["identity"]["id"])

    def test_not_root_writes_preflight_and_blocks_dump(self):
        miner = ScriptedMiner(bytes(range(256)))

        def wrapped(command, binary):
            if command == "id":
                miner.commands.append(command)
                return 0, b"uid=1000(miner)\n", ""
            return miner.runner(command, binary)

        session = er.CommandSession(wrapped)
        with self._tmp() as root:
            with self.assertRaises(er.GateError):
                er.execute_dump(session, target(boards=(0,)), root, NOW)
            preflight = list(root.glob("_preflight/*/*/preflight.json"))
            self.assertEqual(len(preflight), 1)
            body = json.loads(preflight[0].read_text())
            self.assertFalse(body["ready_to_dump"])
            self.assertNotIn(SECRET, preflight[0].read_text())

    def _tmp(self):
        import tempfile

        class _PathDir:
            def __enter__(self):
                self._raw = tempfile.TemporaryDirectory()
                return Path(self._raw.__enter__())

            def __exit__(self, exc_type, exc, tb):
                return self._raw.__exit__(exc_type, exc, tb)

        return _PathDir()


class CliTests(unittest.TestCase):
    def test_plan_prints_reads_and_does_not_connect(self):
        import io
        from contextlib import redirect_stdout

        import dump_eeprom

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = dump_eeprom.main(
                ["plan", "--host", "192.168.1.20", "--user", "root", "--model", "S21-Pro"]
            )
        text = stdout.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("i2ctransfer -y 0 w1@0x50 0x00 r32", text)
        self.assertNotIn("i2cset", text)
        self.assertNotIn("w2@", text)

    def test_dump_requires_a_model(self):
        import dump_eeprom

        code = dump_eeprom.main(["dump", "--host", "192.168.1.20", "--user", "root"])
        self.assertEqual(code, 1)


class ParserTests(unittest.TestCase):
    def test_i2cdump_round_trip(self):
        data = bytes((index * 3) & 0xFF for index in range(256))
        lines = ["     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f    0123456789abcdef"]
        for offset in range(0, 256, 16):
            chunk = data[offset : offset + 16]
            hexes = " ".join(f"{byte:02x}" for byte in chunk)
            lines.append(f"{offset:02x}: {hexes}    ................")
        self.assertEqual(er.parse_i2cdump("\n".join(lines)), data)

    def test_i2cdump_xx_is_a_failed_read(self):
        text = "00: XX 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n"
        with self.assertRaises(er.ReadError):
            er.parse_i2cdump(text)


if __name__ == "__main__":
    unittest.main()
