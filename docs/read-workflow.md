# Read-only workflow

**UNTESTED AGAINST HARDWARE.** This is the procedure `tools/dump_eeprom.py` implements. It has not been run on a VNish miner. Do a `plan` pass and read the commands before the first SSH session. The tool never logs in by itself and never guesses a password. The operator supplies a password through their own environment.

Write stays out of this procedure. See [write-path-later.md](write-path-later.md) and [SAFETY.md](../SAFETY.md).

## Two board families

Antminer L9 (shop `10.2.21.8` and `10.2.21.26`) is a different board family from Amlogic S21 Pro / S21 XP (shop `10.2.11.42` and `10.2.11.40`). The `/dev/i2c-0` addresses `0x50`–`0x52` are an unverified S21/Amlogic hypothesis only. They must be verified per family. They are not documented here as fact for L9. The control board on an L9 may differ, and its EEPROM bus, chip, and addresses are unknown.

`plan`, `preflight`, and `dump` refuse `--model L9`, `--model "Antminer L9"`, and the same words in any letter case. The refusal is local. It does not open a socket and it does not ask for a password.

## What a dump is

For the S21/Amlogic hypothesis only, each hashboard EEPROM is expected on the control board's `/dev/i2c-0`. skot/amlogic-cb-tools maps three S19j Pro boards, and this project is trying that same bus on S21 Pro / S21 XP. That map is still unverified on those machines, and it is not an L9 map:

| Hashboard | I2C address |
| --- | --- |
| 0 | `0x50` |
| 1 | `0x51` |
| 2 | `0x52` |

The script stores one capture as:

```
dumps/<model>/<serial-or-ip>/<YYYY-MM-DD>/
  metadata.json
  SHA256SUMS
  hb0-0x50.bin
  hb0-0x50.sha256
  hb1-0x51.bin
  ...
```

`<serial-or-ip>` is the chassis serial you type, or the miner IP. The hashboard serial lives inside the EEPROM. D-Central says that payload is AES-128, and Alex20129's S21+ path is AES-256-CBC. Neither is proven on our hardware. The folder stores raw bytes and does not claim to have decoded them.

If `YYYY-MM-DD` already exists, the script uses `YYYY-MM-DDTHHMMSSZ` and leaves the older folder alone.

## Chip size used for the read

Two public readers that actually issue an I2C read use 256 bytes and an 8-bit word address:

- [skot/amlogic-cb-tools](https://github.com/skot/amlogic-cb-tools) `src/bin/hashboard_s19jpro.rs` sets `EEPROM_LEN` to 256 and reads `/dev/i2c-0` at `0x50` / `0x51` / `0x52`. Its decoder is the S19j Pro XXTEA path, so the length is the evidence, not the S21 field layout.
- [Alex20129/eeprom_tool](https://github.com/Alex20129/eeprom_tool) `i2c_eeprom.c` is commented as a 24C02 load of 256 bytes at `0x50 + board index`. `eeprom_structure.h` sizes the struct it labels "Antminer S21+" at 256 bytes (16-byte header, 80-byte PT1, 16-byte PT2, 144-byte sweep).

[D-Central's EEPROM overview](https://d-central.tech/understanding-the-role-of-eeprom-in-antminer-devices/) lists the S21 era (S21, S21 Pro, T21) as AT24C16 or AT24C32. That table is not a dump of an S21 Pro or S21 XP. An AT24C16 answers at `0x50` through `0x57` by itself, so it cannot be three separate chips at `0x50`, `0x51`, and `0x52` on one bus. An AT24C32 uses a 16-bit word address and can sit at those three addresses. S21 Pro / S21 XP chip size is unconfirmed.

The default read is therefore 256 bytes, one address byte, in 32-byte chunks. That matches the code that reads, and it does not prove the package is only 256 bytes.

A second address byte is dangerous on an 8-bit part: the chip stores that byte. The script sends a 16-bit pointer only when you pass both `--addr-bytes 2` and `--confirm-16bit-read`. Leave those off until a sysfs EEPROM node reports a longer file, or until the package marking is read on the bench. Prefer the sysfs file when it exists; the kernel driver already knows the address width, and the script only reads the file (`dd if=...`, never `of=`).

D-Central says the S21 family uses AES-128 (`x21_aes`, preamble byte `0x05`). Alex20129's S21+ path is AES-256-CBC. Neither is proven on our hardware. This workflow stores raw bytes and does not decrypt them. A same-board backup does not need the key. Editing or moving an image to another board is unproven.

## Step 0. Review the commands on the PC

```
py -3 tools/dump_eeprom.py plan --host <miner-ip> --user <ssh-user> --model S21-Pro
```

`plan` does not connect. The printed list is the raw `i2ctransfer` path. A live run uses a readable `/sys/bus/i2c/devices/0-0050/eeprom` (and `0051`, `0052`) ahead of that list.

## Step 1. SSH from Desktop-2026

```
py -3 tools/dump_eeprom.py preflight --host <miner-ip> --user <ssh-user> --accept-new-host
```

The tool does not log in by itself and does not guess a password. The operator supplies one through their own environment (`EPROM_SSH_PASSWORD`). If that variable is unset, the S21 path can prompt. It uses that supplied password only (no key file, no agent, no built-in password). The first session needs `--accept-new-host` or `--host-key SHA256:...` after you have checked the fingerprint out of band. The fingerprint is printed and stored in the preflight JSON. An L9 model never reaches this step.

Add `--skip-probe` if the first session should stop before any EEPROM byte is read.

## Step 2. Confirm a root shell and the I2C node

The script runs, and records, only these identity commands:

- `id` (a dump requires `uid=0`)
- `uname -a`
- `ls -l /dev/i2c*`
- `ls -l /sys/bus/i2c/devices`
- `cat /proc/device-tree/model`
- `cat /proc/device-tree/compatible`

VNish exposing a real root shell and `/dev/i2c-0` is the thing this step is there to prove. It is still unverified.

## Step 3. See which read tools exist

A fixed loop runs `command -v` for `i2cdetect`, `i2cdump`, `i2cget`, `i2ctransfer`, `dd`, `sha256sum`, and `busybox`.

`i2cdetect` is never executed. It is only named so the report shows whether i2c-tools is installed.

`i2cdetect -r` forces an SMBus Receive Byte at every address. That scan is known to lock write-only chips, including clock chips at `0x69`. `i2cdetect -q` forces Quick Write, which has corrupted AT24RF08-class EEPROMs. A default scan still Quick-Writes addresses outside `0x30–0x37` and `0x50–0x5F`, and the TMP75 sensors on this bus sit in that range (`0x48`, `0x49`, `0x4C`, `0x4D`, `0x4E` in the skot map). The probe below is three single-address reads instead of a bus scan.

Firmware text is read, if the file is readable, from `/etc/os-release`, `/etc/issue`, `/etc/vnish_version`, `/etc/vnish-version`, `/etc/miner_version`, and `/opt/vnish/version`. Those paths are candidates. A missing file is recorded as missing. The first non-empty line becomes `firmware_version` in the JSON.

## Step 4. Probe 0x50, 0x51, 0x52 (S21/Amlogic hypothesis only)

This step is for an S21 Pro or S21 XP label. It is not a procedure for L9. For each address the script:

1. Runs `test -r /sys/bus/i2c/devices/0-00NN/eeprom`.
2. If `i2ctransfer` exists, runs `i2ctransfer -y 0 r1@0xNN` (one current-address read, no pointer write).
3. Otherwise, if `i2cget` exists, runs `i2cget -y 0 0xNN` with no data address (SMBus Receive Byte, a one-byte read).

Exit status 0 is an ACK. The script does not pass `-f` unless you set `--force-i2c`. A busy device stays a failed probe so it can be read from the report instead of being forced.

## Step 5. Dump each answering chip twice

Read order for each present board:

1. A readable sysfs `eeprom` node, via `dd if=/sys/bus/i2c/devices/0-00NN/eeprom bs=256 count=32` (8192-byte cap). Two reads.
2. Else `i2ctransfer -y <bus> w1@0xNN <offset> r<1-32>`, repeated across the 256-byte image. The single write byte is the word address. No data byte follows it. The whole image is read twice.
3. Else `i2cdump -y -r 0-255 <bus> 0xNN b` (byte mode, 256 registers, non-interactive). Twice.
4. Else the static reader in [the fallback](#fallback-when-i2c-tools-are-missing).

The two copies are compared on the PC. When they match, the folder gets `hb<index>-0x<addr>.bin`. When they differ, it gets `.read1.bin` and `.read2.bin` and the run exits 3. The script does not choose a winner.

SHA-256 is computed locally and written to `hbN-0xAA.sha256` and `SHA256SUMS`. Miner-side `sha256sum` is not required.

`metadata.json` records IP, SSH user, model, serial (or null), firmware version, UTC time, hashboard index, I2C address, method, length, both hashes, the host-key fingerprint, `id`, `uname`, and `hardware_tested: false`. The command list is included. The password is not.

A selected board that does not ACK fails the dump (exit 2) so a missing chain is obvious. The boards that did match are still saved. `--allow-absent` turns a missing board into a warning.

## Fallback when i2c-tools are missing

VNish images often ship without `i2ctransfer`. Use the first method that exists:

1. **sysfs** — `/sys/bus/i2c/devices/0-0050/eeprom` (and `0051`, `0052`). This is a plain file read. The script does not bind a driver and does not write the file. The byte count that comes back is the size the kernel driver knows, which is the safe way to learn whether the part is larger than 256 bytes.
2. **static binary** — build `tools/eeprom-read.c` as a static aarch64 binary (see `tools/README.md`). Run dump with `--reader <file> --allow-tmp-upload`. That copies the file to `/tmp/eprom-eeprom-read` and executes it. The copy is a filesystem write on the miner; the EEPROM traffic is still a pointer byte plus a read. The script does not remove the temp file. Omit the flag and the script will not upload anything.

If none of those exist, preflight finishes with `ready_to_dump: false` and dump does not create a board folder.

## What the first preflight should capture

Run preflight before dump. The JSON under `dumps/_preflight/<ip>/<timestamp>/preflight.json` should answer:

- Did SSH accept the user, and what is the host-key fingerprint?
- Does `id` show `uid=0`?
- What do `uname -a` and the device-tree model say (architecture, Amlogic or not)?
- Is `/dev/i2c-0` present, and what else is under `/sys/bus/i2c/devices`?
- Which of `i2ctransfer`, `i2cdump`, `i2cget`, `dd` exist? (`i2cdetect` may be listed and must not have been run.)
- Are the sysfs nodes `0-0050`, `0-0051`, `0-0052` readable, and did a one-byte read ACK?
- Which candidate firmware file, if any, was readable?

EEPROM contents belong to `dump`, not to this first file. `--skip-probe` drops the one-byte read if you want identity and `/dev/i2c-0` only.

## Stop

Stop when preflight is not ready, when the two reads differ, or when a present board errors. Do not start a write. Do not pass `--addr-bytes 2` on a guess.
