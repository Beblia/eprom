# Safety rules

These rules bind every script and document in this repo. The dump tool has been checked with local unit tests only. It has not been run against a miner.

## Hard rules

1. Never write EEPROM until a reviewed dump of that same board exists. Same-board restore is the only write that will be considered later, and it is not implemented.
2. This tool never logs in by itself and never guesses passwords. The operator supplies a password through their own environment. The repo contains no password.
3. D-Central says S21 EEPROM encryption is AES-128. Alex20129's S21+ path is AES-256-CBC. Neither is proven on our hardware. A raw same-board backup does not need the key. This repo does not contain keys and does not treat either cipher as broken.
4. `/dev/i2c-0` addresses `0x50`–`0x52` are an unverified S21/Amlogic hypothesis. Antminer L9 is a different family. The tool refuses an L9 model before any login, and that address map is not a fact for L9.

## Read-path rules

The dump script talks to the miner through one allowlisted command at a time. It has no interactive shell and no EEPROM program path.

- On the unverified S21/Amlogic hypothesis, probes are a one-byte read at `0x50`, `0x51`, and `0x52` on the bus you name (default `/dev/i2c-0`). That map is not used for L9.
- `i2cdetect` is never executed. `i2cdetect -r` forces an SMBus Receive Byte at every address on the bus, and that scan is known to lock write-only chips, including clock chips at `0x69`. `i2cdetect -q` forces SMBus Quick Write at every address, which has corrupted AT24RF08-class EEPROMs. A default `i2cdetect` scan still Quick-Writes addresses outside `0x30–0x37` and `0x50–0x5F`, including the TMP75 sensors on this bus (`0x48`, `0x49`, `0x4C`, `0x4D`, `0x4E` on the S19j Pro map in skot/amlogic-cb-tools).
- The default image is 256 bytes with one word-address byte, then a read. That matches the read length in skot/amlogic-cb-tools (`EEPROM_LEN` 256) and Alex20129/eeprom_tool (24C02, 256 bytes, including its S21+ struct).
- A 16-bit pointer is a different transaction. On an 8-bit chip such as a 24C02, the second byte is stored as data. The script sends that transaction only when you pass both `--addr-bytes 2` and `--confirm-16bit-read`.
- `i2cset`, sysfs stores, `dd of=`, redirects, and shell snippets built from operator strings are rejected.
- The script does not stop the miner, bind an I2C driver, or delete files on the miner.
- Pushing the optional static reader writes `/tmp/eprom-eeprom-read` on the miner filesystem. That path is off unless you pass `--allow-tmp-upload` and a local binary. It is a file copy, and it is still an EEPROM read afterward.

## Dumps

Captures stay on the PC that ran the script, under `dumps/`, and `.gitignore` leaves them untracked. Treat a dump as board-specific calibration, not as a generic image to copy onto another hashboard.
