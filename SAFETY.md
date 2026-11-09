# Safety rules

These rules bind every script and document in this repo. The dump tool has been checked with local unit tests only. It has not been run against a miner.

## Hard rules

1. EEPROM write stays blocked until Andrey has reviewed a successful read-only dump of that same board. Same-board restore is the only write that will be considered later, and it is not implemented.
2. Credentials are runtime inputs. The repo has no miner IP, SSH user, or password. Pass them on the command line, in the environment, or at the prompt.
3. S21 AES-128 edit and cross-board clone stay unsolved. A raw same-board backup does not need the key. This repo does not contain keys and does not treat the cipher as broken.

## Read-path rules

The dump script talks to the miner through one allowlisted command at a time. It has no interactive shell and no EEPROM program path.

- Probes are a one-byte read at `0x50`, `0x51`, and `0x52` on the bus you name (default `/dev/i2c-0`).
- `i2cdetect` is never executed. `i2cdetect -r` forces an SMBus Receive Byte at every address on the bus, and that scan is known to lock write-only chips, including clock chips at `0x69`. `i2cdetect -q` forces SMBus Quick Write at every address, which has corrupted AT24RF08-class EEPROMs. A default `i2cdetect` scan still Quick-Writes addresses outside `0x30–0x37` and `0x50–0x5F`, including the TMP75 sensors on this bus (`0x48`, `0x49`, `0x4C`, `0x4D`, `0x4E` on the S19j Pro map in skot/amlogic-cb-tools).
- The default image is 256 bytes with one word-address byte, then a read. That matches the read length in skot/amlogic-cb-tools (`EEPROM_LEN` 256) and Alex20129/eeprom_tool (24C02, 256 bytes, including its S21+ struct).
- A 16-bit pointer is a different transaction. On an 8-bit chip such as a 24C02, the second byte is stored as data. The script sends that transaction only when you pass both `--addr-bytes 2` and `--confirm-16bit-read`.
- `i2cset`, sysfs stores, `dd of=`, redirects, and shell snippets built from operator strings are rejected.
- The script does not stop the miner, bind an I2C driver, or delete files on the miner.
- Pushing the optional static reader writes `/tmp/eprom-eeprom-read` on the miner filesystem. That path is off unless you pass `--allow-tmp-upload` and a local binary. It is a file copy, and it is still an EEPROM read afterward.

## Dumps

Captures stay on the PC that ran the script, under `dumps/`, and `.gitignore` leaves them untracked. Treat a dump as board-specific calibration, not as a generic image to copy onto another hashboard.
