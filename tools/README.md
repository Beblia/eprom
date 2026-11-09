# tools

| File | Role |
| --- | --- |
| `dump_eeprom.py` | CLI Andrey runs on Desktop-2026. Subcommands: `plan`, `preflight`, `dump`. |
| `eprom_read.py` | Command allowlist, parsers, folder layout, metadata. No network import. |
| `eeprom-read.c` | Optional read-only static reader for a miner without i2c-tools. |

Build the reader on a cross toolchain that has Linux I2C headers. The binary is gitignored under `tools/bin/`.

```
aarch64-linux-musl-gcc -static -O2 -Wall -Wextra -o tools/bin/eeprom-read-aarch64 tools/eeprom-read.c
```

Upload it only for a dump that has no sysfs EEPROM node and no `i2ctransfer` / `i2cdump`:

```
py -3 tools/dump_eeprom.py dump --host <ip> --user <ssh-user> --model S21-Pro ^
  --reader tools\bin\eeprom-read-aarch64 --allow-tmp-upload
```

`--allow-tmp-upload` copies that file to `/tmp/eprom-eeprom-read` on the miner and runs it. The copy is a filesystem write. The EEPROM transactions stay reads. The script does not delete the temp file afterward.

This code has not been run on a control board.
