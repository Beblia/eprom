# Dump folder layout

Real captures land here and are gitignored. This file is the exception.

```
dumps/<model>/<serial-or-ip>/<date>/
```

| Piece | Meaning |
| --- | --- |
| `model` | Operator-supplied, for example `S21-Pro` or `S21-XP`. Spaces become underscores. |
| `serial-or-ip` | Miner serial if you pass `--serial`. Otherwise the miner IP. This is not the hashboard serial inside the EEPROM. |
| `date` | UTC day `YYYY-MM-DD`. If that folder already exists, the script uses `YYYY-MM-DDTHHMMSSZ` and does not overwrite. |

A completed read looks like:

```
dumps/S21-Pro/192.168.1.20/2026-11-09/
  metadata.json
  SHA256SUMS
  hb0-0x50.bin
  hb0-0x50.sha256
  hb1-0x51.bin
  hb1-0x51.sha256
  hb2-0x52.bin
  hb2-0x52.sha256
```

Hashboard index 0 is I2C `0x50`, index 1 is `0x51`, index 2 is `0x52`.

If the two reads differ, the script writes `hbN-0xAA.read1.bin` and `hbN-0xAA.read2.bin` and does not pick a winner.

Preflight reports (no EEPROM bytes) go under `dumps/_preflight/<ip>/<timestamp>/preflight.json`. Those are gitignored too.

Nothing in this tree has been captured from a miner yet.
