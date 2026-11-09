# eprom

**UNTESTED AGAINST HARDWARE.** This repo is the read-only workflow for dumping Antminer hashboard EEPROMs from Andrey's Windows PC (`Desktop-2026`). Nothing here has been pointed at a miner. The tool never logs in by itself and never guesses a password. The operator supplies a password through their own environment.

Antminer L9 (shop `10.2.21.8` and `10.2.21.26`) is a different board family from Amlogic S21 Pro / S21 XP (shop `10.2.11.42` and `10.2.11.40`). The `/dev/i2c-0` addresses `0x50`–`0x52` are an unverified S21/Amlogic hypothesis only. They have to be verified per family, and they are not a fact for L9. `--model L9` or `--model "Antminer L9"` is refused before any login.

Write is not implemented. [SAFETY.md](SAFETY.md) is the rule set. EEPROM write stays blocked until Andrey has reviewed a successful read-only dump of that same board.

## What you pass in

The script has no built-in address, login, or password.

| Input | Where it goes |
| --- | --- |
| Miner IP or hostname | `--host` or `EPROM_SSH_HOST` |
| SSH user | `--user` or `EPROM_SSH_USER` |
| SSH password | The operator's own environment (`EPROM_SSH_PASSWORD`). The tool does not guess one. A prompt is the fallback if that variable is unset. `--password` works and shows up in the process list. |
| SSH host key | `--host-key SHA256:...` or `--accept-new-host` the first time you have checked the fingerprint |
| Model label | `--model`, for example `S21-Pro` or `S21-XP`. `L9` and `Antminer L9` are refused. |
| Miner serial | Optional `--serial`. If you omit it, the folder name uses the IP. |

## Layout

```
SAFETY.md                 hard rules
README.md                 this file
requirements.txt          paramiko
docs/read-workflow.md     step-by-step read plan
docs/write-path-later.md  write is gated; open questions
tools/dump_eeprom.py      CLI (plan, preflight, dump)
tools/eprom_read.py       allowlist, parsers, metadata
tools/eeprom-read.c       optional static reader source
dumps/<model>/<serial-or-ip>/<date>/
```

Real captures under `dumps/` are gitignored. See [dumps/README.md](dumps/README.md).

## Run it from Desktop-2026

Python 3.9 or newer, then:

```
py -3 -m pip install -r requirements.txt
py -3 tools/dump_eeprom.py plan --host 192.168.1.20 --user root --model S21-Pro
py -3 tools/dump_eeprom.py preflight --host 192.168.1.20 --user root --accept-new-host
py -3 tools/dump_eeprom.py dump --host 192.168.1.20 --user root --model S21-Pro --host-key SHA256:...
```

`plan` prints the commands and does not connect. For an S21 Pro or S21 XP label, `preflight` checks SSH, `id`, `uname -a`, `/dev/i2c*`, which read tools exist, and (unless `--skip-probe`) one read at `0x50`, `0x51`, and `0x52`. That address list is the unverified S21/Amlogic hypothesis, not an L9 map. `dump` reads each answering EEPROM twice, compares the copies, and writes the folder, `metadata.json`, and SHA-256 sums. An L9 model is refused in `plan`, `preflight`, and `dump` with no network and no login.

Python and paramiko are the runner because the password can stay in the prompt, each remote command is one allowlisted read, and a sysfs EEPROM read returns raw bytes. The script does not open an interactive shell and does not use SSH keys or an agent.

Exit codes: `0` ready or a matching dump, `1` local usage error, `2` the miner is not in a state to dump (or a present board failed), `3` the two reads differed, `4` SSH failed.

The read procedure, the 256-byte default, and the fallbacks are in [docs/read-workflow.md](docs/read-workflow.md).
