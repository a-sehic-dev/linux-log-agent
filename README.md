# Linux Log Agent

Local, defensive log analysis in Python. Reads Linux-style `.log` files on disk, stores unique incidents in SQLite, and prints a ranked report.

No network scan. No firewall changes. No payload. Own files / lab samples only.

Part of a Python + Linux **blue-team** portfolio ([Sedin Šehić](https://github.com/a-sehic-dev)).

## What it does

1. Walks a folder of `.log` / `.bak` files
2. Classifies lines: failed SSH, invalid users, syslog `WARNING`/`ERROR`/`CRITICAL`, HTTP 4xx/5xx
3. Extracts IPv4 addresses
4. Inserts rows with `INSERT OR IGNORE` (duplicate `description` is skipped)
5. Reports counts, top source IPs, and repeat IPs (`HAVING COUNT(*) >= threshold`)

## Requirements

- Python 3.8+
- Standard library only (`os`, `re`, `sqlite3`, `argparse`, `unittest`)

## Run

```bash
python agent.py
```

Default input is `samples/`. Custom paths:

```bash
python agent.py --logs /var/log --db ./security.db --threshold 5
```

On Windows, keep using the bundled `samples/` or a folder of logs you own. Do not point this at hosts you do not administer.

## Tests

```bash
python -m unittest tests.test_parse
```

## Sample story

The lab logs describe a short burst from documentation IPs (`203.0.113.0/24`, `198.51.100.0/24`):

- repeated SSH failures against `root`
- `/admin` and `/wp-login.php` 404s
- a 500 on `/api/users`
- local disk and database warnings

Re-running the agent must insert **0** new rows if the samples did not change.

## Stack

Python · SQLite · Linux log formats (`auth.log`, `syslog`, nginx access log)

## License

MIT
