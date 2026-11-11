# Defensive Python + Linux — tool series

One public repo at a time. Empty repos and tutorial dumps hurt more than they help.

| # | Tool | Status | What a client / hiring manager sees |
|---|------|--------|-------------------------------------|
| 1 | **linux-log-agent** | this repo | Parse Linux logs → SQLite → incident report |
| 2 | file-integrity-monitor | planned | SHA-256 baseline, alert if a file changed |
| 3 | auth-failure-watch | planned | Daily failed-SSH summary from `auth.log` |
| 4 | secret-scanner | planned | Find leaked keys in *your* project tree |
| 5 | http-access-analyzer | planned | nginx/Apache 4xx/5xx, noisy paths |
| 6 | log-hygiene | planned | Size check + rotate/archive |
| 7 | ioc-search | planned | Hunt one IP/hash across log archives |
| 8 | linux-hardening-report | planned | Read-only checks on a machine you own |
| 9 | incident-reporter | planned | Markdown/JSON report from SQLite |
| 10 | disk-cron-health | planned | Disk fill + failed jobs, local only |

Work this can support later: junior SOC / detection engineering intern, SMB log automation, internal tooling. Not pentest-as-a-service and not exploit development.
