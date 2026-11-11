#!/usr/bin/env python3
"""Linux Log Agent — local defensive parser. No scanning, no firewall changes."""

import argparse
import os
import sys

from linux_log_agent.db import connect
from linux_log_agent.ingest import ingest_directory
from linux_log_agent.report import print_report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Parse local Linux-style logs into SQLite and print an incident report."
    )
    parser.add_argument(
        "--logs",
        default=os.path.join(BASE_DIR, "samples"),
        help="Directory with .log / .bak files (default: ./samples)",
    )
    parser.add_argument(
        "--db",
        default=os.path.join(BASE_DIR, "security.db"),
        help="SQLite database path (default: ./security.db)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=2,
        help="Repeat-IP alert threshold (default: 2)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    log_dir = os.path.abspath(args.logs)
    if not os.path.isdir(log_dir):
        print(f"Log directory not found: {log_dir}", file=sys.stderr)
        return 1

    print("[*] Linux Log Agent")
    print(f"[*] Logs: {log_dir}")
    print(f"[*] Database: {os.path.abspath(args.db)}")

    conn = connect(args.db)
    try:
        files, inserted, skipped = ingest_directory(conn, log_dir)
        print(
            f"[*] Scanned {files} file(s). New: {inserted} | Duplicates skipped: {skipped}\n"
        )
        print_report(conn, threshold=args.threshold)
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
