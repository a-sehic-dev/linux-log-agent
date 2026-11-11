"""Walk a directory of .log / .bak files and ingest classified lines."""

import os

from .db import insert_incident
from .parse import classify


def iter_log_files(log_dir):
    for name in sorted(os.listdir(log_dir)):
        if not (name.endswith(".log") or name.endswith(".bak")):
            continue
        path = os.path.join(log_dir, name)
        if os.path.isfile(path):
            yield name, path


def ingest_directory(conn, log_dir):
    inserted = 0
    skipped = 0
    scanned_files = 0

    for name, path in iter_log_files(log_dir):
        scanned_files += 1
        with open(path, "r", encoding="utf-8") as handle:
            for line_no, raw in enumerate(handle, 1):
                classified = classify(raw)
                if classified is None:
                    continue
                event_type, severity, ip = classified
                description = raw.strip()
                if insert_incident(
                    conn, name, line_no, event_type, severity, ip, description
                ):
                    inserted += 1
                else:
                    skipped += 1

    conn.commit()
    return scanned_files, inserted, skipped
