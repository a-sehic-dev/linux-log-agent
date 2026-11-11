import os
import sqlite3
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from linux_log_agent.db import connect, insert_incident
from linux_log_agent.ingest import ingest_directory
from linux_log_agent.parse import classify


class ParseTests(unittest.TestCase):
    def test_failed_ssh(self):
        line = "Nov 11 20:01:11 lab sshd[1102]: Failed password for root from 203.0.113.50 port 53221 ssh2"
        event, severity, ip = classify(line)
        self.assertEqual(event, "FAILED_AUTH")
        self.assertEqual(severity, "WARNING")
        self.assertEqual(ip, "203.0.113.50")

    def test_benign_line_skipped(self):
        line = "Nov 11 20:00:01 lab sshd[1024]: Accepted publickey for sedin from 10.0.0.5 port 51122 ssh2"
        self.assertIsNone(classify(line))

    def test_http_404(self):
        line = '203.0.113.50 - - [11/Nov/2026:20:01:30 +0000] "GET /admin HTTP/1.1" 404 162'
        event, severity, ip = classify(line)
        self.assertEqual(event, "HTTP_CLIENT_ERROR")
        self.assertEqual(severity, "WARNING")
        self.assertEqual(ip, "203.0.113.50")


class DbTests(unittest.TestCase):
    def test_insert_ignore_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "t.db")
            conn = connect(db_path)
            first = insert_incident(
                conn, "a.log", 1, "FAILED_AUTH", "WARNING", "203.0.113.50", "same"
            )
            second = insert_incident(
                conn, "a.log", 2, "FAILED_AUTH", "WARNING", "203.0.113.50", "same"
            )
            conn.close()
            self.assertTrue(first)
            self.assertFalse(second)

    def test_ingest_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "t.db")
            conn = connect(db_path)
            files, inserted, skipped = ingest_directory(
                conn, os.path.join(ROOT, "samples")
            )
            total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            conn.close()
            self.assertEqual(files, 3)
            self.assertGreaterEqual(inserted, 8)
            self.assertEqual(skipped, 0)
            self.assertEqual(total, inserted)


if __name__ == "__main__":
    unittest.main()
