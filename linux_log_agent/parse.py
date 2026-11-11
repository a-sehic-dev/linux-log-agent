"""Classify local log lines. Lab / own-host files only."""

import re

IP_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

# First matching rule wins. Patterns are for common Linux / web logs.
RULES = (
    (
        "FAILED_AUTH",
        "WARNING",
        re.compile(r"Failed password for .* from (" + IP_REGEX + r")"),
    ),
    (
        "INVALID_USER",
        "WARNING",
        re.compile(r"Invalid user .* from (" + IP_REGEX + r")"),
    ),
    (
        "HTTP_SERVER_ERROR",
        "ERROR",
        re.compile(r'"[A-Z]+ [^"]+" 5\d{2} '),
    ),
    (
        "HTTP_CLIENT_ERROR",
        "WARNING",
        re.compile(r'"[A-Z]+ [^"]+" 4\d{2} '),
    ),
    (
        "SYSLOG_CRITICAL",
        "CRITICAL",
        re.compile(r"\bCRITICAL\b"),
    ),
    (
        "SYSLOG_ERROR",
        "ERROR",
        re.compile(r"\bERROR\b"),
    ),
    (
        "SYSLOG_WARNING",
        "WARNING",
        re.compile(r"\bWARNING\b"),
    ),
)


def extract_ip(line):
    found = re.findall(IP_REGEX, line)
    return found[0] if found else "N/A"


def classify(line):
    """Return (event_type, severity, ip) or None if the line is not an incident."""
    text = line.strip()
    if not text:
        return None
    for event_type, severity, pattern in RULES:
        if pattern.search(text):
            return event_type, severity, extract_ip(text)
    return None
