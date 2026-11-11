"""SQL aggregations for a terminal incident report."""


def print_report(conn, threshold=2):
    cursor = conn.cursor()

    print("=" * 68)
    print("              LINUX LOG AGENT  —  INCIDENT REPORT")
    print("=" * 68)

    total = cursor.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    print(f"Unique incidents stored: {total}")

    print("\nBy severity:")
    rows = cursor.execute(
        """
        SELECT severity, COUNT(*) AS n
        FROM incidents
        GROUP BY severity
        ORDER BY n DESC
        """
    ).fetchall()
    if rows:
        for severity, n in rows:
            print(f"  {severity:<12} {n}")
    else:
        print("  (none)")

    print("\nTop source IPs:")
    print(f"  {'IP ADDRESS':<20} {'EVENTS':<8}")
    print("  " + "-" * 30)
    top = cursor.execute(
        """
        SELECT ip, COUNT(*) AS n
        FROM incidents
        WHERE ip != 'N/A'
        GROUP BY ip
        ORDER BY n DESC
        """
    ).fetchall()
    if top:
        for ip, n in top:
            print(f"  {ip:<20} {n:<8}")
    else:
        print("  (none)")

    print(f"\nRepeat sources (threshold >= {threshold}):")
    repeats = cursor.execute(
        """
        SELECT ip, COUNT(*) AS n
        FROM incidents
        WHERE ip != 'N/A'
        GROUP BY ip
        HAVING COUNT(*) >= ?
        ORDER BY n DESC
        """,
        (threshold,),
    ).fetchall()
    if repeats:
        for ip, n in repeats:
            print(f"  [ALERT] {ip} appeared {n} times")
    else:
        print("  none")

    print("\nBy event type:")
    types = cursor.execute(
        """
        SELECT event_type, COUNT(*) AS n
        FROM incidents
        GROUP BY event_type
        ORDER BY n DESC
        """
    ).fetchall()
    for event_type, n in types:
        print(f"  {event_type:<20} {n}")

    print("=" * 68)
