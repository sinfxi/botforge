from pathlib import Path
import sqlite3

root = Path(__file__).resolve().parents[1]
migration = (root / "database" / "migrations" / "0001_initial.sql").read_text(encoding="utf-8")
schema = (root / "database" / "schema.sql").read_text(encoding="utf-8")

for label, sql in (("migration", migration), ("schema", schema)):
    connection = sqlite3.connect(":memory:")
    connection.executescript(sql)
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    expected = {"users", "sessions", "bots", "submissions", "notifications", "audit_logs"}
    missing = expected - tables
    if missing:
        raise SystemExit(f"{label}: missing tables: {', '.join(sorted(missing))}")
    connection.close()
    print(f"{label}: OK")
