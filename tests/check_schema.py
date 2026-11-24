from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "database" / "migrations"
SCHEMA = ROOT / "database" / "schema.sql"
EXPECTED_TABLES = {"users", "sessions", "bots", "submissions", "notifications", "audit_logs"}
EXPECTED_USER_COLUMNS = {"id", "public_id", "email", "username", "password_hash", "password_salt", "role", "status", "permissions_json"}

def inspect(label: str, connection: sqlite3.Connection) -> None:
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing = EXPECTED_TABLES - tables
    if missing:
        raise AssertionError(f"{label}: missing tables: {', '.join(sorted(missing))}")
    columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
    missing_columns = EXPECTED_USER_COLUMNS - columns
    if missing_columns:
        raise AssertionError(f"{label}: missing users columns: {', '.join(sorted(missing_columns))}")
    indexes = {row[1] for row in connection.execute("PRAGMA index_list(users)")}
    if not any("public_id" in row[1] for row in connection.execute("PRAGMA index_list(users)")):
        raise AssertionError(f"{label}: public_id must be indexed uniquely")
    if not any("username" in row[1] for row in connection.execute("PRAGMA index_list(users)")):
        raise AssertionError(f"{label}: username must be indexed uniquely")

def check_uniqueness(label: str, connection: sqlite3.Connection) -> None:
    values = ("u1", "1234", "u1@accounts.botforge.invalid", "alpha", "hash", "salt")
    connection.execute(
        "INSERT INTO users (id,public_id,email,username,password_hash,password_salt) VALUES (?,?,?,?,?,?)",
        values,
    )
    for column, duplicate in (("public_id", "1234"), ("username", "alpha")):
        try:
            connection.execute(
                f"INSERT INTO users (id,public_id,email,username,password_hash,password_salt) VALUES (?,?,?,?,?,?)",
                ("u2", duplicate, "u2@accounts.botforge.invalid", "beta", "hash", "salt"),
            )
        except sqlite3.IntegrityError:
            connection.rollback()
        else:
            raise AssertionError(f"{label}: duplicate {column} was accepted")
    connection.close()

def main() -> None:
    migration_db = sqlite3.connect(":memory:")
    migration_db.execute("PRAGMA foreign_keys = ON")
    migration_files = sorted(MIGRATIONS.glob("*.sql"))
    if not migration_files:
        raise AssertionError("No migration files found")
    for migration in migration_files:
        migration_db.executescript(migration.read_text(encoding="utf-8"))
    inspect("migrations", migration_db)
    check_uniqueness("migrations", migration_db)
    print(f"migrations: OK ({len(migration_files)} files)")

    schema_db = sqlite3.connect(":memory:")
    schema_db.execute("PRAGMA foreign_keys = ON")
    schema_db.executescript(SCHEMA.read_text(encoding="utf-8"))
    inspect("schema.sql", schema_db)
    check_uniqueness("schema.sql", schema_db)
    print("schema.sql: OK")

if __name__ == "__main__":
    main()
