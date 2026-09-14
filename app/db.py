import os
import re
import sqlite3
from pathlib import Path
from contextlib import contextmanager


BASE_DIR = Path(__file__).resolve().parent.parent
MIGRATIONS_DIR = BASE_DIR / "migrations"
SQLITE_PATH = Path(os.getenv("DATA_DIR", "/tmp/unified_ai_lab")) / "lab.db"
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
PRODUCTION = os.getenv("APP_ENV", "production" if os.getenv("RENDER") else "development").lower() == "production"


class CompatRow(dict):
    def __init__(self, values, columns):
        super().__init__(zip(columns, values))
        self._values = tuple(values)
        self._columns = tuple(columns)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


class CompatCursor:
    def __init__(self, cursor, postgres=False):
        self.cursor = cursor
        self.postgres = postgres

    def _row(self, row):
        if row is None:
            return None
        if isinstance(row, CompatRow):
            return row
        if self.postgres:
            return CompatRow(row, [d.name for d in self.cursor.description])
        return row

    def fetchone(self):
        return self._row(self.cursor.fetchone())

    def fetchall(self):
        return [self._row(row) for row in self.cursor.fetchall()]

    def __iter__(self):
        for row in self.cursor:
            yield self._row(row)


class Database:
    def __init__(self, connection, postgres):
        self.connection = connection
        self.postgres = postgres

    def _sql(self, sql):
        if self.postgres:
            return sql.replace("?", "%s")
        return sql

    def execute(self, sql, params=()):
        if self.postgres:
            cur = self.connection.cursor()
            cur.execute(self._sql(sql), params)
            return CompatCursor(cur, postgres=True)
        cur = self.connection.cursor()
        cur.execute(self._sql(sql), params)
        return CompatCursor(cur, postgres=False)

    def executescript(self, sql):
        if self.postgres:
            for statement in _split_sql(sql):
                if statement.strip():
                    self.execute(statement)
        else:
            self.connection.executescript(sql)

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()


def _split_sql(sql):
    return [part.strip() for part in sql.split(";") if part.strip()]


def _sqlite_schema(sql):
    sql = re.sub(r"\bBIGSERIAL\b", "INTEGER", sql, flags=re.I)
    sql = re.sub(r"\bSERIAL\b", "INTEGER", sql, flags=re.I)
    sql = re.sub(r"\bBIGINT\b", "INTEGER", sql, flags=re.I)
    sql = re.sub(r"\bTIMESTAMPTZ\b", "TEXT", sql, flags=re.I)
    sql = re.sub(r"\bJSONB\b", "TEXT", sql, flags=re.I)
    sql = re.sub(r"\bBOOLEAN\b", "INTEGER", sql, flags=re.I)
    sql = sql.replace("GENERATED ALWAYS AS IDENTITY", "")
    sql = re.sub(r"\bDEFAULT\s+FALSE\b", "DEFAULT 0", sql, flags=re.I)
    sql = re.sub(r"\bDEFAULT\s+TRUE\b", "DEFAULT 1", sql, flags=re.I)
    return sql


def _migration_text():
    return (MIGRATIONS_DIR / "001_initial.sql").read_text(encoding="utf-8")


def run_migrations(db):
    db.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    db.commit()
    version = "001_initial"
    exists = db.execute("SELECT version FROM schema_migrations WHERE version=?", (version,)).fetchone()
    if not exists:
        db.executescript(_migration_text())
        db.execute("INSERT INTO schema_migrations(version) VALUES(?)", (version,))
        db.commit()


def _sqlite_connection():
    SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(SQLITE_PATH)
    connection.row_factory = sqlite3.Row
    db = Database(connection, postgres=False)
    db.executescript(_sqlite_schema(_migration_text()))
    run_migrations(db)
    return db


def get_db():
    if DATABASE_URL:
        try:
            import psycopg
            connection = psycopg.connect(DATABASE_URL, connect_timeout=10)
            db = Database(connection, postgres=True)
            run_migrations(db)
            return db
        except Exception:
            if PRODUCTION:
                raise
    if PRODUCTION and not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is required in production")
    return _sqlite_connection()


def metadata_status():
    if not DATABASE_URL:
        return {"metadata_store": "unavailable", "reason": "DATABASE_URL_missing", "backend": "none" if PRODUCTION else "sqlite_development_fallback"}
    try:
        db = get_db()
        db.execute("SELECT 1").fetchone()
        db.close()
        return {"metadata_store": "connected", "backend": "postgresql"}
    except Exception:
        return {"metadata_store": "unavailable", "backend": "postgresql"}


@contextmanager
def transaction():
    db = get_db()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
