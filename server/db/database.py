"""
SentinelBash - Database Connection Manager & DAO Tier
Provides thread-safe, WAL-enabled SQLite3 connections and data access objects.
"""

import os
import sqlite3
import contextlib
from typing import Generator, Any, Dict, List, Optional
from datetime import datetime

# Resolve default database path
DEFAULT_DB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))
DEFAULT_DB_PATH = os.path.join(DEFAULT_DB_DIR, "sentinel.db")
DB_PATH = os.environ.get("SENTINEL_DB_PATH", DEFAULT_DB_PATH)


def get_db_path() -> str:
    """Returns the absolute path to the active SQLite database."""
    return os.environ.get("SENTINEL_DB_PATH", DB_PATH)


def configure_sqlite_connection(conn: sqlite3.Connection) -> None:
    """Configures high-performance PRAGMAs for concurrent WAL-mode access."""
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode = WAL;")
    cursor.execute("PRAGMA synchronous = NORMAL;")
    cursor.execute("PRAGMA foreign_keys = ON;")
    cursor.execute("PRAGMA busy_timeout = 10000;")
    cursor.close()


@contextlib.contextmanager
def get_db_connection() -> Generator[sqlite3.Connection, None, None]:
    """Context manager providing a configured SQLite connection."""
    db_file = get_db_path()
    os.makedirs(os.path.dirname(db_file), exist_ok=True)
    conn = sqlite3.connect(db_file, timeout=10.0)
    configure_sqlite_connection(conn)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def query_all(query: str, params: tuple = ()) -> List[Dict[str, Any]]:
    """Executes a SELECT query and returns all rows as dictionaries."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def query_one(query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
    """Executes a SELECT query and returns the first row as a dictionary."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        row = cursor.fetchone()
        return dict(row) if row else None


def execute_stmt(query: str, params: tuple = ()) -> int:
    """Executes an INSERT, UPDATE, or DELETE query and returns rows affected."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.rowcount
