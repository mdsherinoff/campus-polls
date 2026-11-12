"""SQLite storage for Campus Polls."""
import os
import sqlite3
from contextlib import contextmanager

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "data", "campus_polls.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS elections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    poll_key    TEXT NOT NULL,
    mode        TEXT NOT NULL,          -- 'basic' or 'protected'
    status      TEXT NOT NULL,          -- 'open' or 'closed'
    created_at  REAL NOT NULL,
    closed_at   REAL,
    paillier_n  TEXT,                   -- public key (protected mode only)
    paillier_p  TEXT,                   -- private key, held by the election authority
    paillier_q  TEXT,
    key_bits    INTEGER,
    result_json TEXT
);
CREATE TABLE IF NOT EXISTS codes (
    code        TEXT PRIMARY KEY,
    election_id INTEGER NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL,
    source      TEXT
);
CREATE TABLE IF NOT EXISTS ballots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id INTEGER NOT NULL,
    seq         INTEGER NOT NULL,
    created_at  REAL NOT NULL,
    voter_code  TEXT,                   -- stored only by the basic (insecure) system
    payload     TEXT NOT NULL,
    prev_hash   TEXT,
    entry_hash  TEXT,
    signature   TEXT,
    source      TEXT
);
CREATE TABLE IF NOT EXISTS traffic (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id INTEGER,
    created_at  REAL NOT NULL,
    source      TEXT,
    body        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id INTEGER,
    created_at  REAL NOT NULL,
    kind        TEXT NOT NULL,          -- 'info', 'blocked', 'attack', 'warning'
    message     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tamper_backup (
    ballot_id   INTEGER PRIMARY KEY,
    payload     TEXT,
    prev_hash   TEXT,
    entry_hash  TEXT,
    signature   TEXT
);
"""


def connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@contextmanager
def session():
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init():
    with session() as conn:
        conn.executescript(SCHEMA)
