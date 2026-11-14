"""Shared helpers for the attacker scripts (CMPS 380 Group G03).

These scripts attack only our own Campus Polls demo. The "insider" scripts open
the database file directly, the way someone with access to the server could.
"""
import json
import math
import os
import secrets
import sqlite3
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(HERE, "..", "data", "campus_polls.db"))
OPTIONS = {
    "food": ["Zatar w Zeit", "Teatime", "Hot Bake", "Karak wa Maqanees"],
    "football": ["Messi", "Ronaldo"],
}

RED, GREEN, YELLOW, BOLD, END = "\033[91m", "\033[92m", "\033[93m", "\033[1m", "\033[0m"
if os.name == "nt":
    os.system("")  # turn on colours in the Windows terminal


def open_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def current_poll(conn):
    e = conn.execute("SELECT * FROM elections ORDER BY id DESC LIMIT 1").fetchone()
    if not e:
        raise SystemExit("No poll has been opened yet.")
    return e


def short(s, n=18):
    s = str(s)
    return s if len(s) <= n * 2 + 3 else f"{s[:n]}...{s[-6:]}"


def encrypt(m, n):
    """Paillier encryption with the PUBLIC key only: c = (1 + m*n) * r^n mod n^2."""
    n2 = n * n
    while True:
        r = secrets.randbelow(n - 1) + 1
        if math.gcd(r, n) == 1:
            break
    return (1 + m * n) * pow(r, n, n2) % n2


def entry_hash(prev_hash, election_id, seq, created_at, payload_json):
    import hashlib
    material = f"{prev_hash}|{election_id}|{seq}|{created_at:.3f}|{payload_json}"
    return hashlib.sha256(material.encode()).hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as err:
        return json.loads(err.read() or b"{}")


def get(url):
    with urllib.request.urlopen(url, timeout=20) as r:
        return json.loads(r.read())
