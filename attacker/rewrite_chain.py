"""Insider attack 3: cover your tracks by recomputing the SHA-256 hash chain.

    python attacker/rewrite_chain.py

Every hash is recomputed so the chain lines up again. What the attacker cannot
do is make new Ed25519 signatures, because the server's private key is not in
the database.
"""
from _common import BOLD, END, GREEN, RED, YELLOW, current_poll, entry_hash, open_db

conn = open_db()
e = current_poll(conn)
if e["mode"] != "protected":
    raise SystemExit("Basic mode has no hash chain at all, so there is nothing to cover up.")
rows = conn.execute("SELECT * FROM ballots WHERE election_id=? ORDER BY seq", (e["id"],)).fetchall()
prev = "0" * 64
fixed = 0
for r in rows:
    h = entry_hash(prev, e["id"], r["seq"], r["created_at"], r["payload"])
    if h != r["entry_hash"] or prev != r["prev_hash"]:
        conn.execute("INSERT OR IGNORE INTO tamper_backup (ballot_id, payload, prev_hash, entry_hash, signature) "
                     "VALUES (?,?,?,?,?)", (r["id"], r["payload"], r["prev_hash"], r["entry_hash"], r["signature"]))
        conn.execute("UPDATE ballots SET prev_hash=?, entry_hash=? WHERE id=?", (prev, h, r["id"]))
        print(f"{RED}entry #{r['seq']}: new hash {h[:16]}...{END}")
        fixed += 1
    prev = h
conn.commit()
print(f"{BOLD}{fixed} hashes recomputed. Every link in the chain matches again.{END}")
print(f"{YELLOW}But the signatures were made with the server's private key, which we don't have.{END}")
