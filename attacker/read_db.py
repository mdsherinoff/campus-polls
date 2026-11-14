"""Insider attack 1: read every ballot straight out of the database file.

    python attacker/read_db.py
"""
from _common import BOLD, END, GREEN, RED, current_poll, open_db, short
import json

conn = open_db()
e = current_poll(conn)
rows = conn.execute("SELECT seq, voter_code, payload FROM ballots WHERE election_id=? ORDER BY seq", (e["id"],)).fetchall()
print(f"{BOLD}Poll #{e['id']} ({e['mode']} mode): {len(rows)} ballots in the database{END}\n")
print(f"{'#':>3}  {'voting code':<12} what is stored")
for r in rows:
    p = json.loads(r["payload"])
    if "choice" in p:
        print(f"{r['seq']:>3}  {RED}{(r['voter_code'] or '-'):<12}{END} {RED}{p['choice']}{END}")
    else:
        print(f"{r['seq']:>3}  {GREEN}{'(not stored)':<12}{END} " + ", ".join(short(c, 8) for c in p["ciphertexts"]))
