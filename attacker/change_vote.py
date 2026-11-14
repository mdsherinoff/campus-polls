"""Insider attack 2: secretly change a ballot in the database so it counts for TARGET.

    python attacker/change_vote.py Ronaldo

Basic mode: finds a ballot for someone else and rewrites its choice.
Protected mode: the insider cannot read the ballots, so they overwrite the last
one with a fresh encryption of a vote for TARGET (made with the public key).
"""
import sys
from _common import BOLD, END, RED, YELLOW, canonical, current_poll, encrypt, open_db, OPTIONS
import json

target = " ".join(sys.argv[1:]) or "Ronaldo"
conn = open_db()
e = current_poll(conn)
options = OPTIONS[e["poll_key"]]
if target not in options:
    raise SystemExit(f"Pick one of: {', '.join(options)}")
rows = conn.execute("SELECT * FROM ballots WHERE election_id=? ORDER BY seq", (e["id"],)).fetchall()
if not rows:
    raise SystemExit("No ballots yet.")

if e["mode"] == "basic":
    victim = next((r for r in reversed(rows) if json.loads(r["payload"])["choice"] != target), None)
    if not victim:
        raise SystemExit(f"Every ballot is already for {target}.")
    old = json.loads(victim["payload"])["choice"]
    conn.execute("UPDATE ballots SET payload=? WHERE id=?", (json.dumps({"choice": target}), victim["id"]))
    conn.commit()
    print(f"{RED}{BOLD}Ballot #{victim['seq']} changed: {old} -> {target}{END}")
else:
    victim = rows[-1]
    n = int(e["paillier_n"])
    fake = [str(encrypt(1 if o == target else 0, n)) for o in options]
    conn.execute("INSERT OR IGNORE INTO tamper_backup (ballot_id, payload, prev_hash, entry_hash, signature) "
                 "VALUES (?,?,?,?,?)", (victim["id"], victim["payload"], victim["prev_hash"],
                                        victim["entry_hash"], victim["signature"]))
    conn.execute("UPDATE ballots SET payload=? WHERE id=?", (canonical({"ciphertexts": fake}), victim["id"]))
    conn.commit()
    print(f"{RED}{BOLD}Ballot #{victim['seq']} replaced with an encrypted vote for {target}.{END}")
    print(f"{YELLOW}(We could not read what it said before. Now let's see if anyone notices.){END}")
