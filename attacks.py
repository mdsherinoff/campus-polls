"""Attack simulations for the live demo.

Each attack runs against whichever mode the current poll uses, so the same
button shows the attack succeeding in BASIC mode and being stopped (or, for the
known limitations, still succeeding) in PROTECTED mode.

Every attack result has:
  outcome: 'succeeded' | 'blocked' | 'detected' | 'limitation' | 'info'
  message: what happened, written for the audience
"""
import json
import random
import secrets

import crypto_core as cc
import db
import voting
from voting import LOCK, current_election, log_event, options_of


def _result(outcome, title, message):
    return {"outcome": outcome, "title": title, "message": message}


def _fresh_ballot(e, idx, value=1):
    """Build a ballot body the way a phone would."""
    options = options_of(e)
    if e["mode"] == "protected":
        pub = cc.public_key_from_n(e["paillier_n"])
        return {"ciphertexts": cc.encrypt_vote_vector(pub, idx, len(options), value)}
    return {"choice": options[idx]}


def _backup(conn, row):
    conn.execute(
        "INSERT OR IGNORE INTO tamper_backup (ballot_id, payload, prev_hash, entry_hash, signature) "
        "VALUES (?,?,?,?,?)",
        (row["id"], row["payload"], row["prev_hash"], row["entry_hash"], row["signature"]),
    )


# ------------------------------------------------------------------ 1. insider tampering
def tamper(target_idx=0):
    with LOCK, db.session() as conn:
        e = current_election(conn)
        if not e:
            return _result("info", "Tamper", "No poll yet.")
        options = options_of(e)
        target = options[target_idx]
        rows = conn.execute("SELECT * FROM ballots WHERE election_id=? ORDER BY seq", (e["id"],)).fetchall()
        if e["mode"] == "basic":
            victims = [r for r in rows if json.loads(r["payload"])["choice"] != target]
            if not victims:
                return _result("info", "Tamper", f"No ballots that are not already for {target}.")
            r = random.choice(victims)
            old = json.loads(r["payload"])["choice"]
            _backup(conn, r)
            conn.execute("UPDATE ballots SET payload=? WHERE id=?", (json.dumps({"choice": target}), r["id"]))
            log_event(conn, e["id"], "attack", f"Insider silently changed ballot #{r['seq']} from {old} to {target}.")
            return _result("succeeded", "Insider tampering",
                           f"A dishonest admin changed ballot #{r['seq']} from {old} to {target}. "
                           "Nothing in the system noticed: there is no way to detect the change.")
        if not rows:
            return _result("info", "Tamper", "Cast some votes first.")
        r = rows[-1] if len(rows) < 3 else random.choice(rows[:-1])
        _backup(conn, r)
        body = _fresh_ballot(e, target_idx)
        conn.execute("UPDATE ballots SET payload=? WHERE id=?", (cc.canonical(body), r["id"]))
        log_event(conn, e["id"], "attack",
                  f"Insider replaced encrypted ballot #{r['seq']} with a new encrypted vote for {target}.")
        return _result("detected", "Insider tampering",
                       f"The admin replaced encrypted ballot #{r['seq']} with an encrypted vote for {target}. "
                       "The bulletin board now flags entry "
                       f"#{r['seq']} as ALTERED: its SHA-256 hash no longer matches its contents, "
                       "and the result will not be certified.")


def tamper_rewrite(target_idx=0):
    """A smarter insider also recomputes the hash chain to hide the change."""
    with LOCK, db.session() as conn:
        e = current_election(conn)
        if not e or e["mode"] != "protected":
            return _result("info", "Rewrite chain", "This attack only makes sense against the protected poll.")
        rows = conn.execute("SELECT * FROM ballots WHERE election_id=? ORDER BY seq", (e["id"],)).fetchall()
        if not rows:
            return _result("info", "Rewrite chain", "Cast some votes first.")
        target = options_of(e)[target_idx]
        start = rows[-1] if len(rows) < 3 else random.choice(rows[:-1])
        prev = cc.GENESIS_HASH
        for r in rows:
            if r["seq"] < start["seq"]:
                prev = r["entry_hash"]
                continue
            _backup(conn, r)
            payload = r["payload"]
            if r["id"] == start["id"]:
                payload = cc.canonical(_fresh_ballot(e, target_idx))
            h = cc.entry_hash(prev, e["id"], r["seq"], r["created_at"], payload)
            # The attacker cannot produce the server's Ed25519 signature, so the old one stays.
            conn.execute("UPDATE ballots SET payload=?, prev_hash=?, entry_hash=? WHERE id=?",
                         (payload, prev, h, r["id"]))
            prev = h
        log_event(conn, e["id"], "attack",
                  f"Insider replaced ballot #{start['seq']} and recomputed every hash after it.")
        return _result("detected", "Insider rewrites the hash chain",
                       f"The attacker changed ballot #{start['seq']} to {target} and recomputed all the "
                       "hashes so the chain links up again. It is still caught: without the server's private "
                       "Ed25519 key the attacker cannot re-sign the entries, so their signatures fail. "
                       "Voters' receipts from that point on also no longer match anything on the board.")


def undo_tamper():
    with LOCK, db.session() as conn:
        rows = conn.execute("SELECT * FROM tamper_backup").fetchall()
        for b in rows:
            conn.execute("UPDATE ballots SET payload=?, prev_hash=?, entry_hash=?, signature=? WHERE id=?",
                         (b["payload"], b["prev_hash"], b["entry_hash"], b["signature"], b["ballot_id"]))
        conn.execute("DELETE FROM tamper_backup")
        e = current_election(conn)
        if e:
            log_event(conn, e["id"], "info", f"Restored {len(rows)} tampered ballot(s) from backup (demo reset).")
        return _result("info", "Undo tampering", f"Restored {len(rows)} ballot(s) to their original state.")


# ------------------------------------------------------------------ 2. double voting
def double_vote(target_idx=0):
    with db.session() as conn:
        e = current_election(conn)
        if not e:
            return _result("info", "Double vote", "No poll yet.")
        if e["mode"] == "basic":
            row = conn.execute("SELECT voter_code FROM ballots WHERE election_id=? AND voter_code!='(none)' "
                               "ORDER BY RANDOM() LIMIT 1", (e["id"],)).fetchone()
            code = row["voter_code"] if row else None
        else:
            row = conn.execute("SELECT code FROM codes WHERE election_id=? AND used=1 ORDER BY RANDOM() LIMIT 1",
                               (e["id"],)).fetchone()
            code = row["code"] if row else None
    if not code:
        return _result("info", "Double vote", "Cast at least one vote first.")
    body = {"election_id": e["id"], "code": code, **_fresh_ballot(e, target_idx)}
    res = voting.submit_ballot(body, source="attacker")
    if res["ok"]:
        return _result("succeeded", "Double voting",
                       f"Code {code} was used to vote a second time and the system accepted it.")
    return _result("blocked", "Double voting", f"Code {code} tried to vote again. {res['message']}")


# ------------------------------------------------------------------ 3. replay
def replay():
    with db.session() as conn:
        e = current_election(conn)
        if not e:
            return _result("info", "Replay", "No poll yet.")
        t = conn.execute("SELECT * FROM traffic WHERE election_id=? AND source IN ('voter','simulated') "
                         "ORDER BY id DESC LIMIT 1", (e["id"],)).fetchone()
    if not t:
        return _result("info", "Replay", "No captured vote yet. Cast a vote first.")
    body = json.loads(t["body"])
    res = voting.submit_ballot(body, source="attacker")
    if res["ok"]:
        return _result("succeeded", "Replay attack",
                       "The attacker re-sent a ballot captured from the network, and it was counted again.")
    return _result("blocked", "Replay attack",
                   f"The attacker re-sent a ballot captured from the network. {res['message']}")


# ------------------------------------------------------------------ 4. ballot stuffing
def stuff(count=20, target_idx=0):
    with db.session() as conn:
        e = current_election(conn)
    if not e:
        return _result("info", "Ballot stuffing", "No poll yet.")
    ok = 0
    for _ in range(count):
        fake = "".join(secrets.choice(voting.CODE_ALPHABET) for _ in range(6))
        body = {"election_id": e["id"], "code": f"{fake[:3]}-{fake[3:]}", **_fresh_ballot(e, target_idx)}
        if voting.submit_ballot(body, source="attacker")["ok"]:
            ok += 1
    target = options_of(e)[target_idx]
    if ok:
        return _result("succeeded", "Ballot stuffing",
                       f"{ok} fake ballots for {target} with made-up codes were accepted and counted.")
    return _result("blocked", "Ballot stuffing",
                   f"All {count} fake ballots for {target} were rejected: their codes were never issued.")


# ------------------------------------------------------------------ 5. malicious ballot (limitation)
def malicious(target_idx=0, value=100):
    with db.session() as conn:
        e = current_election(conn)
    if not e or e["mode"] != "protected":
        return _result("info", "Malicious ballot",
                       "Run this against the protected poll. (In the basic poll an attacker can do far worse.)")
    code = voting.register_code(e["id"], source="attacker")
    if not code:
        return _result("info", "Malicious ballot", "The poll is closed.")
    body = {"election_id": e["id"], "code": code, **_fresh_ballot(e, target_idx, value)}
    res = voting.submit_ballot(body, source="attacker")
    target = options_of(e)[target_idx]
    if res["ok"]:
        with db.session() as conn:
            log_event(conn, e["id"], "warning",
                      f"LIMITATION: a registered voter encrypted the value {value} for {target} instead of 1. "
                      "The server cannot see inside the ciphertext, so it was accepted.")
        return _result("limitation", "Malicious ballot (known limitation)",
                       f"A real, registered voter modified their app to encrypt {value} for {target} instead of 1. "
                       "Because the server cannot read the ciphertext, it accepted the ballot and the tally is now "
                       f"inflated by {value - 1}. Real systems (Helios, ElectionGuard) stop this with "
                       "zero-knowledge proofs that each encrypted value is 0 or 1.")
    return _result("blocked", "Malicious ballot", res["message"])


ATTACKS = {
    "tamper": tamper,
    "tamper_rewrite": tamper_rewrite,
    "undo_tamper": undo_tamper,
    "double_vote": double_vote,
    "replay": replay,
    "stuff": stuff,
    "malicious": malicious,
}
