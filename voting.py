"""Election logic for Campus Polls.

Two modes run the same poll so the class can compare them:

* basic     -- a naive online poll: votes travel and are stored as plain text,
               voting codes are never checked, nothing protects the stored data.
* protected -- votes are Paillier-encrypted in the browser, only the final
               total is decrypted, each code works once, and every accepted
               ballot is placed on a signed SHA-256 hash chain (bulletin board).
"""
import json
import os
import random
import secrets
import threading
import time
from collections import Counter

import crypto_core as cc
import db
from polls import POLLS

KEY_BITS = int(os.environ.get("PAILLIER_BITS", "2048"))
LOCK = threading.RLock()
SIGNING_KEY = None
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def init():
    global SIGNING_KEY
    db.init()
    SIGNING_KEY = cc.load_signing_key()


def now():
    return round(time.time(), 3)


def log_event(conn, election_id, kind, message):
    conn.execute(
        "INSERT INTO events (election_id, created_at, kind, message) VALUES (?,?,?,?)",
        (election_id, now(), kind, message),
    )


def new_code():
    s = "".join(secrets.choice(CODE_ALPHABET) for _ in range(6))
    return f"{s[:3]}-{s[3:]}"


def current_election(conn):
    return conn.execute("SELECT * FROM elections ORDER BY id DESC LIMIT 1").fetchone()


def options_of(e):
    return POLLS[e["poll_key"]]["options"]


# ------------------------------------------------------------------ elections
def create_election(poll_key, mode):
    if poll_key not in POLLS:
        raise ValueError("Unknown poll")
    if mode not in ("basic", "protected"):
        raise ValueError("Unknown mode")
    n = p = q = None
    bits = None
    if mode == "protected":
        pub, priv = cc.new_paillier_keypair(KEY_BITS)
        n, p, q, bits = str(pub.n), str(priv.p), str(priv.q), KEY_BITS
    with LOCK, db.session() as conn:
        conn.execute("UPDATE elections SET status='closed', closed_at=? WHERE status='open'", (now(),))
        conn.execute("DELETE FROM tamper_backup")
        cur = conn.execute(
            "INSERT INTO elections (poll_key, mode, status, created_at, paillier_n, paillier_p, "
            "paillier_q, key_bits) VALUES (?,?,?,?,?,?,?,?)",
            (poll_key, mode, "open", now(), n, p, q, bits),
        )
        eid = cur.lastrowid
        label = "PROTECTED (Paillier + signed hash chain)" if mode == "protected" else "BASIC (no protection)"
        log_event(conn, eid, "info", f"Poll #{eid} opened in {label} mode: {POLLS[poll_key]['question']}")
        if mode == "protected":
            log_event(conn, eid, "info", f"Generated a {bits}-bit Paillier key pair. Public key n has {len(n)} digits.")
        return eid


def public_state():
    with db.session() as conn:
        e = current_election(conn)
        if not e:
            return {"election": None}
        count = conn.execute("SELECT COUNT(*) FROM ballots WHERE election_id=?", (e["id"],)).fetchone()[0]
        poll = POLLS[e["poll_key"]]
        return {
            "election": {
                "id": e["id"],
                "question": poll["question"],
                "options": poll["options"],
                "mode": e["mode"],
                "status": e["status"],
                "ballots": count,
                "paillier_n": e["paillier_n"],
                "key_bits": e["key_bits"],
                "result": json.loads(e["result_json"]) if e["result_json"] else None,
            }
        }


# ------------------------------------------------------------------ voting
def register_code(election_id, source="voter"):
    with LOCK, db.session() as conn:
        e = current_election(conn)
        if not e or e["id"] != election_id or e["status"] != "open":
            return None
        code = new_code()
        conn.execute(
            "INSERT INTO codes (code, election_id, used, created_at, source) VALUES (?,?,0,?,?)",
            (code, e["id"], now(), source),
        )
        return code


def _reject(conn, e, message, kind="blocked"):
    log_event(conn, e["id"] if e else None, kind, message)
    return {"ok": False, "message": message}


def submit_ballot(body, source="voter"):
    """Handle one incoming vote request (from a phone, the simulator or an attacker)."""
    if not isinstance(body, dict):
        body = {}
    with LOCK, db.session() as conn:
        e = current_election(conn)
        conn.execute(
            "INSERT INTO traffic (election_id, created_at, source, body) VALUES (?,?,?,?)",
            (e["id"] if e else None, now(), source, json.dumps(body)),
        )
        if not e or body.get("election_id") != e["id"]:
            return _reject(conn, e, "Rejected: this ballot is for a poll that is not running.", "warning")
        if e["status"] != "open":
            return _reject(conn, e, "Rejected: voting for this poll is closed.", "warning")
        options = options_of(e)
        code = str(body.get("code") or "").strip().upper()

        # ---------------- BASIC: trusts whatever arrives, stores it in plain text
        if e["mode"] == "basic":
            choice = body.get("choice")
            if choice not in options:
                return _reject(conn, e, "Rejected: unknown choice.", "warning")
            last = conn.execute(
                "SELECT MAX(seq) FROM ballots WHERE election_id=?", (e["id"],)
            ).fetchone()[0] or 0
            conn.execute(
                "INSERT INTO ballots (election_id, seq, created_at, voter_code, payload, source) "
                "VALUES (?,?,?,?,?,?)",
                (e["id"], last + 1, now(), code or "(none)", json.dumps({"choice": choice}), source),
            )
            return {"ok": True, "message": "Vote recorded.", "receipt": None}

        # ---------------- PROTECTED
        row = conn.execute(
            "SELECT * FROM codes WHERE code=? AND election_id=?", (code, e["id"])
        ).fetchone()
        if not row:
            return _reject(conn, e, f"Blocked: voting code '{code or '(none)'}' was never issued for this poll.")
        if row["used"]:
            return _reject(conn, e, f"Blocked: voting code {code} has already been used. One code = one vote.")
        cts = body.get("ciphertexts")
        if not isinstance(cts, list) or len(cts) != len(options):
            return _reject(conn, e, "Blocked: ballot is malformed (wrong number of encrypted values).")
        n = int(e["paillier_n"])
        clean = []
        for c in cts:
            try:
                ci = int(str(c))
            except ValueError:
                return _reject(conn, e, "Blocked: ballot contains something that is not a ciphertext.")
            if not cc.is_valid_ciphertext(n, ci):
                return _reject(conn, e, "Blocked: ballot contains an invalid ciphertext.")
            clean.append(str(ci))
        conn.execute("UPDATE codes SET used=1 WHERE code=?", (code,))
        receipt = _append_to_board(conn, e, {"ciphertexts": clean}, source)
        log_event(conn, e["id"], "info", f"Encrypted ballot accepted and added to the bulletin board (receipt {receipt[:12]}…).")
        return {"ok": True, "message": "Encrypted vote recorded.", "receipt": receipt}


def _append_to_board(conn, e, payload, source):
    last = conn.execute(
        "SELECT seq, entry_hash FROM ballots WHERE election_id=? ORDER BY seq DESC LIMIT 1", (e["id"],)
    ).fetchone()
    seq = last["seq"] + 1 if last else 1
    prev = last["entry_hash"] if last else cc.GENESIS_HASH
    ts = now()
    h = cc.entry_hash(prev, e["id"], seq, ts, cc.canonical(payload))
    sig = cc.sign(SIGNING_KEY, h)
    conn.execute(
        "INSERT INTO ballots (election_id, seq, created_at, voter_code, payload, prev_hash, entry_hash, "
        "signature, source) VALUES (?,?,?,?,?,?,?,?,?)",
        (e["id"], seq, ts, None, cc.canonical(payload), prev, h, sig, source),
    )
    return h


# ------------------------------------------------------------------ bulletin board
def verify_board(conn, e):
    """Re-check every entry: content hash, link to previous entry, server signature."""
    rows = conn.execute("SELECT * FROM ballots WHERE election_id=? ORDER BY seq", (e["id"],)).fetchall()
    if e["mode"] != "protected":
        return rows, {r["id"]: "unprotected" for r in rows}, None
    pub = SIGNING_KEY.public_key()
    statuses = {}
    expected_prev = cc.GENESIS_HASH
    for r in rows:
        recomputed = cc.entry_hash(r["prev_hash"], e["id"], r["seq"], r["created_at"], r["payload"])
        if r["prev_hash"] != expected_prev:
            statuses[r["id"]] = "broken link"
        elif recomputed != r["entry_hash"]:
            statuses[r["id"]] = "altered"
        elif not cc.verify_signature(pub, r["entry_hash"], r["signature"]):
            statuses[r["id"]] = "bad signature"
        else:
            statuses[r["id"]] = "ok"
        expected_prev = r["entry_hash"]
    intact = all(s == "ok" for s in statuses.values())
    return rows, statuses, intact


def _payload_preview(e, payload_json):
    p = json.loads(payload_json)
    if e["mode"] == "basic":
        return {"plain": p.get("choice")}
    return {"ciphertexts": [cc.short(c, 14, 6) for c in p.get("ciphertexts", [])],
            "digits": len(p["ciphertexts"][0]) if p.get("ciphertexts") else 0}


def board(election_id=None):
    with db.session() as conn:
        e = current_election(conn) if election_id is None else conn.execute(
            "SELECT * FROM elections WHERE id=?", (election_id,)).fetchone()
        if not e:
            return {"election": None, "entries": []}
        rows, statuses, intact = verify_board(conn, e)
        poll = POLLS[e["poll_key"]]
        return {
            "election": {"id": e["id"], "question": poll["question"], "options": poll["options"],
                         "mode": e["mode"], "status": e["status"]},
            "intact": intact,
            "entries": [
                {"seq": r["seq"], "created_at": r["created_at"], "receipt": r["entry_hash"],
                 "prev": r["prev_hash"], "signature": r["signature"],
                 "status": statuses[r["id"]], **_payload_preview(e, r["payload"])}
                for r in rows
            ],
        }


def verify_receipt(receipt):
    receipt = (receipt or "").strip().lower()
    if len(receipt) < 8:
        return {"found": False, "message": "Please paste your full receipt."}
    with db.session() as conn:
        row = conn.execute("SELECT * FROM ballots WHERE entry_hash=?", (receipt,)).fetchone()
        if not row:
            return {"found": False,
                    "message": "No ballot on the bulletin board matches this receipt. "
                               "Your ballot may have been removed or rewritten. Report this to the election officials."}
        e = conn.execute("SELECT * FROM elections WHERE id=?", (row["election_id"],)).fetchone()
        _, statuses, intact = verify_board(conn, e)
        status = statuses[row["id"]]
        return {"found": True, "seq": row["seq"], "status": status, "board_intact": intact,
                "election_id": e["id"], "question": POLLS[e["poll_key"]]["question"],
                "message": ("Your encrypted ballot is on the bulletin board, unchanged, and signed by the server."
                            if status == "ok" else
                            "Your ballot is on the board but it FAILED the integrity check: "
                            "it has been altered since you cast it.")}


# ------------------------------------------------------------------ tally
def compute_tally(conn, e):
    options = options_of(e)
    rows, statuses, intact = verify_board(conn, e)
    t0 = time.perf_counter()
    if e["mode"] == "basic":
        counts = Counter(json.loads(r["payload"])["choice"] for r in rows)
        totals = [counts.get(o, 0) for o in options]
        return {"options": options, "totals": totals, "ballots": len(rows), "mode": "basic",
                "certified": None, "ms": round((time.perf_counter() - t0) * 1000, 1)}
    pub = cc.public_key_from_n(e["paillier_n"])
    priv = cc.private_key_from(pub, e["paillier_p"], e["paillier_q"])
    payloads = [json.loads(r["payload"])["ciphertexts"] for r in rows]
    enc_totals, totals = [], []
    t_add = time.perf_counter()
    sums = [cc.homomorphic_sum(pub, [p[i] for p in payloads]) if payloads else None
            for i in range(len(options))]
    add_ms = (time.perf_counter() - t_add) * 1000
    t_dec = time.perf_counter()
    bad_options = []
    for i, s in enumerate(sums):
        if s is None:
            enc_totals.append(None)
            totals.append(0)
            continue
        enc_totals.append(cc.short(s.ciphertext(be_secure=False), 18, 8))
        try:
            totals.append(priv.decrypt(s))
        except (OverflowError, ValueError):
            # A structurally valid but meaningless ciphertext (not an encryption of a small
            # number) was submitted. The sum decrypts to garbage, so report it instead of crashing.
            totals.append(0)
            bad_options.append(options[i])
    dec_ms = (time.perf_counter() - t_dec) * 1000
    certified = (bool(intact) if rows else True) and not bad_options
    result = {"options": options, "totals": totals, "ballots": len(rows), "mode": "protected",
              "encrypted_totals": enc_totals, "certified": certified,
              "add_ms": round(add_ms, 1), "decrypt_ms": round(dec_ms, 1),
              "ms": round((time.perf_counter() - t0) * 1000, 1)}
    if bad_options:
        result["error"] = ("The total for " + ", ".join(bad_options) + " could not be decrypted: at least one "
                           "ballot did not hold a valid vote value. Those totals are shown as 0 and the "
                           "result is not certified.")
    return result


def close_and_tally():
    with LOCK, db.session() as conn:
        e = current_election(conn)
        if not e:
            return None
        if e["status"] == "open":
            conn.execute("UPDATE elections SET status='closed', closed_at=? WHERE id=?", (now(), e["id"]))
        e = conn.execute("SELECT * FROM elections WHERE id=?", (e["id"],)).fetchone()
        result = compute_tally(conn, e)
        conn.execute("UPDATE elections SET result_json=? WHERE id=?", (json.dumps(result), e["id"]))
        if e["mode"] == "protected":
            msg = (f"Voting closed. {result['ballots']} encrypted ballots were combined homomorphically "
                   f"({result['add_ms']} ms) and only the totals were decrypted ({result['decrypt_ms']} ms).")
            log_event(conn, e["id"], "info", msg)
            if result.get("error"):
                log_event(conn, e["id"], "warning", "Result NOT certified: " + result["error"])
            elif not result["certified"]:
                log_event(conn, e["id"], "warning",
                          "Result NOT certified: the bulletin board failed its integrity check.")
        else:
            log_event(conn, e["id"], "info", f"Voting closed. {result['ballots']} plain-text ballots counted.")
        return result


# ------------------------------------------------------------------ admin view
def admin_state():
    with db.session() as conn:
        e = current_election(conn)
        if not e:
            return {"election": None}
        poll = POLLS[e["poll_key"]]
        rows, statuses, intact = verify_board(conn, e)
        codes = conn.execute(
            "SELECT COUNT(*) AS issued, COALESCE(SUM(used),0) AS used FROM codes WHERE election_id=?",
            (e["id"],)).fetchone()
        traffic = conn.execute(
            "SELECT * FROM traffic WHERE election_id=? ORDER BY id DESC LIMIT 6", (e["id"],)).fetchall()
        events = conn.execute(
            "SELECT * FROM events WHERE election_id=? ORDER BY id DESC LIMIT 14", (e["id"],)).fetchall()
        live = None
        if e["mode"] == "basic":
            c = Counter(json.loads(r["payload"])["choice"] for r in rows)
            live = [c.get(o, 0) for o in poll["options"]]
        return {
            "election": {"id": e["id"], "question": poll["question"], "options": poll["options"],
                         "mode": e["mode"], "status": e["status"], "key_bits": e["key_bits"],
                         "n_digits": len(e["paillier_n"]) if e["paillier_n"] else None,
                         "n_preview": cc.short(e["paillier_n"], 20, 10) if e["paillier_n"] else None},
            "codes": {"issued": codes["issued"], "used": codes["used"]},
            "intact": intact,
            "live_totals": live,
            "result": json.loads(e["result_json"]) if e["result_json"] else None,
            "ballots": [
                {"seq": r["seq"], "voter_code": r["voter_code"], "source": r["source"],
                 "receipt": cc.short(r["entry_hash"], 10, 4) if r["entry_hash"] else None,
                 "status": statuses[r["id"]], **_payload_preview(e, r["payload"])}
                for r in rows
            ],
            "traffic": [
                {"source": t["source"], "created_at": t["created_at"], "body": _short_body(t["body"])}
                for t in traffic
            ],
            "events": [{"kind": ev["kind"], "message": ev["message"], "created_at": ev["created_at"]}
                       for ev in events],
            "tampered": conn.execute("SELECT COUNT(*) FROM tamper_backup").fetchone()[0] > 0,
        }


def _short_body(body_json):
    b = json.loads(body_json)
    if isinstance(b.get("ciphertexts"), list):
        b["ciphertexts"] = [cc.short(c, 12, 6) for c in b["ciphertexts"]]
    return json.dumps(b, ensure_ascii=False)


# ------------------------------------------------------------------ simulated voters
def simulate_voters(count):
    """Simulated phones: each gets a code, picks an option, encrypts on its own side, submits."""
    state = public_state()["election"]
    if not state or state["status"] != "open":
        return {"ok": False, "message": "No open poll."}
    options = state["options"]
    weights = [random.randint(1, 6) for _ in options]
    pub = cc.public_key_from_n(state["paillier_n"]) if state["mode"] == "protected" else None
    accepted = 0
    for _ in range(max(1, min(int(count), 200))):
        code = register_code(state["id"], source="simulated")
        idx = random.choices(range(len(options)), weights=weights)[0]
        body = {"election_id": state["id"], "code": code}
        if pub:
            body["ciphertexts"] = cc.encrypt_vote_vector(pub, idx, len(options))
        else:
            body["choice"] = options[idx]
        if submit_ballot(body, source="simulated")["ok"]:
            accepted += 1
    with db.session() as conn:
        log_event(conn, state["id"], "info", f"{accepted} simulated voters cast their ballots.")
    return {"ok": True, "message": f"{accepted} simulated voters voted."}
