"""Outside attack: stuff the ballot box with votes that use made-up voting codes.

    python attacker/stuff_ballots.py http://localhost:5050 20 Messi
"""
import sys
from _common import BOLD, END, GREEN, RED, encrypt, get, post

url = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5050").rstrip("/")
count = int(sys.argv[2]) if len(sys.argv) > 2 else 20
target = " ".join(sys.argv[3:]) or "Messi"
e = get(f"{url}/api/state")["election"]
if not e or e["status"] != "open":
    raise SystemExit("No open poll.")
accepted = 0
for i in range(1, count + 1):
    body = {"election_id": e["id"], "code": f"FAKE-{i:03d}"}
    if e["mode"] == "protected":
        n = int(e["paillier_n"])  # the public key is public, so anyone can make a valid-looking ballot
        body["ciphertexts"] = [str(encrypt(1 if o == target else 0, n)) for o in e["options"]]
    else:
        body["choice"] = target
    r = post(f"{url}/api/vote", body)
    accepted += bool(r.get("ok"))
    colour = RED if r.get("ok") else GREEN
    print(f"fake ballot {i:>2} (code {body['code']}): {colour}{r.get('message')}{END}")
print(f"\n{BOLD}{accepted} of {count} fake ballots accepted.{END}")
