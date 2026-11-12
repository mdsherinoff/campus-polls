"""Simulate voters over the real network (used in the video if the Wi-Fi is unavailable).

Each simulated phone asks for a voting code, encrypts its vote locally with the
poll's public key (protected mode) and sends it to the server, exactly like the
browser does.

Usage:  python tools/simulate_voters.py <server-url> [count]
"""
import json
import os
import random
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from phe import paillier


def call(url, body=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        return json.load(e)


if len(sys.argv) < 2:
    sys.exit(__doc__)
base = sys.argv[1].rstrip("/")
count = int(sys.argv[2]) if len(sys.argv) > 2 else 10
e = call(f"{base}/api/state")["election"]
if not e or e["status"] != "open":
    sys.exit("No open poll.")
pub = paillier.PaillierPublicKey(int(e["paillier_n"])) if e["mode"] == "protected" else None
for i in range(count):
    code = call(f"{base}/api/register", {"election_id": e["id"]})["code"]
    idx = random.randrange(len(e["options"]))
    body = {"election_id": e["id"], "code": code}
    if pub:
        body["ciphertexts"] = [str(pub.encrypt(1 if j == idx else 0).ciphertext()) for j in range(len(e["options"]))]
    else:
        body["choice"] = e["options"][idx]
    r = call(f"{base}/api/vote", body)
    print(f"voter {i + 1:>3}  code {code}  ->  {'accepted' if r['ok'] else 'rejected: ' + r['message']}")
