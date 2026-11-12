"""Export one bulletin-board entry so its signature can be checked with OpenSSL.

Usage:
    python tools/export_entry.py <server-url> <entry-number>
    e.g. python tools/export_entry.py http://localhost:5050 3

Then verify with OpenSSL 3:
    openssl pkeyutl -verify -pubin -inkey export/board_public.pem -rawin \
        -in export/entry_3.hash.bin -sigfile export/entry_3.sig.bin
"""
import json
import os
import sys
import urllib.request

if len(sys.argv) != 3:
    sys.exit(__doc__)
base, seq = sys.argv[1].rstrip("/"), int(sys.argv[2])
out = os.path.join(os.getcwd(), "export")
os.makedirs(out, exist_ok=True)

board = json.load(urllib.request.urlopen(f"{base}/api/board"))
entry = next((e for e in board["entries"] if e["seq"] == seq), None)
if not entry or not entry.get("signature"):
    sys.exit("Entry not found, or the poll is not a protected poll.")

pem = urllib.request.urlopen(f"{base}/api/board-public-key.pem").read()
with open(os.path.join(out, "board_public.pem"), "wb") as f:
    f.write(pem)
with open(os.path.join(out, f"entry_{seq}.hash.bin"), "wb") as f:
    f.write(bytes.fromhex(entry["receipt"]))
with open(os.path.join(out, f"entry_{seq}.sig.bin"), "wb") as f:
    f.write(bytes.fromhex(entry["signature"]))

print(f"Entry #{seq} receipt (SHA-256): {entry['receipt']}")
print(f"Board status: {entry['status']}")
print("Files written to ./export. Verify with:")
print(f"  openssl pkeyutl -verify -pubin -inkey export/board_public.pem -rawin "
      f"-in export/entry_{seq}.hash.bin -sigfile export/entry_{seq}.sig.bin")
