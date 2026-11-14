# Campus Polls

A small web voting app that runs the same poll in two ways, one with no protection and one that uses cryptography, so you can attack both and compare.

We built it for CMPS 380 (Cybersecurity Fundamentals, Qatar University, Fall 2026), group G03. Our topic was cryptographic algorithms. It is a classroom demo of homomorphic encryption, not a real election system, and it has nothing to do with the university's own systems.

## What it does

| | Basic mode | Protected mode |
|---|---|---|
| Over the network | the choice as plain text | Paillier ciphertexts, made in the voter's browser |
| In the database | the vote, with the voting code next to it | ciphertexts only (the ballot row has no code) |
| Counting | read every ballot | multiply the ciphertexts, then decrypt only the totals |
| Voting codes | handed out, never checked | each code works once |
| Tamper evidence | none | SHA-256 hash chain, an Ed25519 signature on every entry, a public bulletin board and receipts |

## Tools

- Python 3 and Flask for the server
- `phe` (python-paillier) for Paillier key generation, adding ciphertexts and decrypting
- `static/paillier.js`, our own BigInt code, for encrypting in the browser
- `cryptography` for Ed25519 (and AES-GCM and RSA in the benchmark)
- `hashlib` for SHA-256
- OpenSSL 3 for making the signing key and checking signatures from outside the app
- SQLite for storage, `qrcode` for the join code, matplotlib for the benchmark charts
- Render or ngrok for hosting

## Running it locally

You need Python 3.10 or newer.

```bash
cd campus-polls
python3 -m venv .venv
source .venv/bin/activate          # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

If you want to make the signing key yourself with OpenSSL, do this first. If you skip it, the app makes a key in the same format.

```bash
mkdir -p keys
openssl genpkey -algorithm ed25519 -out keys/board_signing_key.pem
```

Then start the server:

```bash
python app.py
```

It prints an admin link like `Admin page: /admin?key=Lm30...` and also saves the key in `data/admin_key.txt`. To pick your own key, run `ADMIN_KEY=yourkey python app.py` (in PowerShell: `$env:ADMIN_KEY="yourkey"; python app.py`).

| Page | Address | For |
|---|---|---|
| Vote | `http://localhost:5050/` | voters |
| Control room | `http://localhost:5050/admin?key=<admin key>` | whoever runs the poll |
| Bulletin board | `/board` | anyone |
| Check my vote | `/verify` | voters with a receipt |
| How it works | `/learn` | Paillier with small numbers, step by step |

Phones on the same Wi-Fi can use `http://<laptop-ip>:5050`. Campus Wi-Fi often blocks that, so hosting (below) is easier.

## Running a poll

1. In the control room pick a poll (food or football) and a mode, then press Open poll. Protected mode makes a new 2048-bit Paillier key pair, which takes a moment.
2. Voters scan the QR code, get a one-time code and pick an option. In protected mode the phone encrypts one value per option (a 1 for the choice, 0 for the rest) before anything is sent.
3. "Add simulated voters" adds fake voters. Each one encrypts on its own, the way a phone does.
4. "Close voting & count" ends the poll. In protected mode the server multiplies the ciphertexts for each option and decrypts only the totals. The result is marked certified only if the bulletin board passes its integrity check.

After voting, a voter can open "What did my phone actually send?" to see the exact request. In protected mode they also get a receipt to paste into `/verify`.

## Attack console

Choose which option the attacker wants to help, then press Run attack. It works best to run each attack in a basic poll first and then in a protected one.

| Attack | Basic mode | Protected mode | What stops it |
|---|---|---|---|
| Insider reads the database | sees every vote and code | sees only ciphertexts | encryption in the browser |
| Eavesdropper on the network | reads the choice | reads only ciphertexts | encryption before sending |
| Insider edits a ballot | works, nobody notices | detected: the entry shows ALTERED and the result is not certified | hash chain |
| Edit and rewrite the chain | not applicable | detected: signatures fail and receipts stop matching | Ed25519 signatures |
| Double voting | works | blocked | one-time codes |
| Replay of a captured ballot | works | blocked | the code is already used |
| Ballot stuffing (20 made-up codes) | works | blocked | only issued codes are accepted |
| Malicious ballot (encrypts 100) | not applicable | works | nothing, see Limitations |

"Undo tampering" puts the original ballots back so the demo can carry on. The security log lists every blocked attempt.

## Doing the attacks by hand

The `attacker/` folder does the same attacks the way a real attacker would, without the control-room buttons. Run them from the project folder while the app is running locally (the insider scripts open `data/campus_polls.db` directly, like someone with access to the server).

| Command | Attack |
|---|---|
| `python attacker/read_db.py` | insider reads every ballot in the database |
| `python attacker/change_vote.py Ronaldo` | insider changes a ballot so it counts for Ronaldo |
| `python attacker/rewrite_chain.py` | insider recomputes the hash chain to hide the change |
| `python attacker/stuff_ballots.py http://localhost:5050 20 Messi` | 20 votes with made-up codes |
| `attacker/console_snippets.js` | replay a captured vote 50 times, and the malicious ballot (paste into the browser console) |

After `change_vote.py` or `rewrite_chain.py` in a protected poll, press "Undo tampering" in the control room before casting more votes.

## Checking a signature with OpenSSL

While a protected poll has ballots:

```bash
python tools/export_entry.py http://localhost:5050 2
openssl pkeyutl -verify -pubin -inkey export/board_public.pem -rawin \
    -in export/entry_2.hash.bin -sigfile export/entry_2.sig.bin
```

You should see `Signature Verified Successfully`. Change one byte of `entry_2.hash.bin` and the same command prints `Signature Verification Failure`. This needs OpenSSL 3 (on macOS, `brew install openssl`).

## Hosting

On Render (free plan): push this folder to a GitHub repo, choose New, then Blueprint, and pick the repo. Render reads `render.yaml`. Set `ADMIN_KEY` to something secret. Free services go to sleep when nobody visits, so open the site a few minutes before you need it. Data is wiped whenever the service restarts.

With ngrok: run `python app.py`, then in a second terminal run

```bash
ngrok http 5050
```

If you open the admin page through the ngrok address, the QR code uses that address too.

If the network fails, "Add simulated voters" still works, and so does this from another machine:

```bash
python tools/simulate_voters.py https://<your-address> 20
```

## Benchmarks

```bash
python tools/benchmark.py
```

This writes charts and `results.md` into `bench_output/`:

1. Paillier key generation, encryption, addition and decryption at 1024, 2048 and 3072 bits
2. How tally time grows with the number of voters
3. Paillier against AES-256-GCM and RSA-2048-OAEP for one vote (speed, ciphertext size, whether the ciphertexts can be added)
4. How the time to factor n grows with its size (Pollard's rho)

## Files

```
app.py                 Flask routes (pages and API)
voting.py              elections, ballot handling, bulletin board, tally
attacks.py             the attack buttons
crypto_core.py         Paillier helpers, hash chain, Ed25519 signing
db.py                  SQLite schema
polls.py               poll questions and options
static/paillier.js     Paillier encryption in the browser
static/vote.js         voter page
static/admin.js        control room
static/learn.js        the small-numbers walkthrough
templates/             HTML pages
tools/benchmark.py     timing tests and charts
tools/export_entry.py  export one board entry for the OpenSSL check
tools/simulate_voters.py  fake voters over HTTP
attacker/              the attacks done by hand (scripts and browser-console snippets)
requirements.txt, Procfile, render.yaml   deployment
```

## Limitations

- Malicious ballots. The server can't tell whether a ciphertext holds 0 or 1, so a registered voter who encrypts 100 gets 100 votes. Systems like Helios and ElectionGuard attach a zero-knowledge proof to each ballot to prevent this. We didn't build that.
- One key holder. The Paillier private key (p and q) is saved in the `elections` table next to the ballots, and the signing key is on the same server. Whoever controls the server could decrypt single ballots or re-sign a rewritten board. Real systems split the key between several trustees.
- Voter identity. Codes go to any device. The code lives in the browser, so clearing site data, or calling `/api/register` again, gives a fresh code and a second vote. A real system would tie one credential to one registered voter, for example a student ID.
- The request log. The `traffic` table keeps raw request bodies for the network-capture panel, so in that table a code sits next to its ciphertexts.
- Trusting the page. The voter has to trust that the JavaScript the server sends really encrypts their choice. Real systems let voters audit the voting client ("cast or audit").
- Quantum computers. Paillier relies on factoring being hard, like RSA, so Shor's algorithm would break it. Ballots published today could be decrypted later. Lattice-based schemes (BFV, CKKS) are the usual alternative.
- Not covered: coercion, vote buying, and denial of service. There is no rate limiting.
