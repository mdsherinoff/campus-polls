# Campus Polls: user manual

> **University coursework.** This project was built as part of the group project for **CMPS 380 Cybersecurity
> Fundamentals** at **Qatar University** (Fall 2026), by **Group G03**, on the topic *Cryptographic Algorithms*.
> It is an educational demonstration of homomorphic encryption for e-voting. It is not an official Qatar University
> system and is not intended for real elections.

Campus Polls is a web voting system that runs the same poll in two modes so the difference can be seen live:

| | Basic mode | Protected mode |
|---|---|---|
| What travels over the network | The choice in plain text | Paillier ciphertexts made **in the voter's browser** |
| What the server stores | Who (voting code) voted for what | Ciphertexts only; codes are not linked to ballots |
| How votes are counted | Read every ballot | Multiply ciphertexts (adds the hidden votes), decrypt **only the totals** |
| Voting codes | Issued but never checked | One code = one vote |
| Tamper evidence | None | SHA-256 hash chain + Ed25519 server signature on every entry, public bulletin board, voter receipts |

## 1. Technologies

| Tool | Used for |
|---|---|
| Python 3 + Flask | Web server and API |
| `phe` (python-paillier) | Paillier key generation, homomorphic addition, decryption |
| JavaScript BigInt (`static/paillier.js`, our own code) | Paillier encryption on the voter's phone |
| `cryptography` | Ed25519 signatures, AES-GCM/RSA for benchmarks |
| `hashlib` (SHA-256) | Bulletin-board hash chain and receipts |
| OpenSSL 3 | Creating the signing key and independently verifying signatures |
| SQLite | Storage |
| `qrcode` | QR code for joining the poll |
| matplotlib | Benchmark charts |
| Browser DevTools / Wireshark | Showing what an eavesdropper sees |
| Render (free) or ngrok | Hosting for the live class demo |

## 2. Setting up and running locally

Requires Python 3.10+ (macOS, Linux or Windows).

```bash
cd campus-polls
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Optional, create the bulletin-board signing key with OpenSSL (otherwise the app creates one in the same format):

```bash
mkdir -p keys
openssl genpkey -algorithm ed25519 -out keys/board_signing_key.pem
```

Start the server:

```bash
python app.py
```

The terminal prints the admin link, e.g. `Admin page: /admin?key=Lm30...`. The key is also saved in `data/admin_key.txt`. You can choose your own with `ADMIN_KEY=yourkey python app.py`.

| Page | Address | Who uses it |
|---|---|---|
| Vote | `http://localhost:5050/` | Voters (phones) |
| Election control room | `http://localhost:5050/admin?key=<admin key>` | Presenter, on the projector |
| Bulletin board | `/board` | Anyone |
| Check my vote | `/verify` | Voters with a receipt |
| How it works | `/learn` | Presenter: step-by-step Paillier with small numbers |

Phones on the same Wi-Fi can open `http://<laptop-ip>:5050`. University Wi-Fi often blocks this, so use hosting (section 6).

## 3. Running a poll (control room)

1. Choose the **Poll** (food or football) and the **Mode** (Basic or Protected), then press **Open new poll**. Protected mode generates a fresh 2048-bit Paillier key pair.
2. Voters scan the QR code, press **Get my voting code**, choose and press **Cast my vote**. In protected mode the phone encrypts one value per option (1 for the choice, 0 for the others) before sending.
3. **Add simulated voters** adds extra voters (each one encrypts on its own side, like a phone).
4. **Close voting & count** ends the poll. In protected mode the server multiplies all ciphertexts and decrypts only the totals. The result is certified only if the bulletin board passes its integrity check.

After voting, a voter can expand **What did my phone actually send?** to see the exact request, and in protected mode use their **receipt** on `/verify`.

## 4. Attack console

Pick which option the attacker wants to help, then run an attack. Run each one in Basic mode first, then in Protected mode.

| Attack | Basic mode | Protected mode | Defence |
|---|---|---|---|
| Insider reads the database | Sees every vote and voting code | Sees only ciphertext | Paillier encryption in the browser |
| Eavesdropper on the network | Reads the choice | Reads only ciphertext | Encryption before sending |
| Insider tampering | Succeeds, undetected | **Detected**: entry shows ALTERED, result not certified | SHA-256 hash chain |
| Tamper & rewrite chain | (not applicable) | **Detected**: signatures fail, voters' receipts no longer match | Ed25519 signatures + receipts |
| Double voting | Succeeds | **Blocked** | One-time codes |
| Replay of a captured ballot | Succeeds | **Blocked** | Code already used |
| Ballot stuffing (20 fake codes) | Succeeds | **Blocked** | Only issued codes accepted |
| Malicious ballot (encrypts 100) | (not applicable) | **Succeeds: known limitation** | Real systems add zero-knowledge proofs |

**Undo tampering (reset demo)** restores tampered ballots so the demo can continue. The **Security log** shows every blocked attempt.

## 5. Verifying a signature with OpenSSL

While a protected poll has ballots:

```bash
python tools/export_entry.py http://localhost:5050 2
openssl pkeyutl -verify -pubin -inkey export/board_public.pem -rawin \
    -in export/entry_2.hash.bin -sigfile export/entry_2.sig.bin
```

Expected output: `Signature Verified Successfully`. Change one byte of `entry_2.hash.bin` and the same command prints `Signature Verification Failure`.

(Requires OpenSSL 3. On macOS: `brew install openssl`.)

## 6. Hosting for the live demo

**Option A: Render (free).** Push the `campus-polls` folder to a GitHub repository, then in Render choose *New > Blueprint* and pick the repository (it reads `render.yaml`). Set `ADMIN_KEY` to a secret value. Free services sleep when idle, so open the site about 10 minutes before presenting. Data is reset whenever the service restarts, which is fine for a demo.

**Option B: a laptop + ngrok.** Run `python app.py` on the laptop, then in another terminal:

```bash
ngrok http 5050
```

The QR code on the control room automatically uses the public ngrok address once you open the admin page through it.

**Backup if the network fails:** use **Add simulated voters**, or from another computer:

```bash
python tools/simulate_voters.py https://<your-address> 20
```

## 7. Benchmarks

```bash
python tools/benchmark.py
```

Writes charts and `results.md` to `bench_output/`:
1. Paillier key generation / encryption / addition / decryption at 1024, 2048 and 3072 bits
2. Tally time as the number of voters grows
3. Paillier vs AES-256-GCM vs RSA-2048-OAEP for one vote (speed, ciphertext size, homomorphic or not)
4. How factoring time grows with the size of n (Pollard's rho)

## 8. Project structure

```
campus-polls/
  app.py               Flask routes (pages + API)
  voting.py            Elections, ballot handling, bulletin board, tally
  attacks.py           Attack simulations for the demo
  crypto_core.py       Paillier helpers, SHA-256 hash chain, Ed25519 signing
  db.py                SQLite schema
  polls.py             Poll questions and options
  static/paillier.js   Paillier encryption in the browser
  static/vote.js       Voter page
  static/admin.js      Control room
  static/learn.js      Step-by-step Paillier with small numbers
  templates/           HTML pages
  tools/benchmark.py   Performance measurements and charts
  tools/export_entry.py      Export a board entry for OpenSSL verification
  tools/simulate_voters.py   Simulated voters over HTTP
  requirements.txt, Procfile, render.yaml   Deployment
```

## 9. Known limitations (discuss in the report)

* **Malicious ballots:** the server cannot check that each ciphertext encrypts 0 or 1. Real systems (Helios, ElectionGuard) attach zero-knowledge proofs.
* **Single key holder:** whoever holds the Paillier private key could decrypt an individual ballot. Real systems split the key among several trustees (threshold decryption).
* **Voter identity:** voting codes are handed out to any device; clearing the browser gives a new code. Real systems tie credentials to a registered voter (e.g. student ID).
* **Trust in the web page:** voters must trust that the JavaScript served to them really encrypts their choice. Real systems allow independent audit of the voting client ("cast-or-audit").
* **Quantum computers:** Paillier, like RSA, relies on factoring being hard. Shor's algorithm on a large quantum computer would break it, and ballots published today could be decrypted in the future ("harvest now, decrypt later"). Lattice-based homomorphic schemes (BFV/CKKS, based on Learning With Errors) are the post-quantum alternative.
* Coercion and vote buying are not addressed.
