"""Benchmarks for the report (CMPS 380, Group G03).

Measures:
  1. Paillier key generation / encryption / homomorphic addition / decryption at 1024, 2048, 3072 bits
  2. Tally time as the number of voters grows (2048-bit)
  3. Size and speed of Paillier vs AES-256-GCM and RSA-2048-OAEP for one vote
  4. How fast factoring gets harder as n grows (Pollard's rho on small semiprimes)

Usage:  python tools/benchmark.py        (writes charts + results.md into bench_output/)
"""
import math
import os
import random
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from phe import paillier

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bench_output")
os.makedirs(OUT, exist_ok=True)
MAROON = "#8A1538"
GREY = "#505A5F"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "axes.spines.top": False,
                     "axes.spines.right": False})


def timeit(fn, repeat=5):
    xs = []
    for _ in range(repeat):
        t = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t) * 1000)
    return statistics.median(xs)


lines = ["# Campus Polls benchmark results", "",
         f"Machine: {os.uname().machine}, Python {sys.version.split()[0]}", ""]

# ------------------------------------------------------------- 1. key sizes
print("1) Paillier operations by key size")
sizes = [1024, 2048, 3072]
ops = {"Key generation": [], "Encrypt one value": [], "Add two ciphertexts": [], "Decrypt": []}
for bits in sizes:
    kg = timeit(lambda: paillier.generate_paillier_keypair(n_length=bits), repeat=3)
    pub, priv = paillier.generate_paillier_keypair(n_length=bits)
    enc = timeit(lambda: pub.encrypt(1), repeat=20)
    a, b = pub.encrypt(1), pub.encrypt(0)
    add = timeit(lambda: a + b, repeat=200)
    dec = timeit(lambda: priv.decrypt(a), repeat=20)
    for k, v in zip(ops, [kg, enc, add, dec]):
        ops[k].append(v)
    print(f"   {bits}: keygen {kg:.1f} ms, enc {enc:.2f} ms, add {add:.4f} ms, dec {dec:.2f} ms")

lines += ["## 1. Paillier operations (median ms)", "",
          "| Operation | " + " | ".join(f"{s}-bit" for s in sizes) + " |",
          "|---|" + "---|" * len(sizes)]
for k, v in ops.items():
    lines.append(f"| {k} | " + " | ".join(f"{x:.3f}" for x in v) + " |")
lines.append("")

fig, ax = plt.subplots(figsize=(7, 4))
x = range(len(sizes))
w = 0.2
for i, (k, v) in enumerate(ops.items()):
    ax.bar([xi + (i - 1.5) * w for xi in x], v, w, label=k,
           color=[MAROON, "#B5546F", GREY, "#9AA3A8"][i])
ax.set_yscale("log")
ax.set_xticks(list(x), [f"{s}-bit" for s in sizes])
ax.set_ylabel("Time (ms, log scale)")
ax.set_title("Paillier operation cost by key size")
ax.legend(frameon=False, fontsize=9)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "1_paillier_key_sizes.png"), dpi=160)

# ------------------------------------------------------------- 2. tally scaling
print("2) Tally time vs voters (2048-bit, one option)")
pub, priv = paillier.generate_paillier_keypair(n_length=2048)
pool = [pub.encrypt(random.randint(0, 1)) for _ in range(50)]
voters = [10, 100, 500, 1000, 5000, 10000]
tally_ms, enc_ms_est = [], []
enc_one = timeit(lambda: pub.encrypt(1), repeat=10)
for v in voters:
    cts = [pool[i % len(pool)] for i in range(v)]

    def tally():
        total = cts[0]
        for c in cts[1:]:
            total = total + c
        priv.decrypt(total)
    tally_ms.append(timeit(tally, repeat=3))
    enc_ms_est.append(enc_one * v)
    print(f"   {v} voters: tally {tally_ms[-1]:.1f} ms")
lines += ["## 2. Tally time (2048-bit key, one option)", "",
          "| Voters | Homomorphic tally + 1 decryption (ms) | Total encryption work spread over voters' phones (ms) |",
          "|---|---|---|"]
for v, t, e in zip(voters, tally_ms, enc_ms_est):
    lines.append(f"| {v} | {t:.1f} | {e:.0f} |")
lines.append("")
fig, ax = plt.subplots(figsize=(7, 4))
ax.plot(voters, tally_ms, marker="o", color=MAROON, label="Server: add all ballots + decrypt total")
ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlabel("Number of voters")
ax.set_ylabel("Time (ms)")
ax.set_title("Encrypted tally scales linearly with voters")
ax.legend(frameon=False)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "2_tally_scaling.png"), dpi=160)

# ------------------------------------------------------------- 3. compare schemes
print("3) One vote: Paillier vs AES-GCM vs RSA-OAEP")
vote = b"1"
aes_key = AESGCM.generate_key(bit_length=256)
aes = AESGCM(aes_key)
aes_ms = timeit(lambda: aes.encrypt(os.urandom(12), vote, None), repeat=200)
aes_size = 12 + len(aes.encrypt(os.urandom(12), vote, None))
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
rsa_ms = timeit(lambda: rsa_key.public_key().encrypt(vote, oaep), repeat=50)
rsa_size = len(rsa_key.public_key().encrypt(vote, oaep))
pai_ms = enc_one
pai_size = math.ceil(pub.encrypt(1).ciphertext().bit_length() / 8)
rows = [("AES-256-GCM", aes_ms, aes_size, "No", "Symmetric: anyone who can encrypt can also decrypt"),
        ("RSA-2048-OAEP", rsa_ms, rsa_size, "No", "Asymmetric, but ciphertexts cannot be combined"),
        ("Paillier-2048", pai_ms, pai_size, "Yes (addition)", "Asymmetric and additively homomorphic")]
lines += ["## 3. Encrypting one vote", "",
          "| Scheme | Encrypt time (ms) | Ciphertext size (bytes) | Can tally without decrypting? | Note |",
          "|---|---|---|---|---|"]
for r in rows:
    lines.append(f"| {r[0]} | {r[1]:.3f} | {r[2]} | {r[3]} | {r[4]} |")
lines.append("")
fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 3.8))
names = [r[0] for r in rows]
a1.bar(names, [r[1] for r in rows], color=[GREY, "#9AA3A8", MAROON])
a1.set_yscale("log")
a1.set_title("Encrypt one vote (ms, log)")
a2.bar(names, [r[2] for r in rows], color=[GREY, "#9AA3A8", MAROON])
a2.set_title("Ciphertext size (bytes)")
for a in (a1, a2):
    a.tick_params(axis="x", labelsize=9)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "3_scheme_comparison.png"), dpi=160)

# ------------------------------------------------------------- 4. factoring
print("4) Factoring semiprimes with Pollard's rho")


def is_probable_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def rand_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(p):
            return p


def pollard_rho(n):
    if n % 2 == 0:
        return 2
    while True:
        y, c, m = random.randrange(1, n), random.randrange(1, n), 128
        g, r, q = 1, 1, 1
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = math.gcd(q, n)
                k += m
            r *= 2
        if g == n:
            g = 1
            while g == 1:
                ys = (ys * ys + c) % n
                g = math.gcd(abs(x - ys), n)
        if g != n:
            return g


fbits = [32, 40, 48, 56, 64, 72, 80]
fms = []
for b in fbits:
    ts = []
    for _ in range(3):
        n = rand_prime(b // 2) * rand_prime(b // 2)
        t = time.perf_counter()
        f = pollard_rho(n)
        ts.append((time.perf_counter() - t) * 1000)
        assert n % f == 0
    fms.append(statistics.median(ts))
    print(f"   {b}-bit n: {fms[-1]:.1f} ms")
# rho needs ~ n^(1/4) steps: extrapolate
per_step = fms[-1] / (2 ** (fbits[-1] / 4))
est_2048_years = per_step * 2 ** (2048 / 4) / 1000 / 3600 / 24 / 365
lines += ["## 4. Factoring gets exponentially harder", "",
          "Pollard's rho needs about n^(1/4) steps. Measured on this machine:", "",
          "| Size of n | Median time to factor (ms) |", "|---|---|"]
for b, t in zip(fbits, fms):
    lines.append(f"| {b}-bit | {t:.1f} |")
lines += ["", f"Extrapolating Pollard's rho to a 2048-bit n gives roughly 10^{int(math.log10(est_2048_years))} years. "
          "(The best known classical method, the General Number Field Sieve, is much faster than rho but is still "
          "considered infeasible for 2048-bit n. Shor's algorithm on a large quantum computer would be polynomial-time.)", ""]
fig, ax = plt.subplots(figsize=(7, 4))
ax.plot(fbits, fms, marker="o", color=MAROON)
ax.set_yscale("log")
ax.set_xlabel("Size of n (bits)")
ax.set_ylabel("Time to factor (ms, log)")
ax.set_title("Factoring n with Pollard's rho: each 8 bits ≈ 4× slower")
fig.tight_layout()
fig.savefig(os.path.join(OUT, "4_factoring_difficulty.png"), dpi=160)

with open(os.path.join(OUT, "results.md"), "w") as f:
    f.write("\n".join(lines))
print(f"\nCharts and results.md written to {OUT}")
