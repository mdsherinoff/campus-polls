"""Cryptographic building blocks used by Campus Polls.

* Paillier (additively homomorphic encryption) -- via the `phe` library.
  Ciphertexts are created in the voter's browser (static/paillier.js) using the
  same scheme as `phe`: g = n + 1, c = (1 + m*n) * r^n mod n^2.
* SHA-256 hash chain -- every accepted ballot is linked to the previous one.
* Ed25519 signatures -- the server signs every bulletin-board entry.
"""
import hashlib
import json
import math
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from phe import paillier

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_DIR = os.environ.get("KEY_DIR", os.path.join(BASE_DIR, "keys"))
SIGNING_KEY_PATH = os.path.join(KEY_DIR, "board_signing_key.pem")
GENESIS_HASH = "0" * 64


# --------------------------------------------------------------- Ed25519 keys
def load_signing_key():
    """Load the bulletin-board signing key.

    The key can be created with OpenSSL:
        openssl genpkey -algorithm ed25519 -out keys/board_signing_key.pem
    If it does not exist yet, one is generated here in the same PEM format.
    """
    os.makedirs(KEY_DIR, exist_ok=True)
    if not os.path.exists(SIGNING_KEY_PATH):
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(SIGNING_KEY_PATH, "wb") as f:
            f.write(pem)
    with open(SIGNING_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def public_key_pem(signing_key):
    return signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def sign(signing_key, entry_hash_hex):
    return signing_key.sign(bytes.fromhex(entry_hash_hex)).hex()


def verify_signature(public_key, entry_hash_hex, signature_hex):
    try:
        public_key.verify(bytes.fromhex(signature_hex), bytes.fromhex(entry_hash_hex))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --------------------------------------------------------------- hash chain
def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def entry_hash(prev_hash, election_id, seq, created_at, payload_json):
    material = f"{prev_hash}|{election_id}|{seq}|{created_at:.3f}|{payload_json}"
    return hashlib.sha256(material.encode()).hexdigest()


# --------------------------------------------------------------- Paillier
def new_paillier_keypair(bits):
    return paillier.generate_paillier_keypair(n_length=bits)


def public_key_from_n(n):
    return paillier.PaillierPublicKey(int(n))


def private_key_from(public_key, p, q):
    return paillier.PaillierPrivateKey(public_key, int(p), int(q))


def encrypt_vote_vector(public_key, choice_index, num_options, value=1):
    """One-hot ballot: an encryption of `value` for the chosen option, 0 for the rest.

    This mirrors what the voter's browser does in static/paillier.js.
    """
    return [
        str(public_key.encrypt(value if i == choice_index else 0).ciphertext())
        for i in range(num_options)
    ]


def is_valid_ciphertext(n, c):
    """Structural check: 0 < c < n^2 and gcd(c, n) = 1.

    Note: this does NOT prove the ciphertext encrypts 0 or 1. Real systems add
    zero-knowledge proofs for that (see the 'malicious ballot' attack).
    """
    return 0 < c < n * n and math.gcd(c, n) == 1


def homomorphic_sum(public_key, ciphertexts):
    """Multiply ciphertexts mod n^2, which adds the hidden votes."""
    total = None
    for c in ciphertexts:
        enc = paillier.EncryptedNumber(public_key, int(c), 0)
        total = enc if total is None else total + enc
    return total


def short(value, head=10, tail=6):
    s = str(value)
    if len(s) <= head + tail + 1:
        return s
    return f"{s[:head]}…{s[-tail:]}"
