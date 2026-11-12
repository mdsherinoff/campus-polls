# Campus Polls benchmark results

Machine: arm64, Python 3.14.2

## 1. Paillier operations (median ms)

| Operation | 1024-bit | 2048-bit | 3072-bit |
|---|---|---|---|
| Key generation | 1.812 | 18.812 | 65.658 |
| Encrypt one value | 0.708 | 4.697 | 12.958 |
| Add two ciphertexts | 0.003 | 0.006 | 0.009 |
| Decrypt | 0.215 | 1.441 | 4.901 |

## 2. Tally time (2048-bit key, one option)

| Voters | Homomorphic tally + 1 decryption (ms) | Total encryption work spread over voters' phones (ms) |
|---|---|---|
| 10 | 1.6 | 51 |
| 100 | 2.2 | 510 |
| 500 | 4.8 | 2552 |
| 1000 | 8.4 | 5105 |
| 5000 | 35.3 | 25523 |
| 10000 | 65.6 | 51046 |

## 3. Encrypting one vote

| Scheme | Encrypt time (ms) | Ciphertext size (bytes) | Can tally without decrypting? | Note |
|---|---|---|---|---|
| AES-256-GCM | 0.001 | 29 | No | Symmetric: anyone who can encrypt can also decrypt |
| RSA-2048-OAEP | 0.023 | 256 | No | Asymmetric, but ciphertexts cannot be combined |
| Paillier-2048 | 5.105 | 512 | Yes (addition) | Asymmetric and additively homomorphic |

## 4. Factoring gets exponentially harder

Pollard's rho needs about n^(1/4) steps. Measured on this machine:

| Size of n | Median time to factor (ms) |
|---|---|
| 32-bit | 0.1 |
| 40-bit | 0.3 |
| 48-bit | 1.3 |
| 56-bit | 2.4 |
| 64-bit | 21.1 |
| 72-bit | 38.4 |
| 80-bit | 317.9 |

Extrapolating Pollard's rho to a 2048-bit n gives roughly 10^140 years. (The best known classical method, the General Number Field Sieve, is much faster than rho but is still considered infeasible for 2048-bit n. Shor's algorithm on a large quantum computer would be polynomial-time.)
