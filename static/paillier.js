/*
 * Paillier encryption in the voter's browser (CMPS 380 Group G03).
 *
 * Uses the same scheme as the server's `phe` library:
 *   public key: n          (n = p*q, two large secret primes)
 *   g = n + 1
 *   Enc(m) = g^m * r^n mod n^2  =  (1 + m*n) * r^n mod n^2   for random r in [1, n) with gcd(r, n) = 1
 *
 * Only the public key n is ever sent to the phone, so the phone can encrypt
 * but nobody without p and q can decrypt.
 */
const Paillier = (() => {
  function modPow(base, exp, mod) {
    let result = 1n;
    base %= mod;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      exp >>= 1n;
      base = (base * base) % mod;
    }
    return result;
  }

  function gcd(a, b) {
    while (b) [a, b] = [b, a % b];
    return a;
  }

  function bitLength(x) {
    return x.toString(2).length;
  }

  // Cryptographically secure random BigInt in [1, n)
  function randomBelow(n) {
    const bits = bitLength(n);
    const bytes = Math.ceil(bits / 8);
    const excess = BigInt(bytes * 8 - bits);
    while (true) {
      const buf = new Uint8Array(bytes);
      crypto.getRandomValues(buf);
      let x = 0n;
      for (const b of buf) x = (x << 8n) | BigInt(b);
      x >>= excess;
      if (x > 0n && x < n) return x;
    }
  }

  function encrypt(m, n) {
    const n2 = n * n;
    let r;
    do { r = randomBelow(n); } while (gcd(r, n) !== 1n);
    const gm = (1n + BigInt(m) * n) % n2;          // g^m with g = n + 1
    return (gm * modPow(r, n, n2)) % n2;
  }

  return { encrypt, modPow, gcd };
})();
