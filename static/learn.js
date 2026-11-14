// Step-by-step Paillier with small numbers (uses BigInt so the maths is exact).
(() => {
  const $ = (id) => document.getElementById(id);
  const PRIMES = [5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43];
  const { modPow, gcd } = Paillier;
  const lcm = (a, b) => (a / gcd(a, b)) * b;
  function modInv(a, m) {
    let [g, x] = egcd(((a % m) + m) % m, m);
    if (g !== 1n) return null;
    return ((x % m) + m) % m;
  }
  function egcd(a, b) {
    let [x0, x1, a0, b0] = [1n, 0n, a, b];
    while (b0) { const q = a0 / b0; [a0, b0] = [b0, a0 - q * b0]; [x0, x1] = [x1, x0 - q * x1]; }
    return [a0, x0];
  }
  function randomR(n) {
    while (true) {
      const r = BigInt(1 + Math.floor(Math.random() * (Number(n) - 1)));
      if (gcd(r, n) === 1n) return r;
    }
  }

  $("p").innerHTML = PRIMES.map((x) => `<option ${x === 11 ? "selected" : ""}>${x}</option>`).join("");
  $("q").innerHTML = PRIMES.map((x) => `<option ${x === 13 ? "selected" : ""}>${x}</option>`).join("");
  let rs = null;

  function run(newR) {
    const p = BigInt($("p").value), q = BigInt($("q").value);
    const votes = [$("v1").value, $("v2").value, $("v3").value].map(BigInt);
    $("err").textContent = "";
    if (p === q) { $("err").textContent = "p and q must be different primes."; return; }
    const n = p * q, n2 = n * n, g = n + 1n;
    if (gcd(n, (p - 1n) * (q - 1n)) !== 1n) { $("err").textContent = "Pick another pair: gcd(n, (p−1)(q−1)) must be 1."; return; }
    const lambda = lcm(p - 1n, q - 1n);
    const L = (x) => (x - 1n) / n;
    const mu = modInv(L(modPow(g, lambda, n2)), n);

    $("s1").innerHTML =
      `p = ${p},  q = ${q}\n` +
      `<b>n = p × q = ${n}</b>          (public key)\n` +
      `n² = ${n2}\n` +
      `g = n + 1 = ${g}\n` +
      `λ = lcm(p−1, q−1) = lcm(${p - 1n}, ${q - 1n}) = <b>${lambda}</b>   (private)\n` +
      `μ = (L(g^λ mod n²))⁻¹ mod n = <b>${mu}</b>          (private)`;

    if (newR || !rs || rs.some((r) => r >= n || gcd(r, n) !== 1n)) rs = votes.map(() => randomR(n));
    const cs = votes.map((m, i) => ((1n + m * n) * modPow(rs[i], n, n2)) % n2);
    $("s2").innerHTML = votes.map((m, i) =>
      `Voter ${i + 1}: m = ${m}, r = ${rs[i]}\n   c${i + 1} = (1 + ${m}·${n}) · ${rs[i]}^${n} mod ${n2} = <b>${cs[i]}</b>`).join("\n\n");

    const C = cs.reduce((a, c) => (a * c) % n2, 1n);
    $("s3").innerHTML = `C = c1 × c2 × c3 mod n²\n  = ${cs.join(" × ")} mod ${n2}\n  = <b>${C}</b>`;

    const u = modPow(C, lambda, n2);
    const total = (L(u) * mu) % n;
    const real = votes.reduce((a, b) => a + b, 0n);
    $("s4").innerHTML =
      `C^λ mod n² = ${C}^${lambda} mod ${n2} = ${u}\n` +
      `L(${u}) = (${u} − 1) / ${n} = ${L(u)}\n` +
      `m = ${L(u)} × ${mu} mod ${n} = <b>${total}</b>\n\n` +
      `Votes were ${votes.join(" + ")} = ${real}  ${total === real ? "✓ correct, and no single ballot was ever decrypted" : "✗"}`;

    // factoring a tiny n is instant
    let f = 2n; while (n % f) f++;
    $("s5").innerHTML = `An attacker sees n = ${n}.\nTrying divisors 2, 3, 4, … finds ${f} × ${n / f} after ${f - 1n} tries. With tiny numbers the key is broken instantly.`;
  }

  async function realKey() {
    try {
      const s = (await (await fetch("/api/state")).json()).election;
      const box = $("realKey");
      if (s && s.paillier_n) {
        const n = s.paillier_n;
        box.innerHTML = `<p>The live poll's public key is a ${s.key_bits}-bit number with <strong>${n.length} digits</strong>:</p>
          <div class="bignum">${n}</div>
          <p style="margin-top:12px">Trial division would need around 10<sup>${Math.floor(n.length / 2) - 1}</sup> attempts.
          Even the best known classical algorithm (the General Number Field Sieve) is estimated to need far longer than the
          age of the universe for a 2048-bit n. A large quantum computer running Shor's algorithm could do it efficiently,
          which is why post-quantum (lattice-based) homomorphic encryption is being developed.</p>`;
      } else {
        box.innerHTML = `<p>In a protected poll the public key n is a 2048-bit number, about 617 digits long. Factoring it with the best
          known classical algorithms would take far longer than the age of the universe. A large quantum computer running
          Shor's algorithm could do it efficiently, which is why post-quantum (lattice-based) schemes are being developed.</p>`;
      }
    } catch {}
  }

  // Presenter mode: reveal one step at a time.
  const items = [...$("steps").children];
  let shown = items.length, stepping = false;
  function applySteps() {
    items.forEach((li, i) => li.classList.toggle("hidden", stepping && i >= shown));
    $("steps").classList.toggle("stepping", stepping);
    $("nextWrap").hidden = !stepping || shown >= items.length;
    $("nextStep").textContent = `Next: step ${Math.min(shown + 1, items.length)} of ${items.length}`;
    $("stepMode").textContent = stepping ? "Show all steps" : "Present step by step";
  }
  $("stepMode").onclick = () => { stepping = !stepping; shown = stepping ? 1 : items.length; applySteps(); };
  $("nextStep").onclick = () => {
    const li = items[shown];
    shown++; applySteps();
    li.classList.add("reveal");
    li.scrollIntoView({ behavior: "smooth", block: "start" });
  };
  document.addEventListener("keydown", (ev) => {
    if (stepping && (ev.key === "ArrowRight" || ev.key === " ") && shown < items.length && ev.target === document.body) {
      ev.preventDefault(); $("nextStep").click();
    }
  });
  applySteps();

  ["p", "q", "v1", "v2", "v3"].forEach((id) => ($(id).onchange = () => run(false)));
  $("reroll").onclick = () => run(true);
  run(true);
  realKey();
})();
