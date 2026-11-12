// Voter page: one-time code -> choose -> (encrypt on this phone) -> send -> receipt.
(() => {
  const app = document.getElementById("app");
  let election = null;
  let busy = false;

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch {} },
  };
  const key = (name) => `cp_${name}_${election.id}`;
  const shorten = (s, h = 18, t = 8) => (s.length > h + t + 1 ? `${s.slice(0, h)}…${s.slice(-t)}` : s);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const isProtected = () => election.mode === "protected";

  async function refresh(force) {
    if (busy) return;
    let data;
    try { data = await (await fetch("/api/state", { cache: "no-store" })).json(); } catch { return; }
    const e = data.election;
    const changed = !election || !e || e.id !== election.id || e.status !== election.status;
    election = e;
    if (force || changed) render();
  }

  function header(stepIdx) {
    const steps = isProtected() ? ["Choose", "Encrypt", "Receipt"] : ["Choose", "Send", "Done"];
    const pill = isProtected()
      ? `<span class="pill protected">Protected poll</span>`
      : `<span class="pill basic">Basic poll</span>`;
    return `<div class="caption">Poll ${election.id} ${pill}</div>
      <ol class="stepper" aria-label="Progress">${steps.map((s, i) =>
        `<li class="${i < stepIdx ? "done" : i === stepIdx ? "current" : ""}" ${i === stepIdx ? 'aria-current="step"' : ""}>${i + 1}. ${s}</li>`).join("")}</ol>`;
  }

  function render() {
    if (!election) {
      app.innerHTML = `<h1>No poll is open yet</h1>
        <p>Keep this page open. The ballot will appear here by itself when voting starts.</p>
        <p class="waiting">Waiting for the next poll</p>`;
      return;
    }
    if (election.status !== "open") return renderClosed();
    if (store.get(key("voted"))) return renderDone();
    if (!store.get(key("code"))) return fetchCode();
    renderBallot();
  }

  async function fetchCode() {
    app.innerHTML = `<p class="waiting">Getting your one-time voting code</p>`;
    try {
      const r = await fetch("/api/register", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ election_id: election.id }),
      });
      const d = await r.json();
      if (!d.ok) return refresh(true);
      store.set(key("code"), d.code);
      renderBallot();
    } catch {
      app.innerHTML = `<div class="notice bad"><h2>Could not reach the server</h2><p>Check your connection and try again.</p></div>
        <button class="btn" onclick="location.reload()">Try again</button>`;
    }
  }

  function renderBallot() {
    const code = store.get(key("code"));
    const opts = election.options.map((o, i) => `
      <label class="radio"><input type="radio" name="choice" value="${i}"><span>${esc(o)}</span></label>`).join("");
    app.innerHTML = `${header(0)}
      <form id="ballot" novalidate>
        <fieldset>
          <legend><h1>${esc(election.question)}</h1></legend>
          <div class="codechip" title="Each code can cast one vote">Your one-time code <strong>${esc(code)}</strong></div>
          <p class="inset ${election.mode}">${isProtected()
            ? "Your choice is <strong>encrypted on this phone</strong> before it is sent. The server only ever sees unreadable numbers."
            : "Your choice is sent and stored as <strong>readable text</strong>, like many simple online polls."}</p>
          <div class="radios">${opts}</div>
        </fieldset>
        <div class="actionbar">
          <p class="err" id="err" role="alert"></p>
          <button class="btn block" type="submit" id="cast" disabled>Choose an option</button>
        </div>
      </form>`;
    const cast = document.getElementById("cast");
    app.querySelectorAll('input[name="choice"]').forEach((r) => r.addEventListener("change", () => {
      cast.disabled = false;
      cast.textContent = `Cast vote for ${election.options[Number(r.value)]}`;
      document.getElementById("err").textContent = "";
    }));
    document.getElementById("ballot").onsubmit = submitVote;
  }

  async function submitVote(ev) {
    ev.preventDefault();
    const picked = app.querySelector('input[name="choice"]:checked');
    if (!picked) { document.getElementById("err").textContent = "Choose an option first."; return; }
    const idx = Number(picked.value);
    const body = { election_id: election.id, code: store.get(key("code")) };
    busy = true;
    let ms = null;
    try {
      if (isProtected()) {
        ms = await encryptWithAnimation(idx, body);
      } else {
        body.choice = election.options[idx];
        app.innerHTML = `${header(1)}<h1>Sending your vote</h1><p class="waiting">Sending</p>`;
        await sleep(300);
      }
      const r = await fetch("/api/vote", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      const d = await r.json();
      busy = false;
      if (!d.ok) {
        app.innerHTML = `<div class="notice bad"><h1>Your vote was not accepted</h1><p>${esc(d.message)}</p></div>
          <button class="btn secondary" onclick="location.reload()">Back</button>`;
        return;
      }
      const shown = { ...body };
      if (shown.ciphertexts) shown.ciphertexts = shown.ciphertexts.map((c) => `${shorten(c)} (${c.length} digits)`);
      store.set(key("voted"), "1");
      store.set(key("choice"), election.options[idx]);
      if (d.receipt) { store.set(key("receipt"), d.receipt); store.set("cp_last_receipt", d.receipt); }
      store.set(key("sent"), `POST /api/vote\n${JSON.stringify(shown, null, 2)}` + (ms ? `\n\n// encrypted on this phone in ${ms} ms` : ""));
      renderDone(true);
    } catch (e) {
      busy = false;
      app.innerHTML = `<div class="notice bad"><h1>Something went wrong</h1><p>${esc(e.message || e)}</p></div>
        <button class="btn secondary" onclick="location.reload()">Try again</button>`;
    }
  }

  async function encryptWithAnimation(idx, body) {
    const n = BigInt(election.paillier_n);
    app.innerHTML = `${header(1)}
      <h1>Encrypting on your phone</h1>
      <p>Each option gets a <strong>1</strong> (your choice) or a <strong>0</strong>, locked with the poll's
         ${election.key_bits}-bit public key. Every result looks like a random 1,200-digit number.</p>
      <table class="enc-table" aria-live="polite"><tbody>${election.options.map((o, i) => `
        <tr id="row${i}"><td class="opt">${esc(o)}</td><td class="val ${i === idx ? "one" : ""}">${i === idx ? 1 : 0}</td>
        <td class="ct" id="ct${i}">waiting</td></tr>`).join("")}</tbody></table>
      <p class="hint" id="encnote">Nothing has been sent yet.</p>`;
    const cts = [];
    let total = 0;
    for (let i = 0; i < election.options.length; i++) {
      const row = document.getElementById(`row${i}`), cell = document.getElementById(`ct${i}`);
      row.classList.add("active");
      const spin = setInterval(() => {
        let s = ""; for (let k = 0; k < 34; k++) s += Math.floor(Math.random() * 10);
        cell.textContent = s;
      }, 45);
      await sleep(260);
      const t0 = performance.now();
      const c = Paillier.encrypt(i === idx ? 1 : 0, n).toString();
      total += performance.now() - t0;
      clearInterval(spin);
      cts.push(c);
      cell.textContent = `${shorten(c, 22, 8)}`;
      cell.classList.add("done");
      row.classList.remove("active");
    }
    document.getElementById("encnote").textContent = "Sending only the encrypted numbers…";
    body.ciphertexts = cts;
    await sleep(350);
    return Math.round(total);
  }

  function renderDone(justVoted) {
    const receipt = store.get(key("receipt"));
    const choice = store.get(key("choice"));
    app.innerHTML = `${header(3)}
      <div class="confirm"><h1>Vote cast</h1>
        <p>${choice ? `You voted for <strong>${esc(choice)}</strong>. ` : ""}${isProtected()
          ? "Only this phone knows that: the server holds just the encrypted ballot."
          : "The server stored this as plain text."}</p></div>
      ${isProtected() && receipt ? `
        <div class="receipt-box"><span class="label">Your receipt</span>
          <span class="value" id="rcpt">${esc(receipt)}</span>
          <button class="btn small secondary" id="copy" type="button">Copy receipt</button>
          <a class="btn small secondary" href="/verify?r=${encodeURIComponent(receipt)}">Check my vote</a>
          <p class="hint" style="margin:6px 0 0">This is the SHA-256 fingerprint of your ballot on the public
            <a href="/board">bulletin board</a>. Use it any time to confirm your ballot is still there, unchanged.
            It is also saved on this phone.</p>
        </div>` : !isProtected() ? `
        <div class="notice warn"><p><strong>No receipt.</strong> A basic poll gives you no way to check that your vote
          was counted, or that nobody changed it.</p></div>` : ""}
      <details ${justVoted ? "" : ""}><summary>What did my phone actually send?</summary>
        <p class="hint" style="margin-top:8px">Exactly what anyone watching the network, or reading the server's logs, would see.</p>
        <pre class="wire">${esc(store.get(key("sent")) || "")}</pre></details>
      <p class="waiting">Results will appear here when voting closes</p>`;
    const copy = document.getElementById("copy");
    if (copy) copy.onclick = async () => {
      try { await navigator.clipboard.writeText(receipt); copy.textContent = "Copied"; }
      catch { const r = document.createRange(); r.selectNodeContents(document.getElementById("rcpt")); getSelection().removeAllRanges(); getSelection().addRange(r); }
    };
  }

  function renderClosed() {
    const choice = store.get(key("choice"));
    app.innerHTML = `<div class="caption">Poll ${election.id} <span class="pill neutral">Closed</span></div>
      <h1>${esc(election.question)}</h1>
      ${choice ? `<p>You voted for <strong>${esc(choice)}</strong>.</p>` : ""}
      ${election.result ? resultsHtml(election.result) : `<p class="waiting">Counting the votes</p>`}
      <p class="waiting" style="margin-top:28px">Keep this page open for the next poll</p>`;
  }

  function resultsHtml(res) {
    const sum = res.totals.reduce((a, b) => a + b, 0) || 1;
    const max = Math.max(...res.totals);
    const note = res.mode === "protected"
      ? (res.certified
        ? `<p class="hint">${res.ballots} encrypted ballots were added up without opening any of them. Only these totals were decrypted.</p>`
        : `<div class="notice bad"><p><strong>Not certified.</strong> The bulletin board failed its integrity check.</p></div>`)
      : `<p class="hint">Counted by reading every ballot.</p>`;
    return `<h2>Results</h2>${note}<div class="bars">${res.options.map((o, i) => `
      <div class="bar-row ${res.totals[i] === max && max > 0 ? "lead" : ""}">
        <div class="bar-label">${esc(o)}${res.totals[i] === max && max > 0 ? '<span class="winner">Top</span>' : ""}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${(res.totals[i] / sum) * 100}%"></div></div>
        <div class="bar-num"><b>${Math.round((res.totals[i] / sum) * 100)}%</b><span>${res.totals[i]} vote${res.totals[i] === 1 ? "" : "s"}</span></div>
      </div>`).join("")}</div>`;
  }

  refresh(true);
  setInterval(() => refresh(false), 3000);
})();
