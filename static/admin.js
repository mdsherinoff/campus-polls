// Control room (projector view).
(() => {
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const time = (t) => new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  let lastOptions = "";
  let lastElection = null;
  let seen = new Set();
  let state = null;
  $("joinUrl").textContent = location.host;

  async function post(url, body) {
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
    if (r.status === 403) location.reload();
    return r.json();
  }

  function bars(options, totals) {
    const sum = totals.reduce((a, b) => a + b, 0) || 1;
    const max = Math.max(...totals);
    return `<div class="bars">${options.map((o, i) => `
      <div class="bar-row ${totals[i] === max && max > 0 ? "lead" : ""}"><div class="bar-label">${esc(o)}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${(totals[i] / sum) * 100}%"></div></div>
        <div class="bar-num"><b>${totals[i]}</b><span>${Math.round((totals[i] / sum) * 100)}%</span></div></div>`).join("")}</div>`;
  }

  function render(s) {
    state = s;
    const e = s.election;
    if (!e) {
      $("question").textContent = "No poll yet";
      $("stats").innerHTML = `<div class="stat"><span>Choose a poll and a mode below, then press Open poll.</span></div>`;
      return;
    }
    if (lastElection !== e.id) { seen = new Set(s.ballots.map((b) => b.seq)); lastElection = e.id; }
    const protectedMode = e.mode === "protected";
    $("caption").innerHTML = `Control room &middot; Poll ${e.id}
      <span class="pill ${e.mode}">${protectedMode ? "Protected" : "Basic"}</span>
      <span class="pill ${e.status === "open" ? "neutral live" : "neutral"}">${e.status === "open" ? "Voting open" : "Closed"}</span>`;
    $("question").textContent = e.question;
    $("closePoll").disabled = e.status !== "open";
    $("simulate").disabled = e.status !== "open";

    const integrity = !protectedMode ? `<b style="color:var(--bad)">None</b>`
      : s.intact ? `<b class="status-ok">Intact</b>` : `<b class="status-bad">Tampered</b>`;
    $("stats").innerHTML = `
      <div class="stat"><b>${s.ballots.length}</b><span>Ballots stored</span></div>
      ${protectedMode
        ? `<div class="stat"><b>${s.codes.used}<small style="font-size:18px;color:var(--muted)"> / ${s.codes.issued}</small></b><span>Codes used / issued</span></div>`
        : `<div class="stat"><b>${s.codes.issued}</b><span>Codes issued, never checked</span></div>`}
      <div class="stat">${integrity}<span>Bulletin board</span></div>
      <div class="stat"><b>${protectedMode ? e.key_bits + "-bit" : "None"}</b><span>Encryption</span></div>`;

    document.querySelectorAll(".defence").forEach((d) => {
      d.textContent = protectedMode ? `Defence: ${d.dataset.def}` : "No defence in basic mode";
      d.style.color = protectedMode ? "" : "var(--bad)";
    });

    const optKey = e.options.join("|");
    if (optKey !== lastOptions) {
      $("target").innerHTML = e.options.map((o, i) => `<option value="${i}">${esc(o)}</option>`).join("");
      lastOptions = optKey;
    }

    // results
    let res = "", note = "";
    if (s.result) {
      const r = s.result;
      if (r.mode === "protected") {
        note = `${r.ballots} ballots`;
        res += r.certified
          ? `<div class="outcome blocked"><span class="verdict">Certified result</span>All ${r.ballots} encrypted ballots were combined without decrypting any of them. Only the totals were decrypted (add ${r.add_ms} ms, decrypt ${r.decrypt_ms} ms).</div>`
          : `<div class="outcome succeeded"><span class="verdict">Not certified</span>The bulletin board failed its integrity check, so this result cannot be trusted.</div>`;
        res += bars(r.options, r.totals);
        res += `<details style="margin-top:16px"><summary>Encrypted totals before decryption</summary><table>${r.options.map((o, i) =>
          `<tr><td>${esc(o)}</td><td class="mono">${esc(r.encrypted_totals[i] ?? "–")}</td></tr>`).join("")}</table></details>`;
      } else {
        note = `${r.ballots} ballots`;
        res += `<div class="outcome succeeded"><span class="verdict">Final count, unverifiable</span>Counted by reading every plain-text ballot. Nobody can prove these were not changed.</div>` + bars(r.options, r.totals);
      }
    } else if (s.live_totals) {
      note = "Live: the server reads every vote as it arrives";
      res = bars(e.options, s.live_totals);
    } else {
      note = "Hidden until voting closes";
      res = `<div class="panel"><p><strong>The server cannot read any of the ${s.ballots.length} ballots.</strong>
        It can only add them up while they are encrypted. The total is decrypted once voting closes.</p>
        <p class="hint">Public key n, ${e.n_digits} digits: <span class="mono">${esc(e.n_preview)}</span></p></div>`;
    }
    $("resultsNote").textContent = note;
    $("results").innerHTML = res;

    // ballots table (newest first, new rows flash)
    $("ballots").innerHTML = s.ballots.slice().reverse().map((b) => {
      const vote = b.plain !== undefined
        ? `<strong>${esc(b.plain)}</strong>`
        : `<span class="mono">${b.ciphertexts.map(esc).join("<br>")}</span>`;
      const st = b.status === "unprotected" ? `<span class="status-bad">none</span>`
        : b.status === "ok" ? `<span class="status-ok">✓ valid</span>` : `<span class="status-bad">✗ ${esc(b.status)}</span>`;
      const fresh = !seen.has(b.seq) ? " fresh" : "";
      const cls = (b.status !== "ok" && b.status !== "unprotected" ? "row-bad" : b.source === "attacker" ? "attacker" : "") + fresh;
      const who = b.voter_code ? `<span class="mono">${esc(b.voter_code)}</span>` : `<span class="hint">not stored</span>`;
      const src = b.source === "attacker" ? ` <span class="pill basic" style="font-size:11px;padding:0 5px">attacker</span>`
        : b.source === "simulated" ? ` <span class="hint" title="simulated voter">sim</span>` : "";
      return `<tr class="${cls}"><td>${b.seq}${src}</td><td>${who}</td><td>${vote}</td><td>${st}</td></tr>`;
    }).join("") || `<tr><td colspan="4" class="empty">No ballots yet. Ask the room to scan the QR code.</td></tr>`;
    s.ballots.forEach((b) => seen.add(b.seq));

    // traffic
    $("traffic").innerHTML = s.traffic.length
      ? s.traffic.slice(0, 2).map((t) => `<pre class="wire"><span class="k">${time(t.created_at)}  POST /api/vote</span>  from ${esc(t.source)}\n${esc(t.body)}</pre>`).join("")
      : `<p class="empty">Nothing captured yet.</p>`;

    // events
    $("events").innerHTML = s.events.map((ev) =>
      `<li class="${esc(ev.kind)}"><time>${time(ev.created_at)}</time>${esc(ev.message)}</li>`).join("")
      || `<li class="empty" style="border:0">Nothing yet.</li>`;
  }

  async function refresh() {
    try {
      const r = await fetch("/api/admin/state", { cache: "no-store" });
      if (r.status === 403) return location.reload();
      render(await r.json());
    } catch {}
  }

  const busy = (msg) => { $("busy").textContent = msg || ""; };

  $("newPoll").onclick = async () => {
    const e = state && state.election;
    if (e && e.status === "open" && state.ballots.length && !confirm("A poll is still open. Close it and start a new one?")) return;
    const mode = $("mode").value;
    $("newPoll").disabled = true;
    busy(mode === "protected" ? "Generating a fresh 2048-bit Paillier key pair" : "Opening the poll");
    await post("/api/admin/election", { poll: $("poll").value, mode });
    $("outcomes").innerHTML = "";
    $("newPoll").disabled = false;
    busy(""); refresh();
  };
  $("closePoll").onclick = async () => {
    busy("Closing voting and counting");
    await post("/api/admin/close");
    busy(""); refresh();
  };
  $("simulate").onclick = async () => {
    $("simulate").disabled = true;
    busy("Simulated phones are voting");
    const d = await post("/api/admin/simulate", { count: Number($("simN").value) || 10 });
    $("simulate").disabled = false;
    busy(""); refresh();
    if (!d.ok) alert(d.message);
  };

  const VERDICT = { succeeded: "Attack succeeded", blocked: "Blocked", detected: "Detected", limitation: "Got through: known limitation", info: "" };
  document.querySelectorAll("[data-attack]").forEach((b) => {
    b.onclick = async () => {
      b.disabled = true;
      busy("Running the attack");
      const d = await post(`/api/admin/attack/${b.dataset.attack}`, { target: Number($("target").value) });
      b.disabled = false; busy("");
      const box = $("outcomes");
      [...box.children].forEach((c) => c.classList.add("old"));
      box.insertAdjacentHTML("afterbegin",
        `<div class="outcome ${esc(d.outcome)}"><span class="what">${esc(d.title)}</span>${VERDICT[d.outcome] ? `<span class="verdict">${VERDICT[d.outcome]}</span>` : ""}${esc(d.message)}</div>`);
      while (box.children.length > 2) box.lastElementChild.remove();
      refresh();
    };
  });

  refresh();
  setInterval(refresh, 2000);
})();
