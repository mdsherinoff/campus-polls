"""Campus Polls -- CMPS 380 Group G03 web application (Flask)."""
import hmac
import io
import os
import secrets

import qrcode
import qrcode.image.svg
from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

import attacks
import crypto_core as cc
import voting
from polls import POLLS

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["TEMPLATES_AUTO_RELOAD"] = True

voting.init()


def _load_admin_key():
    key = os.environ.get("ADMIN_KEY")
    if key:
        return key
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "admin_key.txt")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    key = secrets.token_urlsafe(9)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(key)
    return key


ADMIN_KEY = _load_admin_key()
print(f"[Campus Polls] Admin page: /admin?key={ADMIN_KEY}", flush=True)


def _key_ok(candidate):
    # compare as bytes so a non-ASCII key gives "wrong key", not an error
    return hmac.compare_digest(str(candidate).encode(), ADMIN_KEY.encode())


def is_admin():
    return session.get("admin") is True


def admin_required(fn):
    def wrapper(*a, **kw):
        if not is_admin():
            return jsonify({"error": "admin only"}), 403
        return fn(*a, **kw)
    wrapper.__name__ = fn.__name__
    return wrapper


# ------------------------------------------------------------------ pages
@app.route("/")
def vote_page():
    return render_template("vote.html")


@app.route("/learn")
def learn_page():
    return render_template("learn.html")


@app.route("/board")
def board_page():
    return render_template("board.html")


@app.route("/verify")
def verify_page():
    return render_template("verify.html", receipt=request.args.get("r", ""))


@app.route("/admin")
def admin_page():
    key = request.args.get("key")
    if key is not None:
        if _key_ok(key):
            session["admin"] = True
            return redirect(url_for("admin_page"))
        return render_template("admin_login.html", error=True), 403
    if not is_admin():
        return render_template("admin_login.html", error=False)
    return render_template("admin.html", polls=POLLS)


@app.route("/admin/login", methods=["POST"])
def admin_login():
    if _key_ok(request.form.get("key", "")):
        session["admin"] = True
        return redirect(url_for("admin_page"))
    return render_template("admin_login.html", error=True), 403


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("vote_page"))


@app.route("/qr.svg")
def qr_svg():
    url = request.host_url
    img = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage, box_size=12, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return Response(buf.getvalue(), mimetype="image/svg+xml")


# ------------------------------------------------------------------ public API
@app.get("/api/state")
def api_state():
    return jsonify(voting.public_state())


@app.post("/api/register")
def api_register():
    body = request.get_json(silent=True) or {}
    code = voting.register_code(body.get("election_id"))
    if not code:
        return jsonify({"ok": False, "message": "This poll is not open."}), 409
    return jsonify({"ok": True, "code": code})


@app.post("/api/vote")
def api_vote():
    res = voting.submit_ballot(request.get_json(silent=True) or {}, source="voter")
    return jsonify(res), (200 if res["ok"] else 400)


@app.get("/api/board")
def api_board():
    return jsonify(voting.board())


@app.get("/api/verify")
def api_verify():
    return jsonify(voting.verify_receipt(request.args.get("receipt", "")))


@app.get("/api/board-public-key.pem")
def api_board_key():
    return Response(cc.public_key_pem(voting.SIGNING_KEY), mimetype="text/plain")


# ------------------------------------------------------------------ admin API
@app.get("/api/admin/state")
@admin_required
def api_admin_state():
    return jsonify(voting.admin_state())


@app.post("/api/admin/election")
@admin_required
def api_admin_new():
    body = request.get_json(silent=True) or {}
    try:
        eid = voting.create_election(body.get("poll"), body.get("mode"))
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    return jsonify({"ok": True, "id": eid})


@app.post("/api/admin/close")
@admin_required
def api_admin_close():
    return jsonify({"ok": True, "result": voting.close_and_tally()})


@app.post("/api/admin/simulate")
@admin_required
def api_admin_simulate():
    body = request.get_json(silent=True) or {}
    return jsonify(voting.simulate_voters(body.get("count", 10)))


@app.post("/api/admin/attack/<name>")
@admin_required
def api_admin_attack(name):
    fn = attacks.ATTACKS.get(name)
    if not fn:
        return jsonify({"outcome": "info", "title": name, "message": "Unknown attack"}), 404
    body = request.get_json(silent=True) or {}
    kwargs = {}
    if name not in ("replay", "undo_tamper"):
        kwargs["target_idx"] = int(body.get("target", 0))
    return jsonify(fn(**kwargs))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5050)), debug=False, threaded=True)
