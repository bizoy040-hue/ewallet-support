import os, sqlite3
from functools import wraps
from flask import Flask, request, redirect, session, render_template_string, g, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret")
DB = "ewallet.db"
SITE = "E-Wallet সাপোর্ট"

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close(_):
    d = g.pop("db", None)
    if d: d.close()

def init():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, phone TEXT UNIQUE, pw TEXT,
        balance REAL DEFAULT 0, commission REAL DEFAULT 0, is_admin INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS tx(id INTEGER PRIMARY KEY, user_id INTEGER, kind TEXT, method TEXT,
        amount REAL, trx TEXT, status TEXT DEFAULT 'pending', created TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
    INSERT OR IGNORE INTO settings VALUES('commission_rate','2');
    INSERT OR IGNORE INTO settings VALUES('bkash','01XXXXXXXXX');
    INSERT OR IGNORE INTO settings VALUES('nagad','01XXXXXXXXX');
    INSERT OR IGNORE INTO settings VALUES('min_withdraw','100');
    """)
    ap = os.environ.get("ADMIN_PASSWORD", "admin123")
    c.execute("INSERT OR IGNORE INTO users(name,phone,pw,is_admin) VALUES(?,?,?,1)",
              ("Main Admin", os.environ.get("ADMIN_PHONE", "01000000000"), generate_password_hash(ap)))
    c.commit(); c.close()

def setting(k):
    return db().execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()["v"]

def me():
    if "uid" in session:
        return db().execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        u = me()
        if not u or u["blocked"]: session.clear(); return redirect("/login")
        return f(*a, **k)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        u = me()
        if not u or not u["is_admin"]: return redirect("/login")
        return f(*a, **k)
    return w

BASE = """<!doctype html><html lang="bn"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{site}}</title>
<style>
*{box-sizing:border-box}body{font-family:system-ui,'Noto Sans Bengali',sans-serif;margin:0;background:#f3f5fb;color:#1b2033}
header{background:linear-gradient(90deg,#1d4ed8,#16a34a);color:#fff;padding:16px;display:flex;justify-content:space-between;align-items:center}
header a{color:#fff;margin-left:12px;text-decoration:none;font-size:14px}
main{max-width:560px;margin:0 auto;padding:16px}
.card{background:#fff;border-radius:16px;padding:16px;margin-bottom:14px;box-shadow:0 2px 8px #0001}
.big{background:linear-gradient(120deg,#1d4ed8,#16a34a);color:#fff}.big h1{margin:6px 0}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
input,select{width:100%;padding:12px;margin:6px 0 12px;border:1px solid #cbd2e6;border-radius:10px;font-size:15px}
button,.btn{background:#1d4ed8;color:#fff;border:0;padding:12px 16px;border-radius:10px;font-size:15px;cursor:pointer;text-decoration:none;display:inline-block}
.red{background:#dc2626}.green{background:#16a34a}.gray{background:#64748b}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:8px 4px;border-bottom:1px solid #eef}
.msg{background:#fef3c7;padding:10px;border-radius:10px;margin-bottom:12px}
small{color:#64748b}
</style></head><body>
<header><b>{{site}}</b><nav>
{% if u %}<a href="/">হোম</a><a href="/history">হিস্ট্রি</a>{% if u['is_admin'] %}<a href="/admin">অ্যাডমিন</a>{% endif %}<a href="/logout">লগআউট</a>
{% else %}<a href="/login">সাইন ইন</a><a href="/signup">সাইন আপ</a>{% endif %}</nav></header>
<main>{% for m in get_flashed_messages() %}<div class="msg">{{m}}</div>{% endfor %}
{{body|safe}}
<p><small>এটি একটি স্বাধীন প্ল্যাটফর্ম। bKash, Nagad বা Rocket-এর অফিশিয়াল সাইট নয়।</small></p>
</main></body></html>"""

def page(body_tpl, **ctx):
    body = render_template_string(body_tpl, **ctx)
    return render_template_string(BASE, body=body, u=me(), site=SITE)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        n, p, pw = request.form["name"].strip(), request.form["phone"].strip(), request.form["pw"]
        if len(pw) < 6 or not p.isdigit() or len(p) != 11:
            flash("সঠিক ১১ ডিজিটের নম্বর ও কমপক্ষে ৬ অক্ষরের পাসওয়ার্ড দিন।"); return redirect("/signup")
        try:
            db().execute("INSERT INTO users(name,phone,pw) VALUES(?,?,?)", (n, p, generate_password_hash(pw)))
            db().commit()
        except sqlite3.IntegrityError:
            flash("এই নম্বর দিয়ে আগেই অ্যাকাউন্ট আছে।"); return redirect("/signup")
        flash("অ্যাকাউন্ট তৈরি হয়েছে, সাইন ইন করুন।"); return redirect("/login")
    return page("""<div class="card"><h2>সাইন আপ</h2><form method="post">
    নাম<input name="name" required>মোবাইল নম্বর<input name="phone" required maxlength="11">
    পাসওয়ার্ড<input name="pw" type="password" required><button>সাইন আপ</button></form></div>""")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db().execute("SELECT * FROM users WHERE phone=?", (request.form["phone"].strip(),)).fetchone()
        if u and check_password_hash(u["pw"], request.form["pw"]) and not u["blocked"]:
            session["uid"] = u["id"]; return redirect("/")
        flash("নম্বর/পাসওয়ার্ড ভুল অথবা অ্যাকাউন্ট ব্লকড।"); return redirect("/login")
    return page("""<div class="card"><h2>সাইন ইন</h2><form method="post">
    মোবাইল নম্বর<input name="phone" required>পাসওয়ার্ড<input name="pw" type="password" required>
    <button>সাইন ইন</button></form></div>""")

@app.route("/logout")
def logout():
    session.clear(); return redirect("/login")

@app.route("/")
@login_required
def home():
    u = me()
    d = db().execute("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE user_id=? AND kind='deposit' AND status='approved' AND date(created)=date('now')", (u["id"],)).fetchone()["s"]
    w = db().execute("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE user_id=? AND kind='withdraw' AND status='approved' AND date(created)=date('now')", (u["id"],)).fetchone()["s"]
    return page("""<div class="card big">হ্যালো, {{u['name']}}<h1>BDT {{'%.2f'|format(u['balance'])}}</h1>ওয়ালেট ব্যালেন্স
    <p><a class="btn green" href="/deposit">ডিপোজিট</a> <a class="btn gray" href="/withdraw">উইথড্র</a></p></div>
    <div class="grid"><div class="card">মোট কমিশন<h3>BDT {{'%.2f'|format(u['commission'])}}</h3></div>
    <div class="card">আজকের ডিপোজিট<h3>BDT {{'%.0f'|format(d)}}</h3></div>
    <div class="card">আজকের উইথড্র<h3>BDT {{'%.0f'|format(w)}}</h3></div>
    <div class="card">ইউজার আইডি<h3>#{{u['id']}}</h3></div></div>""", u=u, d=d, w=w)

@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    if request.method == "POST":
        try: amt = float(request.form["amount"])
        except ValueError: amt = 0
        if amt <= 0: flash("সঠিক পরিমাণ দিন।"); return redirect("/deposit")
        db().execute("INSERT INTO tx(user_id,kind,method,amount,trx) VALUES(?,?,?,?,?)",
                     (session["uid"], "deposit", request.form["method"], amt, request.form["trx"].strip()))
        db().commit(); flash("ডিপোজিট রিকোয়েস্ট জমা হয়েছে, অ্যাডমিন যাচাই করবেন।"); return redirect("/history")
    return page("""<div class="card"><h2>ডিপোজিট</h2>
    <p>bKash: <b>{{bk}}</b><br>Nagad: <b>{{ng}}</b><br><small>টাকা পাঠিয়ে নিচে TrxID দিন।</small></p>
    <form method="post">মাধ্যম<select name="method"><option>bKash</option><option>Nagad</option><option>Rocket</option></select>
    পরিমাণ<input name="amount" type="number" step="any" required>TrxID<input name="trx" required><button>জমা দিন</button></form></div>""",
    bk=setting("bkash"), ng=setting("nagad"))

@app.route("/withdraw", methods=["GET", "POST"])
@login_required
def withdraw():
    u = me()
    if request.method == "POST":
        try: amt = float(request.form["amount"])
        except ValueError: amt = 0
        if amt < float(setting("min_withdraw")) or amt > u["balance"]:
            flash("পরিমাণ সীমার বাইরে বা ব্যালেন্স কম।"); return redirect("/withdraw")
        db().execute("UPDATE users SET balance=balance-? WHERE id=?", (amt, u["id"]))
        db().execute("INSERT INTO tx(user_id,kind,method,amount,trx) VALUES(?,?,?,?,?)",
                     (u["id"], "withdraw", request.form["method"], amt, request.form["number"].strip()))
        db().commit(); flash("উইথড্র রিকোয়েস্ট জমা হয়েছে।"); return redirect("/history")
    return page("""<div class="card"><h2>উইথড্র</h2><small>ন্যূনতম {{mn}} টাকা</small>
    <form method="post">মাধ্যম<select name="method"><option>bKash</option><option>Nagad</option><option>Rocket</option></select>
    পরিমাণ<input name="amount" type="number" step="any" required>আপনার নম্বর<input name="number" required><button>রিকোয়েস্ট</button></form></div>""",
    mn=setting("min_withdraw"))

@app.route("/history")
@login_required
def history():
    rows = db().execute("SELECT * FROM tx WHERE user_id=? ORDER BY id DESC LIMIT 100", (session["uid"],)).fetchall()
    return page("""<div class="card"><h2>হিস্ট্রি</h2><table><tr><th>ধরন</th><th>মাধ্যম</th><th>টাকা</th><th>অবস্থা</th><th>তারিখ</th></tr>
    {% for r in rows %}<tr><td>{{r['kind']}}</td><td>{{r['method']}}</td><td>{{r['amount']}}</td><td>{{r['status']}}</td><td>{{r['created'][:16]}}</td></tr>{% endfor %}
    </table></div>""", rows=rows)

@app.route("/admin")
@admin_required
def admin():
    pend = db().execute("SELECT tx.*,users.name,users.phone FROM tx JOIN users ON users.id=tx.user_id WHERE tx.status='pending' ORDER BY tx.id").fetchall()
    users = db().execute("SELECT * FROM users WHERE is_admin=0 ORDER BY id DESC").fetchall()
    st = {k: setting(k) for k in ("commission_rate", "bkash", "nagad", "min_withdraw")}
    return page("""<div class="card"><h2>পেন্ডিং রিকোয়েস্ট ({{pend|length}})</h2>
    {% for r in pend %}<p><b>{{r['kind']}}</b> {{r['method']}} — {{r['amount']}} টাকা<br>{{r['name']}} ({{r['phone']}})<br>TrxID/নম্বর: {{r['trx']}}<br>
    <a class="btn green" href="/admin/tx/{{r['id']}}/approve">অ্যাপ্রুভ</a> <a class="btn red" href="/admin/tx/{{r['id']}}/reject">রিজেক্ট</a></p><hr>{% endfor %}</div>
    <div class="card"><h2>সেটিংস</h2><form method="post" action="/admin/settings">
    ডিফল্ট কমিশন রেট (%) — শুধু ক্যালকুলেশনের রেফারেন্স<input name="commission_rate" value="{{st['commission_rate']}}">
    bKash নম্বর<input name="bkash" value="{{st['bkash']}}">Nagad নম্বর<input name="nagad" value="{{st['nagad']}}">
    ন্যূনতম উইথড্র<input name="min_withdraw" value="{{st['min_withdraw']}}"><button>সেভ</button></form></div>
    <div class="card"><h2>কমিশন দিন</h2><small>সত্যিকারের কাজ/সার্ভিস সম্পন্ন হলে দিন</small>
    <form method="post" action="/admin/commission">ইউজার<select name="uid">{% for x in users %}<option value="{{x['id']}}">{{x['name']}} ({{x['phone']}})</option>{% endfor %}</select>
    টাকা<input name="amount" type="number" step="any" required>কারণ/নোট<input name="note" required><button>কমিশন যোগ করুন</button></form></div>
    <div class="card"><h2>ইউজার ({{users|length}})</h2><table><tr><th>নাম</th><th>নম্বর</th><th>ব্যালেন্স</th><th></th></tr>
    {% for x in users %}<tr><td>{{x['name']}}</td><td>{{x['phone']}}</td><td>{{x['balance']}}</td>
    <td><a href="/admin/user/{{x['id']}}/toggle">{{'আনব্লক' if x['blocked'] else 'ব্লক'}}</a></td></tr>{% endfor %}</table></div>""",
    pend=pend, users=users, st=st)

@app.route("/admin/tx/<int:i>/<act>")
@admin_required
def admin_tx(i, act):
    t = db().execute("SELECT * FROM tx WHERE id=? AND status='pending'", (i,)).fetchone()
    if t:
        if act == "approve":
            if t["kind"] == "deposit":
                db().execute("UPDATE users SET balance=balance+? WHERE id=?", (t["amount"], t["user_id"]))
            db().execute("UPDATE tx SET status='approved' WHERE id=?", (i,))
        elif act == "reject":
            if t["kind"] == "withdraw":
                db().execute("UPDATE users SET balance=balance+? WHERE id=?", (t["amount"], t["user_id"]))
            db().execute("UPDATE tx SET status='rejected' WHERE id=?", (i,))
        db().commit()
    return redirect("/admin")

@app.route("/admin/user/<int:i>/toggle")
@admin_required
def toggle(i):
    db().execute("UPDATE users SET blocked=1-blocked WHERE id=? AND is_admin=0", (i,)); db().commit()
    return redirect("/admin")

@app.route("/admin/commission", methods=["POST"])
@admin_required
def give_commission():
    try: amt = float(request.form["amount"])
    except ValueError: amt = 0
    if amt > 0:
        uid = int(request.form["uid"])
        db().execute("UPDATE users SET balance=balance+?, commission=commission+? WHERE id=? AND is_admin=0", (amt, amt, uid))
        db().execute("INSERT INTO tx(user_id,kind,method,amount,trx,status) VALUES(?,?,?,?,?,'approved')",
                     (uid, "commission", "admin", amt, request.form["note"].strip()))
        db().commit(); flash("কমিশন যোগ হয়েছে।")
    return redirect("/admin")

@app.route("/admin/settings", methods=["POST"])
@admin_required
def settings():
    for k in ("commission_rate", "bkash", "nagad", "min_withdraw"):
        db().execute("UPDATE settings SET v=? WHERE k=?", (request.form[k].strip(), k))
    db().commit(); flash("সেভ হয়েছে।"); return redirect("/admin")

init()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
