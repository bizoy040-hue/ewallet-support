import os, sqlite3, uuid, re
from functools import wraps
from flask import Flask, request, redirect, session, render_template_string, g, flash, abort, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret")
DB = os.environ.get("DATABASE_PATH", "ewallet.db")
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")
MAX_SCREENSHOT_SIZE = 5 * 1024 * 1024
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
app.config.update(MAX_CONTENT_LENGTH=MAX_SCREENSHOT_SIZE, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER_EXTERNAL_HOSTNAME")))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(os.path.abspath(DB)), exist_ok=True)
SITE = "E-Wallet Support"

def normalize_trx(value):
    return re.sub(r"\s+", "", (value or "")).upper()

def save_screenshot(file):
    if not file or not file.filename:
        return None
    original = secure_filename(file.filename)
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError("শুধু PNG, JPG, JPEG বা WEBP ছবি আপলোড করা যাবে।")
    data = file.read(MAX_SCREENSHOT_SIZE + 1)
    if len(data) > MAX_SCREENSHOT_SIZE:
        raise ValueError("ছবির সাইজ ৫ MB-এর বেশি হতে পারবে না।")
    valid = ((ext == "png" and data.startswith(b"\x89PNG\r\n\x1a\n")) or
             (ext in ("jpg", "jpeg") and data.startswith(b"\xff\xd8\xff")) or
             (ext == "webp" and len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP"))
    if not valid:
        raise ValueError("সঠিক PNG, JPG বা WEBP ছবি নির্বাচন করুন।")
    name = uuid.uuid4().hex + "." + ext
    with open(os.path.join(UPLOAD_FOLDER, name), "wb") as target:
        target.write(data)
    return name

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB, timeout=30)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
        g.db.execute("PRAGMA busy_timeout=30000")
    return g.db

@app.errorhandler(413)
def file_too_large(_error):
    return "আপলোড করা ফাইল ৫ MB-এর বেশি। ছোট ছবি দিন।", 413

@app.teardown_appcontext
def close_db(_):
    c = g.pop("db", None)
    if c: c.close()

def init():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=30000")
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT,phone TEXT UNIQUE,pw TEXT,
      balance REAL DEFAULT 0,commission REAL DEFAULT 0,is_admin INTEGER DEFAULT 0,blocked INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS tx(id INTEGER PRIMARY KEY,user_id INTEGER,kind TEXT,method TEXT,
      amount REAL,trx TEXT,status TEXT DEFAULT 'pending',created TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT);
    CREATE TABLE IF NOT EXISTS admin_logs(id INTEGER PRIMARY KEY,admin_id INTEGER,action TEXT,details TEXT,created TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    uc={r["name"] for r in c.execute("PRAGMA table_info(users)")}
    if "member_id" not in uc: c.execute("ALTER TABLE users ADD COLUMN member_id INTEGER")
    tc={r["name"] for r in c.execute("PRAGMA table_info(tx)")}
    if "commission_paid" not in tc: c.execute("ALTER TABLE tx ADD COLUMN commission_paid INTEGER DEFAULT 0")
    if "commission_amount" not in tc: c.execute("ALTER TABLE tx ADD COLUMN commission_amount REAL DEFAULT 0")
    if "trx_key" not in tc: c.execute("ALTER TABLE tx ADD COLUMN trx_key TEXT")
    if "screenshot" not in tc: c.execute("ALTER TABLE tx ADD COLUMN screenshot TEXT")
    # পুরোনো রেকর্ডে একই TrxID থাকলেও startup বন্ধ হবে না; প্রথমটি সংরক্ষণ করে
    # পুরোনো duplicate-গুলোকে legacy হিসেবে রেখে নতুন জমায় uniqueness enforce হবে।
    seen=set()
    for old in c.execute("SELECT id,trx FROM tx WHERE kind='deposit' AND trx IS NOT NULL ORDER BY id").fetchall():
        key=normalize_trx(old["trx"])
        if key and key not in seen:
            c.execute("UPDATE tx SET trx_key=? WHERE id=?", (key, old["id"]))
            seen.add(key)
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_tx_deposit_trx_key ON tx(trx_key) WHERE kind='deposit' AND trx_key IS NOT NULL")
    # পুরোনো ডেটায় ভুলবশত একই Member ID থাকলে নতুন unique index-এর আগে ঠিক করা।
    used={r[0] for r in c.execute("SELECT member_id FROM users WHERE member_id IS NOT NULL")}
    next_mid=max([1499]+[int(x) for x in used if str(x).isdigit()])+1
    duplicates=c.execute("SELECT member_id FROM users WHERE member_id IS NOT NULL GROUP BY member_id HAVING COUNT(*)>1").fetchall()
    for dup in duplicates:
        rows=c.execute("SELECT id FROM users WHERE member_id=? ORDER BY id",(dup[0],)).fetchall()
        for row in rows[1:]:
            while next_mid in used: next_mid+=1
            c.execute("UPDATE users SET member_id=? WHERE id=?",(next_mid,row["id"]))
            used.add(next_mid); next_mid+=1
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_member_id ON users(member_id) WHERE member_id IS NOT NULL")
    n=1500
    for r in c.execute("SELECT id FROM users WHERE member_id IS NULL AND is_admin=0 ORDER BY id").fetchall():
        while n in used: n+=1
        c.execute("UPDATE users SET member_id=? WHERE id=?",(n,r["id"])); used.add(n); n+=1
    defaults={"commission_enabled":"0","deposit_commission_rate":"0","withdraw_commission_rate":"0",
      "bkash":"01XXXXXXXXX","nagad":"01XXXXXXXXX","rocket":"01XXXXXXXXX","min_withdraw":"100","telegram_support":""}
    for k,v in defaults.items(): c.execute("INSERT OR IGNORE INTO settings VALUES(?,?)",(k,v))
    phone=os.environ.get("ADMIN_PHONE","01000000000")
    c.execute("INSERT OR IGNORE INTO users(name,phone,pw,is_admin) VALUES(?,?,?,1)",
      ("Main Admin",phone,generate_password_hash(os.environ.get("ADMIN_PASSWORD","admin123"))))
    c.execute("UPDATE users SET is_admin=1,member_id=NULL WHERE phone=?",(phone,))
    c.commit(); c.close()

def setting(k):
    r=db().execute("SELECT v FROM settings WHERE k=?",(k,)).fetchone()
    return r["v"] if r else ""

def me():
    return db().execute("SELECT * FROM users WHERE id=?",(session["uid"],)).fetchone() if session.get("uid") else None

def login_required(f):
    @wraps(f)
    def w(*a,**kw):
        u=me()
        if not u or u["blocked"]: session.clear(); return redirect("/login")
        return f(*a,**kw)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a,**kw):
        u=me()
        if not u or not u["is_admin"]: abort(403)
        return f(*a,**kw)
    return w

def log(action,details):
    u=me()
    db().execute("INSERT INTO admin_logs(admin_id,action,details) VALUES(?,?,?)",(u["id"],action,details[:400]))

BASE="""<!doctype html><html lang="bn"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{site}}</title>
<style>*{box-sizing:border-box}body{font-family:system-ui,'Noto Sans Bengali',sans-serif;margin:0;background:#f3f5fb;color:#182033}
header{background:linear-gradient(100deg,#173ea8,#087c61);color:white;padding:15px;display:flex;justify-content:space-between;flex-wrap:wrap}
header a{color:white;text-decoration:none;margin-left:10px}main{max-width:900px;margin:auto;padding:14px}
.card{background:white;border-radius:15px;padding:16px;margin-bottom:14px;box-shadow:0 2px 9px #0001}.hero{background:linear-gradient(120deg,#173ea8,#087c61);color:white}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}input,select{width:100%;padding:11px;margin:6px 0 12px;border:1px solid #ccd3e2;border-radius:9px;font-size:15px}
button,.btn{display:inline-block;background:#1d4ed8;color:white;border:0;border-radius:9px;padding:10px 14px;text-decoration:none;cursor:pointer}
.green{background:#15945d}.red{background:#d62e42}.msg{background:#fff1c2;padding:10px;border-radius:9px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:8px 4px;border-bottom:1px solid #e8ebf2}.scroll{overflow-x:auto}small{color:#64748b}
</style></head><body><header><b>{{site}}</b><nav>{% if u %}<a href="/">Home</a><a href="/history">History</a>{% if u['is_admin'] %}<a href="/admin">Admin</a>{% endif %}<a href="/logout">Logout</a>{% else %}<a href="/login">Login</a><a href="/signup">Sign up</a>{% endif %}</nav></header>
<main>{% for m in get_flashed_messages() %}<div class="msg">{{m}}</div>{% endfor %}{{body|safe}}<p><small>Independent platform; not an official bKash/Nagad/Rocket service.</small></p></main></body></html>"""

def page(t,**ctx):
    return render_template_string(BASE,body=render_template_string(t,**ctx),u=me(),site=SITE)

@app.route("/signup",methods=["GET","POST"])
def signup():
    if request.method=="POST":
        name=request.form.get("name","").strip(); phone=request.form.get("phone","").strip(); pw=request.form.get("pw","")
        if not name or not phone.isdigit() or len(phone)!=11 or len(pw)<6:
            flash("নাম, সঠিক ১১ ডিজিটের নম্বর ও কমপক্ষে ৬ অক্ষরের পাসওয়ার্ড দিন।"); return redirect("/signup")
        try:
            c=db(); c.execute("BEGIN IMMEDIATE")
            mid=c.execute("SELECT COALESCE(MAX(member_id),1499)+1 n FROM users WHERE is_admin=0").fetchone()["n"]
            mid=max(1500,mid)
            c.execute("INSERT INTO users(name,phone,pw,member_id) VALUES(?,?,?,?)",(name,phone,generate_password_hash(pw),mid)); c.commit()
            flash(f"অ্যাকাউন্ট তৈরি হয়েছে। Member ID: #{mid}"); return redirect("/login")
        except sqlite3.IntegrityError:
            flash("এই নম্বর দিয়ে অ্যাকাউন্ট আগে থেকেই আছে।"); return redirect("/signup")
    return page("""<div class="card"><h2>সাইন আপ</h2><form method="post">নাম<input name="name" required>মোবাইল<input name="phone" maxlength="11" required>পাসওয়ার্ড<input name="pw" type="password" minlength="6" required><button>সাইন আপ</button></form></div>""")

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=db().execute("SELECT * FROM users WHERE phone=?",(request.form.get("phone","").strip(),)).fetchone()
        if u and check_password_hash(u["pw"],request.form.get("pw","")) and not u["blocked"]:
            session.clear(); session["uid"]=u["id"]; return redirect("/")
        flash("নম্বর/পাসওয়ার্ড ভুল অথবা অ্যাকাউন্ট ব্লকড।"); return redirect("/login")
    return page("""<div class="card"><h2>সাইন ইন</h2><form method="post">মোবাইল<input name="phone" required>পাসওয়ার্ড<input name="pw" type="password" required><button>সাইন ইন</button></form></div>""")

@app.route("/logout")
def logout(): session.clear(); return redirect("/login")

@app.route("/")
@login_required
def home():
    u=me(); support=setting("telegram_support")
    return page("""<div class="card hero"><h3>স্বাগতম, {{u['name']}}</h3><h1>৳ {{'%.2f'|format(u['balance'])}}</h1>Wallet Balance<br>Member ID: #{{u['member_id'] or 'ADMIN'}}<p><a class="btn green" href="/deposit">ডিপোজিট</a> <a class="btn" href="/withdraw">উইথড্র</a></p></div>
    <div class="grid"><div class="card">মোট কমিশন<h3>৳ {{'%.2f'|format(u['commission'])}}</h3></div><div class="card">অ্যাকাউন্ট<h3>Active</h3></div></div>
    {% if support %}<div class="card"><a class="btn green" href="{{support}}" target="_blank">Telegram Support</a></div>{% endif %}""",u=u,support=support)

@app.route("/deposit",methods=["GET","POST"])
@login_required
def deposit():
    if request.method=="POST":
        try: amount=float(request.form.get("amount","0"))
        except ValueError: amount=0
        trx=request.form.get("trx","").strip(); method=request.form.get("method","")
        if amount<=0 or not trx: flash("সঠিক পরিমাণ ও TrxID দিন।"); return redirect("/deposit")
        screenshot=None
        try:
            screenshot=save_screenshot(request.files.get("screenshot"))
            key=normalize_trx(trx)
            if not key: raise ValueError("সঠিক TrxID দিন।")
            db().execute("INSERT INTO tx(user_id,kind,method,amount,trx,trx_key,screenshot) VALUES(?,?,?,?,?,?,?)",
                (session["uid"],"deposit",method,amount,trx,key,screenshot)); db().commit()
        except ValueError as e:
            if screenshot:
                try: os.remove(os.path.join(UPLOAD_FOLDER, screenshot))
                except OSError: pass
            flash(str(e)); return redirect("/deposit")
        except sqlite3.IntegrityError:
            if screenshot:
                try: os.remove(os.path.join(UPLOAD_FOLDER, screenshot))
                except OSError: pass
            flash("এই TrxID ইতিমধ্যে জমা হয়েছে। একই TrxID দ্বিতীয়বার ব্যবহার করা যাবে না।"); return redirect("/deposit")
        flash("ডিপোজিট রিকোয়েস্ট জমা হয়েছে।"); return redirect("/history")
    return page("""<div class="card"><h2>ডিপোজিট</h2>bKash: {{bk}}<br>Nagad: {{ng}}<br>Rocket: {{rk}}<form method="post" enctype="multipart/form-data">মাধ্যম<select name="method"><option>bKash</option><option>Nagad</option><option>Rocket</option></select>পরিমাণ<input name="amount" type="number" min="1" step=".01" required>TrxID<input name="trx" required><label>পেমেন্টের স্ক্রিনশট (ঐচ্ছিক)</label><input name="screenshot" type="file" accept="image/png,image/jpeg,image/webp"><small>PNG, JPG বা WEBP · সর্বোচ্চ ৫ MB</small><br><button>জমা দিন</button></form></div>""",bk=setting("bkash"),ng=setting("nagad"),rk=setting("rocket"))

@app.route("/withdraw",methods=["GET","POST"])
@login_required
def withdraw():
    if request.method=="POST":
        try: amount=float(request.form.get("amount","0"))
        except ValueError: amount=0
        u=me(); number=request.form.get("number","").strip(); c=db()
        if amount<=0 or amount<float(setting("min_withdraw") or 0) or amount>u["balance"] or not number:
            flash("ন্যূনতম সীমা, ব্যালেন্স অথবা নম্বর যাচাই করুন।"); return redirect("/withdraw")
        try:
            screenshot=save_screenshot(request.files.get("screenshot"))
        except ValueError as e:
            flash(str(e)); return redirect("/withdraw")
        try:
            c.execute("BEGIN IMMEDIATE")
            c.execute("UPDATE users SET balance=balance-? WHERE id=? AND balance>=?",(amount,u["id"],amount))
            if c.execute("SELECT changes()").fetchone()[0]!=1:
                c.rollback()
                if screenshot:
                    try: os.remove(os.path.join(UPLOAD_FOLDER, screenshot))
                    except OSError: pass
                flash("ব্যালেন্স কম।"); return redirect("/withdraw")
            c.execute("INSERT INTO tx(user_id,kind,method,amount,trx,screenshot) VALUES(?,?,?,?,?,?)",
                (u["id"],"withdraw",request.form.get("method"),amount,number,screenshot)); c.commit()
        except Exception:
            c.rollback()
            if screenshot:
                try: os.remove(os.path.join(UPLOAD_FOLDER, screenshot))
                except OSError: pass
            raise
        flash("উইথড্র রিকোয়েস্ট জমা হয়েছে।"); return redirect("/history")
    return page("""<div class="card"><h2>উইথড্র</h2>সর্বনিম্ন ৳{{mn}}<form method="post" enctype="multipart/form-data">মাধ্যম<select name="method"><option>bKash</option><option>Nagad</option><option>Rocket</option></select>পরিমাণ<input name="amount" type="number" min="1" step=".01" required>আপনার নম্বর<input name="number" required><label>স্ক্রিনশট যুক্ত করুন (ঐচ্ছিক)</label><input name="screenshot" type="file" accept="image/png,image/jpeg,image/webp"><small>PNG, JPG বা WEBP · সর্বোচ্চ ৫ MB</small><br><button>রিকোয়েস্ট</button></form></div>""",mn=setting("min_withdraw"))

@app.route("/tx-screenshot/<int:tx_id>")
@login_required
def tx_screenshot(tx_id):
    t=db().execute("SELECT user_id,screenshot FROM tx WHERE id=?", (tx_id,)).fetchone()
    u=me()
    if not t or not t["screenshot"] or (not u["is_admin"] and t["user_id"] != u["id"]):
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, t["screenshot"], as_attachment=False)

@app.route("/history")
@login_required
def history():
    rows=db().execute("SELECT * FROM tx WHERE user_id=? ORDER BY id DESC LIMIT 100",(session["uid"],)).fetchall()
    return page("""<div class="card"><h2>লেনদেনের ইতিহাস</h2><div class="scroll"><table><tr><th>ধরন</th><th>মাধ্যম</th><th>টাকা</th><th>অবস্থা</th><th>স্ক্রিনশট</th><th>তারিখ</th></tr>{% for r in rows %}<tr><td>{{r['kind']}}</td><td>{{r['method']}}</td><td>{{r['amount']}}</td><td>{{r['status']}}</td><td>{% if r['screenshot'] %}<a href="/tx-screenshot/{{r['id']}}" target="_blank">দেখুন</a>{% else %}—{% endif %}</td><td>{{r['created'][:16]}}</td></tr>{% else %}<tr><td colspan="6">কোনো লেনদেন নেই।</td></tr>{% endfor %}</table></div></div>""",rows=rows)

@app.route("/admin")
@admin_required
def admin():
    c=db(); pending=c.execute("SELECT tx.*,users.name,users.phone,users.member_id FROM tx JOIN users ON users.id=tx.user_id WHERE tx.status='pending' ORDER BY tx.id").fetchall()
    q=request.args.get("q","").strip(); like="%"+q+"%"
    users=c.execute("""SELECT * FROM users WHERE is_admin=0 AND (?='' OR name LIKE ? OR phone LIKE ? OR CAST(member_id AS TEXT) LIKE ?) ORDER BY id DESC LIMIT 150""",(q,like,like,like)).fetchall()
    keys=("commission_enabled","deposit_commission_rate","withdraw_commission_rate","bkash","nagad","rocket","min_withdraw","telegram_support")
    st={k:setting(k) for k in keys}
    logs=c.execute("SELECT admin_logs.*,users.name FROM admin_logs LEFT JOIN users ON users.id=admin_logs.admin_id ORDER BY admin_logs.id DESC LIMIT 15").fetchall()
    return page("""<div class="card"><h2>Admin Panel</h2>Pending: {{pending|length}} | Users: {{users|length}}</div>
    <div class="card"><h3>Pending Requests</h3>{% for r in pending %}<p><b>{{r['kind']}}</b> ৳{{r['amount']}} · {{r['method']}}<br>{{r['name']}} (#{{r['member_id']}}) · {{r['phone']}}<br>Trx/নম্বর: {{r['trx']}}
    {% if r['screenshot'] %}<br><a class="btn" href="/tx-screenshot/{{r['id']}}" target="_blank">স্ক্রিনশট দেখুন</a>{% endif %}
    <form method="post" action="/admin/tx/{{r['id']}}/approve" style="display:inline"><button class="green">Approve</button></form>
    <form method="post" action="/admin/tx/{{r['id']}}/reject" style="display:inline"><button class="red">Reject</button></form></p><hr>{% else %}<small>কোনো পেন্ডিং নেই।</small>{% endfor %}</div>
    <div class="card"><h3>Commission & Payment Settings</h3><form method="post" action="/admin/settings">
    কমিশন চালু<select name="commission_enabled"><option value="0" {% if st['commission_enabled']=='0' %}selected{% endif %}>বন্ধ</option><option value="1" {% if st['commission_enabled']=='1' %}selected{% endif %}>চালু</option></select>
    Deposit commission (%)<input name="deposit_commission_rate" type="number" min="0" max="100" step=".01" value="{{st['deposit_commission_rate']}}">
    Withdrawal commission (%)<input name="withdraw_commission_rate" type="number" min="0" max="100" step=".01" value="{{st['withdraw_commission_rate']}}">
    bKash<input name="bkash" value="{{st['bkash']}}">Nagad<input name="nagad" value="{{st['nagad']}}">Rocket<input name="rocket" value="{{st['rocket']}}">
    Minimum withdrawal<input name="min_withdraw" type="number" min="1" value="{{st['min_withdraw']}}">Telegram support URL<input name="telegram_support" value="{{st['telegram_support']}}">
    <button>সেভ সেটিংস</button></form></div>
    <div class="card"><h3>ইউজার খুঁজুন</h3><form method="get"><input name="q" value="{{q}}" placeholder="নাম / ফোন / Member ID"><button>Search</button></form>
    <div class="scroll"><table><tr><th>ID</th><th>নাম</th><th>ফোন</th><th>ব্যালেন্স</th><th></th></tr>{% for x in users %}<tr><td>#{{x['member_id']}}</td><td>{{x['name']}}</td><td>{{x['phone']}}</td><td>{{x['balance']}}</td><td><a class="btn" href="/admin/user/{{x['id']}}">দেখুন</a></td></tr>{% endfor %}</table></div></div>
    <div class="card"><h3>ম্যানুয়াল কমিশন</h3><form method="post" action="/admin/commission">Member ID<input name="member_id" type="number" min="1500" required>টাকা<input name="amount" type="number" min=".01" step=".01" required>কারণ<input name="note" required><button>কমিশন দিন</button></form></div>
    <div class="card"><h3>Admin Activity Log</h3>{% for l in logs %}<p><small>{{l['created']}} · {{l['name'] or 'Admin'}}</small><br>{{l['action']}} — {{l['details']}}</p>{% endfor %}</div>""",pending=pending,users=users,q=q,st=st,logs=logs)

@app.route("/admin/tx/<int:i>/<action>",methods=["POST"])
@admin_required
def admin_tx(i,action):
    if action not in ("approve","reject"): abort(400)
    c=db()
    try:
        c.execute("BEGIN IMMEDIATE")
        t=c.execute("SELECT * FROM tx WHERE id=? AND status='pending'",(i,)).fetchone()
        if not t:
            c.rollback(); flash("এই রিকোয়েস্ট আগেই প্রসেস হয়েছে।"); return redirect("/admin")
        status="approved" if action=="approve" else "rejected"
        c.execute("UPDATE tx SET status=? WHERE id=? AND status='pending'",(status,i))
        if c.execute("SELECT changes()").fetchone()[0] != 1:
            c.rollback(); flash("এই রিকোয়েস্ট আগেই প্রসেস হয়েছে।"); return redirect("/admin")
        if action=="reject":
            if t["kind"]=="withdraw":
                c.execute("UPDATE users SET balance=balance+? WHERE id=?",(t["amount"],t["user_id"]))
        else:
            if t["kind"]=="deposit":
                c.execute("UPDATE users SET balance=balance+? WHERE id=?",(t["amount"],t["user_id"]))
            ratekey="deposit_commission_rate" if t["kind"]=="deposit" else "withdraw_commission_rate"
            if setting("commission_enabled")=="1" and not t["commission_paid"]:
                try: rate=max(0,min(100,float(setting(ratekey) or 0)))
                except (ValueError,TypeError): rate=0
                bonus=round(t["amount"]*rate/100,2)
                if bonus: c.execute("UPDATE users SET balance=balance+?,commission=commission+? WHERE id=?",(bonus,bonus,t["user_id"]))
                c.execute("UPDATE tx SET commission_paid=1,commission_amount=? WHERE id=?",(bonus,i))
        log("Transaction "+action,f"TX #{i}, amount {t['amount']}")
        c.commit()
    except Exception:
        c.rollback(); raise
    flash("রিকোয়েস্ট আপডেট হয়েছে।")
    return redirect("/admin")

@app.route("/admin/user/<int:i>")
@admin_required
def admin_user(i):
    x=db().execute("SELECT * FROM users WHERE id=? AND is_admin=0",(i,)).fetchone()
    if not x: abort(404)
    rows=db().execute("SELECT * FROM tx WHERE user_id=? ORDER BY id DESC LIMIT 30",(i,)).fetchall()
    return page("""<div class="card"><h2>{{x['name']}} · #{{x['member_id']}}</h2>ফোন: {{x['phone']}}<br>ব্যালেন্স: ৳{{x['balance']}}<br>কমিশন: ৳{{x['commission']}}<br>অবস্থা: {{'Blocked' if x['blocked'] else 'Active'}}
    <form method="post" action="/admin/user/{{x['id']}}/toggle"><button class="red">{{'Unblock' if x['blocked'] else 'Block'}}</button></form></div>
    <div class="card"><h3>ব্যালেন্স পরিবর্তন</h3><form method="post" action="/admin/user/{{x['id']}}/balance">অ্যাকশন<select name="direction"><option value="add">যোগ</option><option value="subtract">বিয়োগ</option></select>টাকা<input name="amount" type="number" min=".01" step=".01" required>কারণ<input name="reason" required><button>আপডেট</button></form></div>
    <div class="card"><h3>লেনদেন</h3><div class="scroll"><table><tr><th>ধরন</th><th>টাকা</th><th>অবস্থা</th><th>প্রমাণ</th><th>তারিখ</th></tr>{% for r in rows %}<tr><td>{{r['kind']}}</td><td>{{r['amount']}}</td><td>{{r['status']}}</td><td>{% if r['screenshot'] %}<a href="/tx-screenshot/{{r['id']}}" target="_blank">দেখুন</a>{% else %}—{% endif %}</td><td>{{r['created']}}</td></tr>{% endfor %}</table></div></div>""",x=x,rows=rows)

@app.route("/admin/user/<int:i>/toggle",methods=["POST"])
@admin_required
def toggle_user(i):
    c=db(); c.execute("UPDATE users SET blocked=1-blocked WHERE id=? AND is_admin=0",(i,)); log("User status changed",f"User {i}"); c.commit()
    return redirect(f"/admin/user/{i}")

@app.route("/admin/user/<int:i>/balance",methods=["POST"])
@admin_required
def balance_adjust(i):
    try: amount=float(request.form.get("amount","0"))
    except ValueError: amount=0
    direction=request.form.get("direction"); reason=request.form.get("reason","").strip()
    if amount<=0 or not reason or direction not in ("add","subtract"): flash("সঠিক তথ্য দিন।"); return redirect(f"/admin/user/{i}")
    delta=amount if direction=="add" else -amount; c=db()
    c.execute("UPDATE users SET balance=balance+? WHERE id=? AND is_admin=0 AND balance+?>=0",(delta,i,delta))
    if c.execute("SELECT changes()").fetchone()[0]!=1: c.rollback(); flash("ব্যালেন্স কমানো সম্ভব নয়।"); return redirect(f"/admin/user/{i}")
    c.execute("INSERT INTO tx(user_id,kind,method,amount,trx,status) VALUES(?,?,?,?,?,'approved')",(i,"adjustment","admin",delta,reason))
    log("Balance adjusted",f"User {i}: {delta}; {reason}"); c.commit(); flash("ব্যালেন্স আপডেট হয়েছে।"); return redirect(f"/admin/user/{i}")

@app.route("/admin/commission",methods=["POST"])
@admin_required
def manual_commission():
    try: amount=float(request.form.get("amount","0")); mid=int(request.form.get("member_id","0"))
    except ValueError: amount=0; mid=0
    note=request.form.get("note","").strip(); c=db()
    u=c.execute("SELECT * FROM users WHERE member_id=? AND is_admin=0",(mid,)).fetchone()
    if not u or amount<=0 or not note: flash("সঠিক Member ID, টাকা ও কারণ দিন।"); return redirect("/admin")
    c.execute("UPDATE users SET balance=balance+?,commission=commission+? WHERE id=?",(amount,amount,u["id"]))
    c.execute("INSERT INTO tx(user_id,kind,method,amount,trx,status) VALUES(?,?,?,?,?,'approved')",(u["id"],"commission","admin",amount,note))
    log("Manual commission",f"Member #{mid}: {amount}; {note}"); c.commit(); flash("কমিশন যোগ হয়েছে।"); return redirect("/admin")

@app.route("/admin/settings",methods=["POST"])
@admin_required
def save_settings():
    c=db()
    keys=("commission_enabled","deposit_commission_rate","withdraw_commission_rate","bkash","nagad","rocket","min_withdraw","telegram_support")
    for k in keys:
        v=request.form.get(k,"").strip()
        if k in ("deposit_commission_rate","withdraw_commission_rate","min_withdraw"):
            try:
                n=float(v)
                if n<0 or (k!="min_withdraw" and n>100): raise ValueError()
            except ValueError: flash("কমিশন রেট বা ন্যূনতম উইথড্র সঠিক নয়।"); return redirect("/admin")
        c.execute("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",(k,v))
    log("Settings updated","Payment and commission settings changed"); c.commit(); flash("সেটিংস সেভ হয়েছে।"); return redirect("/admin")

init()
if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))
