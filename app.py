"""E-Wallet Support v3 - single file app (Flask + SQLite).
Env: SECRET_KEY, ADMIN_PHONE, ADMIN_PASSWORD, DATABASE_PATH, UPLOAD_DIR, BASE_URL (optional)
"""
import os, re, sqlite3, secrets, hashlib, time
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, request, redirect, session, render_template_string, g, flash,
                   abort, send_file, jsonify)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")),
                  MAX_CONTENT_LENGTH=3 * 1024 * 1024,
                  PERMANENT_SESSION_LIFETIME=timedelta(days=7))
if os.environ.get("RENDER"):  # trust exactly one proxy hop (Render) for real client IP / https
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
DB = os.environ.get("DATABASE_PATH", "ewallet.db")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(os.path.dirname(os.path.abspath(DB)), "uploads"))
SITE = "E-Wallet Support"
METHODS = ("bKash", "Nagad", "Rocket")
SCHEMA_VERSION = 3
CODE_ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

# ---------------------------------------------------------------- roles & permissions (enforced server-side)
ROLES = {"super_admin": "সুপার অ্যাডমিন", "admin": "অ্যাডমিন", "finance": "ফাইন্যান্স স্টাফ", "support": "সাপোর্ট স্টাফ"}
PERM_LABELS = {
    "dashboard_fin": "আর্থিক পরিসংখ্যান দেখা", "deposits": "ডিপোজিট প্রসেস", "withdrawals": "উইথড্র প্রসেস",
    "users_view": "ইউজার/লেনদেন দেখা", "users_manage": "ইউজার ব্লক ও রিসেট কোড", "adjust": "ব্যালেন্স সমন্বয়",
    "referrals": "রেফারেল অনুমোদন", "commissions": "কমিশন প্রদান", "tickets": "সাপোর্ট টিকিট",
    "notices": "নোটিশ প্রকাশ", "audit": "অডিট লগ দেখা"}
ADMIN_ASSIGNABLE = tuple(PERM_LABELS)                       # what a Super Admin can grant to an "admin"
ADMIN_DEFAULT = tuple(p for p in ADMIN_ASSIGNABLE if p != "adjust")
ROLE_FIXED = {"finance": frozenset({"dashboard_fin", "deposits", "withdrawals", "users_view", "referrals", "commissions"}),
              "support": frozenset({"tickets", "users_view"})}
SUPER_ONLY = frozenset({"staff", "settings", "backup"})

WELCOME_DEFAULT = ("আসসালামু আলাইকুম!\n\nআমাদের E-Wallet Support প্ল্যাটফর্মে আপনাকে স্বাগতম।\n\n"
                   "আপনার সময়, দক্ষতা ও প্রচেষ্টাকে কাজে লাগিয়ে আমাদের সঙ্গে কাজ করার সুযোগ গ্রহণ করুন।\n\n"
                   "আপনার যাত্রা শুরু হোক আজ থেকেই!")


def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB, timeout=30, isolation_level=None)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
        g.db.execute("PRAGMA busy_timeout=30000")
    return g.db


@app.teardown_appcontext
def _close(_):
    d = g.pop("db", None)
    if d:
        d.close()


def q1(sql, a=()):
    return db().execute(sql, a).fetchone()


def qa(sql, a=()):
    return db().execute(sql, a).fetchall()


def money(x):
    return "{:,.2f}".format(float(x or 0))


def norm_trx(s):
    return re.sub(r"[^A-Z0-9]", "", (s or "").upper())


def parse_amount(s):
    try:
        v = round(float(str(s).replace(",", "").strip()), 2)
    except (ValueError, TypeError):
        return 0.0
    return v if 0 < v < 10_000_000 else 0.0


def gen_code(conn):
    while True:
        code = "".join(secrets.choice(CODE_ALPHA) for _ in range(8))
        if not conn.execute("SELECT 1 FROM users WHERE referral_code=?", (code,)).fetchone():
            return code


# ---------------------------------------------------------------- migrations
def _cols(c, t):
    return [r[1] for r in c.execute("PRAGMA table_info(%s)" % t)]


def _addcol(c, t, col, decl):
    if col not in _cols(c, t):
        c.execute("ALTER TABLE %s ADD COLUMN %s %s" % (t, col, decl))


def _prebackup(c):
    """Before upgrading an existing older database, keep a consistent copy next to it (never overwritten)."""
    if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'").fetchone():
        return
    ver = 0
    if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone():
        r = c.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
        ver = int(r[0]) if r and str(r[0]).isdigit() else 0
    if ver >= SCHEMA_VERSION:
        return
    dst = sqlite3.connect("%s.pre-v%d-%s.bak" % (DB, SCHEMA_VERSION, datetime.utcnow().strftime("%Y%m%d%H%M%S")))
    c.backup(dst)
    dst.close()


def migrate():
    """Non-destructive, idempotent. Never drops/clears/rewrites existing users, balances, member ids or history."""
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    c = sqlite3.connect(DB, timeout=30, isolation_level=None)
    c.row_factory = sqlite3.Row
    _prebackup(c)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, phone TEXT UNIQUE, pw TEXT,
        balance REAL DEFAULT 0, commission REAL DEFAULT 0, is_admin INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS tx(id INTEGER PRIMARY KEY, user_id INTEGER, kind TEXT, method TEXT,
        amount REAL, trx TEXT, status TEXT DEFAULT 'pending', created TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
    CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
    CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, kind TEXT NOT NULL,
        amount REAL NOT NULL, ref_type TEXT, ref_id INTEGER, idem TEXT UNIQUE, note TEXT, actor TEXT,
        created TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS ix_ledger_user ON ledger(user_id);
    CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger
        BEGIN SELECT RAISE(ABORT,'ledger is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger
        BEGIN SELECT RAISE(ABORT,'ledger is immutable'); END;
    CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, body TEXT,
        is_read INTEGER DEFAULT 0, created TEXT);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, actor TEXT, action TEXT, detail TEXT, created TEXT);
    CREATE TABLE IF NOT EXISTS login_history(id INTEGER PRIMARY KEY, user_id INTEGER, phone TEXT, ip TEXT,
        ok INTEGER, created TEXT);
    CREATE TABLE IF NOT EXISTS resets(id INTEGER PRIMARY KEY, user_id INTEGER, token_hash TEXT, expires TEXT,
        used INTEGER DEFAULT 0, created TEXT);
    CREATE TABLE IF NOT EXISTS tickets(id INTEGER PRIMARY KEY, user_id INTEGER, subject TEXT, message TEXT,
        reply TEXT, status TEXT DEFAULT 'open', created TEXT);
    CREATE TABLE IF NOT EXISTS referrals(id INTEGER PRIMARY KEY,
        referrer_id INTEGER NOT NULL REFERENCES users(id),
        referred_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
        code TEXT, amount REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending', note TEXT,
        created TEXT NOT NULL, decided_by TEXT, decided_by_id INTEGER, decided_at TEXT,
        CHECK(referrer_id<>referred_id), CHECK(status IN('pending','approved','rejected')));
    CREATE INDEX IF NOT EXISTS ix_ref_referrer ON referrals(referrer_id);
    CREATE INDEX IF NOT EXISTS ix_ref_status ON referrals(status);
    CREATE TABLE IF NOT EXISTS commissions(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
        amount REAL NOT NULL CHECK(amount>0), reason TEXT NOT NULL, given_by_id INTEGER, given_by TEXT,
        idem TEXT UNIQUE, created TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS ix_comm_user ON commissions(user_id);
    """)
    c.execute("BEGIN IMMEDIATE")
    for col, decl in (("member_id", "TEXT"), ("created", "TEXT"), ("last_login", "TEXT"),
                      ("session_ver", "INTEGER DEFAULT 0"), ("comm_rate_note", "TEXT"),
                      ("role", "TEXT"), ("perms", "TEXT"), ("referral_code", "TEXT"),
                      ("referred_by", "INTEGER"), ("signup_ip", "TEXT")):
        _addcol(c, "users", col, decl)
    for col, decl in (("norm_trx", "TEXT"), ("note", "TEXT"), ("screenshot", "TEXT"),
                      ("updated", "TEXT"), ("number", "TEXT")):
        _addcol(c, "tx", col, decl)
    _addcol(c, "audit", "actor_id", "INTEGER")
    _addcol(c, "audit", "ip", "TEXT")
    _addcol(c, "tickets", "replied_by", "TEXT")
    _addcol(c, "tickets", "replied_at", "TEXT")
    # preserve existing member ids; assign new ones only to users lacking one
    nxt = c.execute("SELECT COALESCE(MAX(CAST(member_id AS INTEGER)),1499) FROM users WHERE member_id GLOB '[0-9]*'").fetchone()[0]
    for r in c.execute("SELECT id,is_admin FROM users WHERE member_id IS NULL ORDER BY id").fetchall():
        if r["is_admin"]:
            c.execute("UPDATE users SET member_id='ADMIN' WHERE id=?", (r["id"],))
        else:
            nxt += 1
            c.execute("UPDATE users SET member_id=? WHERE id=?", (str(nxt), r["id"]))
    c.execute("UPDATE users SET created=COALESCE(created,?) WHERE created IS NULL", (now(),))
    c.execute("UPDATE tx SET norm_trx=UPPER(REPLACE(REPLACE(COALESCE(trx,''),' ',''),'-','')) "
              "WHERE norm_trx IS NULL AND kind='deposit'")
    c.execute("CREATE INDEX IF NOT EXISTS ix_tx_user ON tx(user_id)")
    # roles: existing customers -> 'user'; first existing admin -> super_admin; other legacy admins -> admin
    c.execute("UPDATE users SET role='user' WHERE role IS NULL AND COALESCE(is_admin,0)=0")
    if not c.execute("SELECT 1 FROM users WHERE role='super_admin'").fetchone():
        first = c.execute("SELECT id FROM users WHERE is_admin=1 AND role IS NULL ORDER BY id LIMIT 1").fetchone()
        if first:
            c.execute("UPDATE users SET role='super_admin' WHERE id=?", (first["id"],))
    c.execute("UPDATE users SET role='admin', perms=? WHERE is_admin=1 AND role IS NULL", (",".join(ADMIN_ASSIGNABLE),))
    # referral codes for every customer lacking one (existing codes never change)
    for r in c.execute("SELECT id FROM users WHERE is_admin=0 AND referral_code IS NULL ORDER BY id").fetchall():
        c.execute("UPDATE users SET referral_code=? WHERE id=?", (gen_code(c), r["id"]))
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_refcode ON users(referral_code) WHERE referral_code IS NOT NULL")
    # opening-balance ledger entry ONLY for legacy users that have a balance but no ledger history at all.
    # (Users who already have ledger rows are never touched, so balances are never double-counted;
    #  any genuine mismatch is left visible in the dashboard reconciliation instead of being hidden.)
    for r in c.execute("SELECT u.id,u.balance FROM users u WHERE NOT EXISTS(SELECT 1 FROM ledger l WHERE l.user_id=u.id)").fetchall():
        if round(r["balance"] or 0, 2) != 0:
            c.execute("INSERT OR IGNORE INTO ledger(user_id,kind,amount,idem,note,actor,created) VALUES(?,?,?,?,?,?,?)",
                      (r["id"], "opening_balance", round(r["balance"], 2), "open:%d" % r["id"],
                       "Migration: opening balance", "system", now()))
    # copy past manual commissions (from the ledger) into the dedicated commissions table
    c.execute("INSERT OR IGNORE INTO commissions(user_id,amount,reason,given_by,idem,created) "
              "SELECT user_id,amount,COALESCE(NULLIF(note,''),'-'),actor,idem,created FROM ledger "
              "WHERE kind='commission' AND amount>0 AND idem IS NOT NULL")
    defaults = {"bkash": "", "nagad": "", "rocket": "", "min_deposit": "50", "min_withdraw": "100",
                "telegram_url": "", "welcome": WELCOME_DEFAULT, "commission_note": "", "referral_bonus": "50"}
    for k, v in defaults.items():
        c.execute("INSERT OR IGNORE INTO settings VALUES(?,?)", (k, v))
    c.execute("INSERT OR REPLACE INTO meta VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
    phone = os.environ.get("ADMIN_PHONE")
    pw = os.environ.get("ADMIN_PASSWORD")
    if phone and pw:  # env vars are the source of truth for the Super Admin credentials
        adm = c.execute("SELECT * FROM users WHERE role='super_admin' ORDER BY id LIMIT 1").fetchone()
        if not adm:
            c.execute("INSERT INTO users(name,phone,pw,is_admin,member_id,created,role) VALUES(?,?,?,?,?,?,?)",
                      ("Main Admin", phone, generate_password_hash(pw), 1, "ADMIN", now(), "super_admin"))
        else:
            clash = c.execute("SELECT 1 FROM users WHERE phone=? AND id<>?", (phone, adm["id"])).fetchone()
            if not clash and adm["phone"] != phone:
                c.execute("UPDATE users SET phone=? WHERE id=?", (phone, adm["id"]))
            if not check_password_hash(adm["pw"], pw):
                c.execute("UPDATE users SET pw=?, session_ver=session_ver+1 WHERE id=?",
                          (generate_password_hash(pw), adm["id"]))
    c.execute("COMMIT")
    try:  # DB-level duplicate-TrxID guard (skipped if legacy data already has duplicates)
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_dep_trx ON tx(norm_trx) WHERE kind='deposit' AND norm_trx<>''")
    except sqlite3.IntegrityError:
        pass
    c.close()


def setting(k, d=""):
    r = q1("SELECT v FROM settings WHERE k=?", (k,))
    return r["v"] if r else d


# ---------------------------------------------------------------- ledger
class LedgerError(Exception):
    pass


def post(user_id, kind, amount, idem, ref_type=None, ref_id=None, note="", actor="system"):
    """Atomic ledger entry + balance cache update. Caller must hold a transaction (BEGIN IMMEDIATE).
    Idempotent on `idem` (returns False for a duplicate); refuses negative balance."""
    amount = round(float(amount), 2)
    if q1("SELECT 1 FROM ledger WHERE idem=?", (idem,)):
        return False
    u = q1("SELECT balance FROM users WHERE id=?", (user_id,))
    if not u:
        raise LedgerError("user not found")
    if round(u["balance"] + amount, 2) < 0:
        raise LedgerError("insufficient balance")
    db().execute("INSERT INTO ledger(user_id,kind,amount,ref_type,ref_id,idem,note,actor,created) VALUES(?,?,?,?,?,?,?,?,?)",
                 (user_id, kind, amount, ref_type, ref_id, idem, note, actor, now()))
    extra = ", commission=commission+%s" % amount if kind in ("commission", "commission_reversal") else ""
    db().execute("UPDATE users SET balance=round(balance+?,2)%s WHERE id=?" % extra, (amount, user_id))
    return True


class atomic:
    def __enter__(self):
        db().execute("BEGIN IMMEDIATE")

    def __exit__(self, et, ev, tb):
        db().execute("ROLLBACK" if et else "COMMIT")
        return False


def notify(user_id, title, body=""):
    db().execute("INSERT INTO notifications(user_id,title,body,created) VALUES(?,?,?,?)",
                 (user_id, title, body, now()))


def audit(action, detail="", actor=None):
    u = actor or me()
    db().execute("INSERT INTO audit(actor,action,detail,created,actor_id,ip) VALUES(?,?,?,?,?,?)",
                 (u["member_id"] if u else "system", action, detail, now(), u["id"] if u else None,
                  client_ip() if request else None))


def reconcile():
    return qa("""SELECT u.id,u.member_id,u.balance, COALESCE(SUM(l.amount),0) AS ledger_sum
                 FROM users u LEFT JOIN ledger l ON l.user_id=u.id GROUP BY u.id
                 HAVING ABS(u.balance-COALESCE(SUM(l.amount),0))>0.005""")


# ---------------------------------------------------------------- auth / security
def me():
    if "uid" in session:
        if not hasattr(g, "_me"):
            g._me = q1("SELECT * FROM users WHERE id=?", (session["uid"],))
        u = g._me
        if u and u["session_ver"] == session.get("sv", 0) and not u["blocked"]:
            return u
    return None


def has_perm(p, u=None):
    u = u or me()
    if not u or not u["is_admin"]:
        return False
    r = u["role"]
    if r == "super_admin":
        return True
    if p in SUPER_ONLY:
        return False
    if r == "admin":
        return p in (u["perms"] or "").split(",")
    return p in ROLE_FIXED.get(r, ())


def csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.before_request
def _guard():
    if request.method == "POST":
        t = (request.form.get("_csrf") or request.headers.get("X-CSRF") or "").encode()
        if not t or not secrets.compare_digest(t, session.get("csrf", "").encode()):
            abort(400, "Invalid CSRF token. Reload the page.")


@app.after_request
def _headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "same-origin"
    r.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    if "uid" in session:
        r.headers["Cache-Control"] = "no-store"
    return r


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not me():
            session.clear()
            return redirect("/login")
        return f(*a, **k)
    return w


def customer_required(f):
    @wraps(f)
    def w(*a, **k):
        u = me()
        if not u:
            session.clear()
            return redirect("/login")
        if u["is_admin"]:
            return redirect("/admin")
        return f(*a, **k)
    return w


def staff_required(*perms):
    """Any staff role; if perms are given, at least one must be held (checked from the DB on every request)."""
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            u = me()
            if not u:
                session.clear()
                return redirect("/login")
            if not u["is_admin"] or (perms and not any(has_perm(p, u) for p in perms)):
                abort(403)
            return f(*a, **k)
        return w
    return deco


def too_many(phone, ip):
    since = (datetime.utcnow() - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
    n = q1("SELECT COUNT(*) c FROM login_history WHERE ok=0 AND created>? AND (phone=? OR ip=?)",
           (since, phone, ip))["c"]
    return n >= 8


_RL = {}


def rate_hit(key, limit, secs):
    """tiny in-memory limiter per process"""
    t = time.time()
    b = _RL.setdefault(key, [])
    b[:] = [x for x in b if t - x < secs]
    if len(b) >= limit:
        return True
    b.append(t)
    return False


def client_ip():
    return (request.remote_addr or "")[:64]


# ---------------------------------------------------------------- UI shell
@app.context_processor
def _ctx():
    u = me()
    unread = q1("SELECT COUNT(*) c FROM notifications WHERE is_read=0 AND user_id=?", (u["id"],))["c"] if u and not u["is_admin"] else 0
    return dict(csrf_token=csrf(), u=u, site=SITE, unread=unread, money=money, can=has_perm,
                role_name=ROLES.get(u["role"], "") if u else "", tg=setting("telegram_url"))


CSS = """
:root{--b:#1d4ed8;--g:#16a34a;--bg:#f2f5fb;--card:#fff;--tx:#0f172a;--mut:#64748b;--ln:#e2e8f0;--rd:#dc2626}
@media(prefers-color-scheme:dark){:root{--bg:#0b1220;--card:#111a2e;--tx:#e5eaf5;--mut:#94a3b8;--ln:#1f2b45}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font-family:'Hind Siliguri',system-ui,sans-serif;padding-bottom:84px}
a{color:inherit;text-decoration:none}
.top{background:linear-gradient(100deg,#1d4ed8,#16a34a);color:#fff;padding:14px 16px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:5}
.top b{font-size:17px}.bell{position:relative;font-size:20px}.dot{position:absolute;top:-6px;right:-8px;background:#ef4444;border-radius:99px;font-size:11px;padding:0 5px}
main{max-width:620px;margin:0 auto;padding:14px}
.card{background:var(--card);border-radius:18px;padding:16px;margin-bottom:14px;box-shadow:0 4px 14px #0f172a14;border:1px solid var(--ln)}
.hero{background:linear-gradient(125deg,#1e40af,#0f766e 60%,#16a34a);color:#fff;border:0}
.hero .bal{font-size:34px;font-weight:700;margin:4px 0 12px}.hero small{opacity:.85}
.row{display:flex;gap:10px;flex-wrap:wrap}.row>*{flex:1}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px}.g2 .card{margin:0}
.k{color:var(--mut);font-size:13px}.v{font-size:20px;font-weight:700}
.btn,button{background:var(--b);color:#fff;border:0;border-radius:12px;padding:11px 16px;font:inherit;cursor:pointer;display:inline-block;text-align:center}
.btn.g{background:var(--g)}.btn.r{background:var(--rd)}.btn.s{background:#475569}.btn.w{background:#ffffff26}.btn.sm{padding:6px 10px;font-size:13px}
button[disabled]{opacity:.6}
input,select,textarea{width:100%;padding:12px;border:1px solid var(--ln);border-radius:12px;background:var(--card);color:var(--tx);font:inherit;margin:4px 0 12px}
input[type=checkbox]{width:auto;margin:0 6px 0 0}
label{font-size:14px;color:var(--mut)}label.ck{display:block;margin:6px 0;color:var(--tx)}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:8px 6px;border-bottom:1px solid var(--ln);text-align:left}
.tw{overflow-x:auto}
.pill{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;background:var(--ln)}
.pill.approved,.pill.paid{background:#dcfce7;color:#166534}.pill.rejected{background:#fee2e2;color:#991b1b}
.pill.pending,.pill.review,.pill.processing{background:#fef9c3;color:#854d0e}
.msg{padding:11px 14px;border-radius:12px;margin-bottom:12px;background:#dbeafe;color:#1e3a8a;word-break:break-word}.msg.error{background:#fee2e2;color:#991b1b}
.nav{position:fixed;bottom:0;left:0;right:0;background:var(--card);border-top:1px solid var(--ln);display:flex;justify-content:space-around;padding:8px 0 10px;z-index:6}
.nav a{text-align:center;font-size:12px;color:var(--mut);flex:1}.nav a.on{color:var(--b);font-weight:700}.nav i{display:block;font-style:normal;font-size:20px}
.welcome{white-space:pre-line;line-height:1.8;font-size:15px;border-left:4px solid var(--g)}
.empty{text-align:center;color:var(--mut);padding:22px}
.foot{color:var(--mut);font-size:12px;text-align:center;padding:10px}
.adm{overflow-x:auto;white-space:nowrap;padding-bottom:4px;margin-bottom:6px}
.adm a.t{display:inline-block;padding:7px 12px;border-radius:99px;background:var(--card);border:1px solid var(--ln);margin:0 4px 8px 0;font-size:14px}
.adm a.t.on{background:var(--b);color:#fff}
.copybox{background:var(--bg);border:1px dashed var(--ln);border-radius:12px;padding:10px;word-break:break-all;font-size:14px;margin:6px 0 10px;user-select:all}
.code{font-size:26px;font-weight:700;letter-spacing:3px;text-align:center}
canvas{width:100%;height:170px}
"""

JS = """
document.addEventListener('submit',function(e){var f=e.target,c=f.dataset.confirm;
 if(c&&!confirm(c)){e.preventDefault();return}
 setTimeout(function(){f.querySelectorAll('button').forEach(function(b){b.disabled=true;b.dataset.t=b.textContent;b.textContent='...'})},20);});
function copyText(t,btn){var done=function(){if(btn){var o=btn.dataset.o||btn.textContent;btn.dataset.o=o;btn.textContent='✅ কপি হয়েছে';setTimeout(function(){btn.textContent=o},1800)}};
 if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(done,function(){fb()})}else{fb()}
 function fb(){var a=document.createElement('textarea');a.value=t;a.style.position='fixed';a.style.opacity='0';document.body.appendChild(a);a.select();
  try{document.execCommand('copy');done()}catch(x){prompt('কপি করুন:',t)}document.body.removeChild(a)}}
document.addEventListener('click',function(e){var b=e.target.closest('[data-copy]');if(b){e.preventDefault();copyText(b.dataset.copy,b);return}
 b=e.target.closest('[data-share]');if(b){e.preventDefault();var t=b.dataset.text,u=b.dataset.share;
  if(navigator.share){navigator.share({title:document.title,text:t,url:u}).catch(function(){})}else{copyText(t+' '+u,b)}}});
function bars(id,labels,series,colors){var c=document.getElementById(id);if(!c)return;var w=c.width=c.offsetWidth*2,h=c.height=340,x=c.getContext('2d');
 var mx=1;series.forEach(function(s){s.forEach(function(v){mx=Math.max(mx,v)})});var n=labels.length,gw=(w-40)/n;
 x.font='20px sans-serif';x.fillStyle='#94a3b8';
 for(var i=0;i<n;i++){series.forEach(function(s,j){var bh=(h-60)*s[i]/mx,bw=gw/(series.length+1);x.fillStyle=colors[j];x.fillRect(30+i*gw+j*bw,h-30-bh,bw-3,bh)});
  if(n<=16||i%2==0){x.fillStyle='#94a3b8';x.fillText(labels[i],30+i*gw,h-8)}}}
"""

BASE = """<!doctype html><html lang="bn"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{site}}</title>
<link href="https://fonts.googleapis.com/css2?family=Hind+Siliguri:wght@400;600;700&display=swap" rel="stylesheet">
<style>{{css|safe}}</style></head><body>
<div class="top"><b>{{site}}</b>
{% if u and not u['is_admin'] %}<span><a class="bell" href="/notifications">🔔{% if unread %}<span class="dot">{{unread}}</span>{% endif %}</a></span>
{% elif u %}<span style="font-size:13px">{{role_name}}</span>
{% else %}<span><a href="/login">সাইন ইন</a> · <a href="/signup">সাইন আপ</a></span>{% endif %}</div>
<main>{% for c,m in msgs %}<div class="msg {{c}}">{{m}}</div>{% endfor %}
{% if u and u['is_admin'] %}<div class="adm">{% for p,t in tabs %}<a class="t {{'on' if p==active}}" href="{{p}}">{{t}}</a>{% endfor %}</div>{% endif %}
{{body|safe}}
{% if foot %}<div class="foot">{{foot}}</div>{% endif %}</main>
{% if u and not u['is_admin'] %}<div class="nav">
<a class="{{'on' if active=='/'}}" href="/"><i>🏠</i>হোম</a><a class="{{'on' if active=='/history'}}" href="/history"><i>🧾</i>হিস্ট্রি</a>
<a class="{{'on' if active=='/referral'}}" href="/referral"><i>🎁</i>রেফারেল</a><a class="{{'on' if active=='/insight'}}" href="/insight"><i>📊</i>ইনসাইট</a>
<a class="{{'on' if active=='/account'}}" href="/account"><i>👤</i>অ্যাকাউন্ট</a></div>{% endif %}
<script>{{js|safe}}</script></body></html>"""

# (path, label, permission or None = any staff)
ADMIN_TABS = [("/admin", "ড্যাশবোর্ড", None), ("/admin/deposits", "ডিপোজিট", "deposits"),
              ("/admin/withdrawals", "উইথড্র", "withdrawals"), ("/admin/users", "ইউজার", "users_view"),
              ("/admin/referrals", "রেফারেল", "referrals"), ("/admin/commission", "কমিশন", "commissions"),
              ("/admin/staff", "স্টাফ", "staff"), ("/admin/tickets", "টিকিট", "tickets"),
              ("/admin/notices", "নোটিশ", "notices"), ("/admin/settings", "সেটিংস", "settings"),
              ("/admin/audit", "অডিট লগ", "audit"), ("/admin/profile", "প্রোফাইল", None)]


def page(tpl, active="", foot="", **ctx):
    from flask import get_flashed_messages
    body = render_template_string(tpl, **ctx)
    msgs = get_flashed_messages(with_categories=True)
    msgs = [(("error" if c == "error" else ""), m) for c, m in msgs]
    u = me()
    tabs = [(p, t) for p, t, perm in ADMIN_TABS if u and u["is_admin"] and (perm is None or has_perm(perm, u))]
    return render_template_string(BASE, body=body, css=CSS, js=JS, msgs=msgs, active=active, foot=foot, tabs=tabs)


def err(m):
    flash(m, "error")


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def _http_err(e):
    msg = {403: "এই কাজের অনুমতি আপনার নেই।", 404: "পেজ পাওয়া যায়নি।"}.get(e.code, e.description or "অবৈধ অনুরোধ।")
    return page('<div class="card empty"><h2>%d</h2><p>{{m}}</p><a class="btn" href="/">← ফিরে যান</a></div>' % e.code, m=msg), e.code


# ---------------------------------------------------------------- public / auth routes
DISCLAIMER = "এটি একটি স্বাধীন প্ল্যাটফর্ম; bKash, Nagad বা Rocket-এর অফিশিয়াল সার্ভিস নয়।"


@app.route("/about")
def about():
    return page("""<div class="card"><h2>শর্তাবলি ও তথ্য</h2>
<p>• এই প্ল্যাটফর্মে কোনো আয়ের নিশ্চয়তা দেওয়া হয় না।<br>• ডিপোজিট যাচাইয়ের পর ওয়ালেটে যুক্ত হয়।<br>
• উইথড্র রিকোয়েস্ট অনুমোদনের পর পরিশোধ হয়।<br>• কমিশন ম্যানুয়ালি কারণসহ প্রদান করা হয় এবং লেজারে সংরক্ষিত থাকে।<br>
• রেফারেল বোনাস অনুমোদনের পরই ওয়ালেটে যুক্ত হয়; ভুয়া/স্ব-রেফারেল বাতিল হবে।<br>
• প্রতিটি লেনদেন অডিটযোগ্য লেজারে রেকর্ড হয়।</p><p class="k">""" + DISCLAIMER + "</p></div>")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        ip = client_ip()
        if rate_hit("su:" + ip, 6, 3600):
            err("অনেক চেষ্টা হয়েছে, পরে আবার চেষ্টা করুন।"); return redirect("/signup")
        n = request.form.get("name", "").strip()[:60]
        p = request.form.get("phone", "").strip()
        pw = request.form.get("pw", "")
        code = re.sub(r"[^A-Z0-9]", "", request.form.get("ref", "").upper())[:12]
        back = "/signup" + ("?ref=" + code if code else "")
        if not n or not re.fullmatch(r"01\d{9}", p) or len(pw) < 6:
            err("নাম, সঠিক ১১ ডিজিটের মোবাইল নম্বর ও কমপক্ষে ৬ অক্ষরের পাসওয়ার্ড দিন।"); return redirect(back)
        try:
            with atomic():
                referrer = None
                if code:
                    referrer = q1("SELECT id,member_id,phone,blocked FROM users WHERE referral_code=? AND is_admin=0", (code,))
                    if not referrer or referrer["blocked"] or referrer["phone"] == p:
                        err("রেফারেল কোডটি সঠিক নয়। কোড ঠিক করুন বা ফাঁকা রেখে সাইন আপ করুন।"); return redirect(back)
                last = q1("SELECT COALESCE(MAX(CAST(member_id AS INTEGER)),1499) m FROM users WHERE member_id GLOB '[0-9]*'")["m"]
                cur = db().execute("INSERT INTO users(name,phone,pw,member_id,created,role,referral_code,referred_by,signup_ip) VALUES(?,?,?,?,?,?,?,?,?)",
                                   (n, p, generate_password_hash(pw), str(last + 1), now(), "user", gen_code(db()),
                                    referrer["id"] if referrer else None, ip))
                uid = cur.lastrowid
                if referrer:
                    bonus = parse_amount(setting("referral_bonus", "50")) or 50.0
                    db().execute("INSERT INTO referrals(referrer_id,referred_id,code,amount,status,created) VALUES(?,?,?,?,?,?)",
                                 (referrer["id"], uid, code, bonus, "pending", now()))
                    notify(referrer["id"], "নতুন রেফারেল", "আপনার কোডে #%d সাইন আপ করেছেন। ৳%s বোনাস অনুমোদনের অপেক্ষায়।" % (last + 1, money(bonus)))
                    db().execute("INSERT INTO audit(actor,action,detail,created,actor_id,ip) VALUES(?,?,?,?,?,?)",
                                 ("system", "referral_request", "referral for user#%d by user#%d" % (uid, referrer["id"]), now(), None, ip))
        except sqlite3.IntegrityError:
            err("এই নম্বর দিয়ে আগেই অ্যাকাউন্ট আছে।"); return redirect(back)
        flash("অ্যাকাউন্ট তৈরি হয়েছে। সাইন ইন করুন।"); return redirect("/login")
    ref = re.sub(r"[^A-Z0-9]", "", request.args.get("ref", "").upper())[:12]
    return page("""<div class="card"><h2>সাইন আপ</h2><form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>নাম</label><input name="name" required maxlength="60"><label>মোবাইল নম্বর</label><input name="phone" required inputmode="numeric" maxlength="11">
<label>পাসওয়ার্ড (কমপক্ষে ৬ অক্ষর)</label><input name="pw" type="password" required minlength="6">
<label>রেফারেল কোড (ঐচ্ছিক)</label><input name="ref" value="{{ref}}" maxlength="12" autocapitalize="characters" autocomplete="off">
<button style="width:100%">সাইন আপ</button></form><p class="k">আগেই অ্যাকাউন্ট আছে? <a href="/login"><b>সাইন ইন</b></a></p></div>""", ref=ref)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        p, ip = request.form.get("phone", "").strip()[:20], client_ip()
        if too_many(p, ip):
            err("অনেকবার ভুল হয়েছে। ১৫ মিনিট পরে চেষ্টা করুন।"); return redirect("/login")
        u = q1("SELECT * FROM users WHERE phone=?", (p,))
        ok = bool(u and not u["blocked"] and check_password_hash(u["pw"], request.form.get("pw", "")))
        db().execute("INSERT INTO login_history(user_id,phone,ip,ok,created) VALUES(?,?,?,?,?)",
                     (u["id"] if u else None, p, ip, int(ok), now()))
        if ok and u["is_admin"] and check_password_hash(u["pw"], "admin123"):
            err("ডিফল্ট অ্যাডমিন পাসওয়ার্ড নিষিদ্ধ। Render-এ ADMIN_PASSWORD সেট করে রিডেপ্লয় করুন।"); return redirect("/login")
        if ok:
            session.clear(); session.permanent = True
            session["uid"], session["sv"] = u["id"], u["session_ver"]
            db().execute("UPDATE users SET last_login=? WHERE id=?", (now(), u["id"]))
            if u["is_admin"]:
                audit("staff_login", "role=%s" % u["role"], actor=u)
            return redirect("/admin" if u["is_admin"] else "/")
        err("নম্বর/পাসওয়ার্ড ভুল অথবা অ্যাকাউন্ট ব্লকড/নিষ্ক্রিয়।"); return redirect("/login")
    return page("""<div class="card"><h2>সাইন ইন</h2><form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>মোবাইল নম্বর</label><input name="phone" required inputmode="numeric"><label>পাসওয়ার্ড</label><input name="pw" type="password" required>
<button style="width:100%">সাইন ইন</button></form>
<p><a href="/forgot"><b>পাসওয়ার্ড ভুলে গেছেন?</b></a> · <a href="/signup">নতুন অ্যাকাউন্ট</a></p></div>""")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear(); return redirect("/login")


@app.route("/forgot")
def forgot():
    return page("""<div class="card"><h2>পাসওয়ার্ড রিসেট</h2>
<p>ইমেইল সেটআপ নেই, তাই সাপোর্টের সহায়তায় রিসেট হয়:</p>
<p>১. {% if tg %}<a href="{{tg}}"><b>টেলিগ্রামে</b></a>{% else %}সাপোর্টে{% endif %} আপনার নাম, মোবাইল নম্বর ও মেম্বার আইডি জানান।<br>
২. স্টাফ একটি ৩০ মিনিটের এককালীন কোড দেবেন।<br>৩. নিচে কোডটি দিয়ে নতুন পাসওয়ার্ড সেট করুন।</p>
<form method="post" action="/reset"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>মোবাইল নম্বর</label><input name="phone" required><label>রিসেট কোড</label><input name="code" required>
<label>নতুন পাসওয়ার্ড</label><input name="pw" type="password" minlength="6" required><button style="width:100%">পাসওয়ার্ড বদলান</button></form></div>""")


@app.route("/reset", methods=["POST"])
def reset():
    if rate_hit("rs:" + client_ip(), 8, 900):
        err("অনেক চেষ্টা হয়েছে।"); return redirect("/forgot")
    p, code, pw = request.form.get("phone", "").strip(), request.form.get("code", "").strip().upper(), request.form.get("pw", "")
    u = q1("SELECT * FROM users WHERE phone=? AND is_admin=0", (p,))
    h = hashlib.sha256(code.encode()).hexdigest()
    if len(pw) < 6 or not u:
        err("তথ্য সঠিক নয়।"); return redirect("/forgot")
    with atomic():
        r = q1("SELECT * FROM resets WHERE user_id=? AND token_hash=? AND used=0 AND expires>?", (u["id"], h, now()))
        if not r:
            err("কোডটি ভুল, মেয়াদোত্তীর্ণ বা ব্যবহৃত।"); return redirect("/forgot")
        db().execute("UPDATE resets SET used=1 WHERE id=?", (r["id"],))
        db().execute("UPDATE users SET pw=?, session_ver=session_ver+1 WHERE id=?", (generate_password_hash(pw), u["id"]))
    flash("পাসওয়ার্ড বদলেছে। সাইন ইন করুন।"); return redirect("/login")


# ---------------------------------------------------------------- client area
def stats(uid):
    s = {}
    one = lambda sql, a=(): q1(sql, a)["s"]
    s["deposit"] = one("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE user_id=? AND kind='deposit' AND status='approved'", (uid,))
    s["withdraw"] = one("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE user_id=? AND kind='withdraw' AND status IN('approved','paid')", (uid,))
    s["pending"] = one("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE user_id=? AND kind='withdraw' AND status IN('pending','processing')", (uid,))
    s["today"] = one("SELECT COALESCE(SUM(amount),0) s FROM ledger WHERE user_id=? AND kind IN('commission','referral_bonus') AND date(created)=date('now')", (uid,))
    return s


@app.route("/")
@login_required
def home():
    u = me()
    if u["is_admin"]:
        return redirect("/admin")
    return page("""<div class="card hero"><small>উপলব্ধ ব্যালেন্স</small><div class="bal">৳ {{money(u['balance'])}}</div>
<div class="row"><a class="btn w" href="/deposit">➕ ডিপোজিট</a><a class="btn w" href="/withdraw">⬆ উইথড্র</a></div>
<div class="row" style="margin-top:10px"><a class="btn w" href="/referral">🎁 রেফারেল</a><a class="btn w" href="/support">💬 সাপোর্ট</a></div></div>
<div class="g2"><div class="card"><div class="k">পেন্ডিং উইথড্র</div><div class="v">৳ {{money(s.pending)}}</div></div>
<div class="card"><div class="k">মোট ডিপোজিট</div><div class="v">৳ {{money(s.deposit)}}</div></div>
<div class="card"><div class="k">মোট উইথড্র</div><div class="v">৳ {{money(s.withdraw)}}</div></div>
<div class="card"><div class="k">মোট কমিশন</div><div class="v">৳ {{money(u['commission'])}}</div></div>
<div class="card"><div class="k">আজকের আয়</div><div class="v">৳ {{money(s.today)}}</div></div>
<div class="card"><div class="k">মেম্বার আইডি</div><div class="v">#{{u['member_id']}}</div></div></div>
{% if notices %}{% for n in notices %}<div class="card"><b>📢 {{n['title']}}</b><div class="k">{{n['body']}}</div></div>{% endfor %}{% endif %}
<div class="card welcome">{{welcome}}</div>""", active="/", s=stats(u["id"]),
                notices=qa("SELECT * FROM notifications WHERE user_id IS NULL ORDER BY id DESC LIMIT 3"),
                welcome=setting("welcome", WELCOME_DEFAULT))


def save_shot(f):
    if not f or not f.filename:
        return None, None
    data = f.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        return None, "স্ক্রিনশট ২ MB-এর বেশি হতে পারবে না।"
    ext = ("jpg" if data[:3] == b"\xff\xd8\xff" else "png" if data[:4] == b"\x89PNG"
           else "webp" if data[:4] == b"RIFF" and data[8:12] == b"WEBP" else None)
    if not ext:
        return None, "শুধু JPG, PNG বা WEBP ছবি দিন।"
    name = secrets.token_hex(16) + "." + ext
    with open(os.path.join(UPLOAD_DIR, name), "wb") as fh:
        fh.write(data)
    return name, None


@app.route("/deposit", methods=["GET", "POST"])
@customer_required
def deposit():
    u = me()
    mn = float(setting("min_deposit", "50") or 50)
    if request.method == "POST":
        m, amt = request.form.get("method"), parse_amount(request.form.get("amount"))
        trx = request.form.get("trx", "").strip()[:40]
        nt = norm_trx(trx)
        if m not in METHODS or amt < mn or len(nt) < 6:
            err("মাধ্যম, সঠিক পরিমাণ (ন্যূনতম ৳%s) ও কমপক্ষে ৬ অক্ষরের TrxID দিন।" % int(mn)); return redirect("/deposit")
        if rate_hit("dp:%d" % u["id"], 10, 3600):
            err("অনেক রিকোয়েস্ট হয়েছে।"); return redirect("/deposit")
        shot, e = save_shot(request.files.get("shot"))
        if e:
            err(e); return redirect("/deposit")
        with atomic():
            if q1("SELECT 1 FROM tx WHERE kind='deposit' AND norm_trx=?", (nt,)):
                err("এই TrxID আগেই ব্যবহার করা হয়েছে।"); return redirect("/deposit")
            db().execute("INSERT INTO tx(user_id,kind,method,amount,trx,norm_trx,screenshot,status,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (u["id"], "deposit", m, amt, trx, nt, shot, "pending", now(), now()))
        flash("ডিপোজিট রিকোয়েস্ট জমা হয়েছে। যাচাই করা হবে।"); return redirect("/history")
    nums = {m: setting(m.lower()) for m in METHODS}
    return page("""<div class="card"><h2>ডিপোজিট</h2><p class="k">নিচের নম্বরে Send Money করে TrxID দিন।</p>
{% for m,n in nums.items() %}<div class="row" style="margin-bottom:6px"><b>{{m}}</b><span>{{n or 'সেট করা হয়নি'}}</span></div>{% endfor %}</div>
<div class="card"><form method="post" enctype="multipart/form-data" data-confirm="তথ্য ঠিক আছে? জমা দেবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>মাধ্যম</label><select name="method">{% for m in nums %}<option>{{m}}</option>{% endfor %}</select>
<label>পরিমাণ (ন্যূনতম ৳{{mn|int}})</label><input name="amount" type="number" step="0.01" min="{{mn}}" required>
<label>Transaction ID</label><input name="trx" required autocomplete="off">
<label>পেমেন্ট স্ক্রিনশট (ঐচ্ছিক, JPG/PNG/WEBP, ≤২MB)</label><input type="file" name="shot" accept="image/*">
<button style="width:100%">জমা দিন</button></form></div>""", active="/deposit", nums=nums, mn=mn)


@app.route("/withdraw", methods=["GET", "POST"])
@customer_required
def withdraw():
    u = me()
    mn = float(setting("min_withdraw", "100") or 100)
    if request.method == "POST":
        m, amt = request.form.get("method"), parse_amount(request.form.get("amount"))
        num = request.form.get("number", "").strip()
        if m not in METHODS or amt < mn or not re.fullmatch(r"01\d{9}", num):
            err("মাধ্যম, ন্যূনতম ৳%s বা বেশি পরিমাণ ও সঠিক নম্বর দিন।" % int(mn)); return redirect("/withdraw")
        if rate_hit("wd:%d" % u["id"], 6, 3600):
            err("অনেক রিকোয়েস্ট হয়েছে।"); return redirect("/withdraw")
        try:
            with atomic():
                cur = db().execute("INSERT INTO tx(user_id,kind,method,amount,number,status,created,updated) VALUES(?,?,?,?,?,?,?,?)",
                                   (u["id"], "withdraw", m, amt, num, "pending", now(), now()))
                tid = cur.lastrowid
                post(u["id"], "withdraw_hold", -amt, "wd:%d:hold" % tid, "tx", tid, "Withdrawal reserved", u["member_id"])
        except LedgerError:
            err("ব্যালেন্স অপর্যাপ্ত।"); return redirect("/withdraw")
        flash("উইথড্র রিকোয়েস্ট জমা হয়েছে, টাকা রিজার্ভ করা হয়েছে।"); return redirect("/history")
    return page("""<div class="card"><h2>উইথড্র</h2><p class="k">উপলব্ধ: ৳ {{money(u['balance'])}} · ন্যূনতম ৳{{mn|int}}</p>
<form method="post" data-confirm="উইথড্র রিকোয়েস্ট জমা দেবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>মাধ্যম</label><select name="method"><option>bKash</option><option>Nagad</option><option>Rocket</option></select>
<label>পরিমাণ</label><input name="amount" type="number" step="0.01" required><label>আপনার নম্বর</label><input name="number" inputmode="numeric" maxlength="11" required>
<button style="width:100%">রিকোয়েস্ট করুন</button></form></div>""", active="/withdraw", mn=mn)


@app.route("/history")
@customer_required
def history():
    u = me()
    txs = qa("SELECT * FROM tx WHERE user_id=? ORDER BY id DESC LIMIT 100", (u["id"],))
    led = qa("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 100", (u["id"],))
    return page("""<div class="card"><h2>রিকোয়েস্ট</h2>{% if not txs %}<div class="empty">কোনো লেনদেন নেই</div>{% else %}<div class="tw"><table>
<tr><th>ধরন</th><th>মাধ্যম</th><th>৳</th><th>অবস্থা</th><th>সময়</th></tr>{% for t in txs %}<tr><td>{{t['kind']}}</td><td>{{t['method']}}</td>
<td>{{money(t['amount'])}}</td><td><span class="pill {{t['status']}}">{{t['status']}}</span></td><td>{{(t['created'] or '')[:16]}}</td></tr>{% endfor %}</table></div>{% endif %}</div>
<div class="card"><h2>ওয়ালেট লেজার</h2><div class="tw"><table><tr><th>ধরন</th><th>৳</th><th>নোট</th><th>সময়</th></tr>
{% for l in led %}<tr><td>{{l['kind']}}</td><td style="color:{{'#16a34a' if l['amount']>=0 else '#dc2626'}}">{{money(l['amount'])}}</td><td>{{l['note'] or ''}}</td><td>{{l['created'][:16]}}</td></tr>{% endfor %}</table></div></div>""",
                active="/history", txs=txs, led=led)


@app.route("/shot/<name>")
@login_required
def shot(name):
    if not re.fullmatch(r"[0-9a-f]{32}\.(jpg|png|webp)", name):
        abort(404)
    u = me()
    t = q1("SELECT user_id FROM tx WHERE screenshot=?", (name,))
    if not t or (u["id"] != t["user_id"] and not (has_perm("deposits", u) or has_perm("withdrawals", u))):
        abort(404)
    return send_file(os.path.join(UPLOAD_DIR, name))


@app.route("/notifications")
@customer_required
def notifications():
    u = me()
    rows = qa("SELECT * FROM notifications WHERE user_id=? OR user_id IS NULL ORDER BY id DESC LIMIT 50", (u["id"],))
    db().execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (u["id"],))
    return page("""<h2>নোটিফিকেশন</h2>{% if not rows %}<div class="card empty">কোনো নোটিফিকেশন নেই</div>{% endif %}
{% for n in rows %}<div class="card"><b>{{n['title']}}</b><div>{{n['body']}}</div><div class="k">{{n['created'][:16]}}</div></div>{% endfor %}""", rows=rows)


@app.route("/insight")
@customer_required
def insight():
    return page("""<div class="card"><h2>ইনসাইট</h2><div class="row"><a class="btn sm s" href="#" onclick="load(7);return false">৭ দিন</a>
<a class="btn sm s" href="#" onclick="load(30);return false">৩০ দিন</a><a class="btn sm s" href="#" onclick="load(90);return false">৯০ দিন</a></div>
<p class="k">🟦 ডিপোজিট &nbsp; 🟥 উইথড্র &nbsp; 🟩 কমিশন ও রেফারেল</p><canvas id="ch"></canvas><div id="sum" class="k"></div></div>
<script>function load(d){fetch('/insight/data?days='+d).then(r=>r.json()).then(j=>{bars('ch',j.labels,[j.deposit,j.withdraw,j.commission],['#3b82f6','#ef4444','#22c55e']);
document.getElementById('sum').textContent='মোট ডিপোজিট ৳'+j.t[0]+' · উইথড্র ৳'+j.t[1]+' · আয় ৳'+j.t[2]})}load(7)</script>""", active="/insight")


def series(uid, days):
    labels, dep, wd, com = [], [], [], []
    for i in range(days - 1, -1, -1):
        d = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        labels.append(d[5:])
        f = lambda sql: round(q1(sql, (uid, d) if uid else (d,))["s"], 2)
        w = "user_id=? AND " if uid else ""
        dep.append(f("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE %skind='deposit' AND status='approved' AND date(updated)=?" % w))
        wd.append(f("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE %skind='withdraw' AND status IN('approved','paid') AND date(updated)=?" % w))
        com.append(f("SELECT COALESCE(SUM(amount),0) s FROM ledger WHERE %skind IN('commission','referral_bonus') AND date(created)=?" % w))
    return dict(labels=labels, deposit=dep, withdraw=wd, commission=com, t=[round(sum(x), 2) for x in (dep, wd, com)])


@app.route("/insight/data")
@login_required
def insight_data():
    u = me()
    if u["is_admin"] and not has_perm("dashboard_fin", u):
        abort(403)
    try:
        d = min(max(int(request.args.get("days", 7) or 7), 1), 90)
    except ValueError:
        d = 7
    return jsonify(series(None if u["is_admin"] else u["id"], d))


def ref_link(code):
    base = (os.environ.get("BASE_URL") or request.url_root).rstrip("/")
    return "%s/signup?ref=%s" % (base, code)


@app.route("/referral")
@customer_required
def referral():
    u = me()
    if not u["referral_code"]:  # safety net; normally assigned at signup/migration
        with atomic():
            db().execute("UPDATE users SET referral_code=? WHERE id=? AND referral_code IS NULL", (gen_code(db()), u["id"]))
        g.pop("_me", None)
        u = me()
    st = q1("""SELECT COUNT(*) total, COALESCE(SUM(status='pending'),0) pend, COALESCE(SUM(status='approved'),0) appr,
               COALESCE(SUM(status='rejected'),0) rej, COALESCE(SUM(CASE WHEN status='approved' THEN amount END),0) earned,
               COALESCE(SUM(CASE WHEN status='pending' THEN amount END),0) pend_amt FROM referrals WHERE referrer_id=?""", (u["id"],))
    rows = qa("""SELECT r.*, x.name x_name, x.member_id x_mid FROM referrals r JOIN users x ON x.id=r.referred_id
                 WHERE r.referrer_id=? ORDER BY r.id DESC LIMIT 100""", (u["id"],))
    by = q1("SELECT member_id,name FROM users WHERE id=?", (u["referred_by"],)) if u["referred_by"] else None
    link = ref_link(u["referral_code"])
    bonus = parse_amount(setting("referral_bonus", "50")) or 50.0
    text = "%s-এ যোগ দিন! আমার রেফারেল কোড: %s" % (SITE, u["referral_code"])
    return page("""<div class="card hero"><small>আপনার রেফারেল কোড</small><div class="code">{{u['referral_code']}}</div>
<div class="copybox" style="color:var(--tx)">{{link}}</div>
<div class="row"><button class="btn w" data-copy="{{link}}">📋 লিংক কপি</button><button class="btn w" data-share="{{link}}" data-text="{{text}}">📤 শেয়ার</button></div>
<div class="row" style="margin-top:10px"><button class="btn w" data-copy="{{u['referral_code']}}">কোড কপি</button>
<a class="btn w" target="_blank" rel="noopener" href="https://wa.me/?text={{(text+' '+link)|urlencode}}">WhatsApp</a></div></div>
<div class="card"><b>🎁 প্রতি সফল রেফারে ৳{{money(bonus)}}</b><div class="k">বন্ধু আপনার কোডে সাইন আপ করলে বোনাস রিকোয়েস্ট তৈরি হয়। অনুমোদনের পর টাকা ওয়ালেটে যুক্ত হয়। ডিপোজিট লাগে না।</div>
{% if by %}<div class="k" style="margin-top:6px">আপনাকে রেফার করেছেন: #{{by['member_id']}} {{by['name']}}</div>{% endif %}</div>
<div class="g2"><div class="card"><div class="k">মোট রেফার</div><div class="v">{{st['total']}}</div></div>
<div class="card"><div class="k">অনুমোদিত</div><div class="v">{{st['appr']}}</div></div>
<div class="card"><div class="k">অপেক্ষমাণ</div><div class="v">{{st['pend']}} <span class="k">(৳{{money(st['pend_amt'])}})</span></div></div>
<div class="card"><div class="k">মোট বোনাস আয়</div><div class="v">৳ {{money(st['earned'])}}</div></div></div>
<div class="card"><h3>রেফারেল ইতিহাস</h3>{% if not rows %}<div class="empty">এখনো কেউ আপনার কোডে যোগ দেয়নি</div>{% else %}<div class="tw"><table>
<tr><th>সদস্য</th><th>৳</th><th>অবস্থা</th><th>তারিখ</th></tr>{% for r in rows %}<tr><td>#{{r['x_mid']}} {{r['x_name']}}</td><td>{{money(r['amount'])}}</td>
<td><span class="pill {{r['status']}}">{{ {'pending':'অপেক্ষমাণ','approved':'অনুমোদিত','rejected':'বাতিল'}[r['status']] }}</span></td><td>{{r['created'][:10]}}</td></tr>{% endfor %}</table></div>{% endif %}</div>""",
                active="/referral", st=st, rows=rows, by=by, link=link, text=text, bonus=bonus)


@app.route("/support", methods=["GET", "POST"])
@customer_required
def support():
    u = me()
    if request.method == "POST":
        s, m = request.form.get("subject", "").strip()[:100], request.form.get("message", "").strip()[:1000]
        if not s or not m:
            err("বিষয় ও বার্তা দিন।"); return redirect("/support")
        db().execute("INSERT INTO tickets(user_id,subject,message,created) VALUES(?,?,?,?)", (u["id"], s, m, now()))
        flash("টিকিট জমা হয়েছে।"); return redirect("/support")
    rows = qa("SELECT * FROM tickets WHERE user_id=? ORDER BY id DESC LIMIT 30", (u["id"],))
    return page("""<div class="card"><h2>সাপোর্ট</h2>{% if tg %}<a class="btn g" href="{{tg}}" target="_blank" rel="noopener" style="width:100%;margin-bottom:12px">✈ টেলিগ্রামে যোগাযোগ</a>{% endif %}
<form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}"><label>বিষয়</label><input name="subject" required maxlength="100">
<label>বার্তা</label><textarea name="message" rows="3" required maxlength="1000"></textarea><button style="width:100%">টিকিট জমা দিন</button></form></div>
{% for t in rows %}<div class="card"><b>{{t['subject']}}</b> <span class="pill {{'approved' if t['status']=='closed' else 'pending'}}">{{t['status']}}</span>
<div>{{t['message']}}</div>{% if t['reply'] %}<div class="k" style="margin-top:8px">↳ সাপোর্ট: {{t['reply']}}</div>{% endif %}</div>{% endfor %}""", active="/account", rows=rows)


@app.route("/account", methods=["GET", "POST"])
@customer_required
def account():
    u = me()
    if request.method == "POST":
        if not check_password_hash(u["pw"], request.form.get("old", "")) or len(request.form.get("new", "")) < 6:
            err("পুরনো পাসওয়ার্ড ভুল অথবা নতুন পাসওয়ার্ড ৬ অক্ষরের কম।"); return redirect("/account")
        db().execute("UPDATE users SET pw=?, session_ver=session_ver+1 WHERE id=?", (generate_password_hash(request.form["new"]), u["id"]))
        session.clear(); flash("পাসওয়ার্ড বদলেছে। আবার সাইন ইন করুন।"); return redirect("/login")
    hist = qa("SELECT * FROM login_history WHERE user_id=? ORDER BY id DESC LIMIT 8", (u["id"],))
    return page("""<div class="card"><h2>{{u['name']}}</h2><p>📱 {{u['phone']}}<br>🆔 #{{u['member_id']}}</p>
<a class="btn g" href="/support" style="width:100%">💬 সাপোর্ট</a></div>
<div class="card"><h3>পাসওয়ার্ড বদলান</h3><form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>পুরনো পাসওয়ার্ড</label><input name="old" type="password" required><label>নতুন পাসওয়ার্ড</label><input name="new" type="password" minlength="6" required>
<button style="width:100%">বদলান</button></form></div>
<div class="card"><h3>সাম্প্রতিক লগইন</h3><div class="tw"><table>{% for h in hist %}<tr><td>{{h['created'][:16]}}</td><td>{{h['ip']}}</td><td>{{'✅' if h['ok'] else '❌'}}</td></tr>{% endfor %}</table></div></div>
<div class="card"><a href="/about">শর্তাবলি</a><form method="post" action="/logout" style="margin-top:10px"><input type="hidden" name="_csrf" value="{{csrf_token}}"><button class="r" style="width:100%">লগআউট</button></form></div>""",
                active="/account", hist=hist)


# ---------------------------------------------------------------- admin: shared pieces
REF_SQL = """SELECT r.*, rf.member_id rf_mid, rf.name rf_name, rf.phone rf_phone, x.member_id x_mid, x.name x_name, x.phone x_phone,
 (COALESCE(x.signup_ip,'')<>'' AND (x.signup_ip=rf.signup_ip OR EXISTS(SELECT 1 FROM login_history h WHERE h.user_id=rf.id AND h.ip=x.signup_ip))) same_ip
 FROM referrals r JOIN users rf ON rf.id=r.referrer_id JOIN users x ON x.id=r.referred_id"""

REF_LIST = """{% if not rows %}<div class="card empty">কোনো রেফারেল রিকোয়েস্ট নেই</div>{% endif %}
{% for r in rows %}<div class="card"><div class="row" style="align-items:center"><b>৳ {{money(r['amount'])}}</b><span class="pill {{r['status']}}" style="flex:0">{{r['status']}}</span></div>
<div class="k">রেফারার: <b>#{{r['rf_mid']}} {{r['rf_name']}}</b> · {{r['rf_phone']}}</div>
<div class="k">নতুন ইউজার: <b>#{{r['x_mid']}} {{r['x_name']}}</b> · {{r['x_phone']}} · {{r['created'][:16]}}</div>
{% if r['same_ip'] and r['status']=='pending' %}<div class="msg error" style="margin:6px 0">⚠ একই আইপি থেকে সাইন আপ/লগইন — যাচাই করুন</div>{% endif %}
{% if r['status']!='pending' %}<div class="k">সিদ্ধান্ত: {{r['decided_by']}} · {{(r['decided_at'] or '')[:16]}}{% if r['note'] %} · {{r['note']}}{% endif %}</div>
{% elif can('referrals') %}<form method="post" action="/admin/referrals/{{r['id']}}" style="margin-top:8px" data-confirm="নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<input name="note" placeholder="নোট (ঐচ্ছিক)" maxlength="200"><div class="row"><button name="act" value="approve" class="btn sm g">✅ অনুমোদন</button><button name="act" value="reject" class="btn sm r">❌ বাতিল</button></div></form>{% endif %}</div>{% endfor %}"""


def back(default="/admin"):
    ref = request.referrer or ""
    return redirect(ref if ref.startswith(request.host_url) else default)


# ---------------------------------------------------------------- admin: dashboard
@app.route("/admin")
@staff_required()
def admin_home():
    u = me()
    one = lambda sql: q1(sql)["s"]
    fin = has_perm("dashboard_fin", u)
    s = dict(open_tickets=one("SELECT COUNT(*) s FROM tickets WHERE status='open'"),
             total=one("SELECT COUNT(*) s FROM users WHERE is_admin=0"),
             active=one("SELECT COUNT(*) s FROM users WHERE is_admin=0 AND blocked=0"),
             blocked=one("SELECT COUNT(*) s FROM users WHERE is_admin=0 AND blocked=1"))
    bad, pend = [], []
    if fin:
        s.update(
            liability=one("SELECT COALESCE(SUM(balance),0) s FROM users WHERE is_admin=0"),
            pend_dep=one("SELECT COUNT(*) s FROM tx WHERE kind='deposit' AND status IN('pending','review')"),
            pend_wd=one("SELECT COUNT(*) s FROM tx WHERE kind='withdraw' AND status IN('pending','processing','approved')"),
            dep_vol=one("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE kind='deposit' AND status='approved'"),
            wd_vol=one("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE kind='withdraw' AND status IN('approved','paid')"),
            comm=one("SELECT COALESCE(SUM(amount),0) s FROM ledger WHERE kind='commission'"),
            ref_paid=one("SELECT COALESCE(SUM(amount),0) s FROM ledger WHERE kind='referral_bonus'"),
            ref_pend_n=one("SELECT COUNT(*) s FROM referrals WHERE status='pending'"),
            ref_pend_amt=one("SELECT COALESCE(SUM(amount),0) s FROM referrals WHERE status='pending'"),
            today_dep=one("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE kind='deposit' AND status='approved' AND date(updated)=date('now')"))
        bad = reconcile()
    if has_perm("referrals", u):
        pend = qa(REF_SQL + " WHERE r.status='pending' ORDER BY r.id LIMIT 5")
    return page("""{% if fin %}<div class="g2"><div class="card"><div class="k">মোট ইউজার</div><div class="v">{{s.total}}</div></div>
<div class="card"><div class="k">সক্রিয় / ব্লকড</div><div class="v">{{s.active}} / {{s.blocked}}</div></div>
<div class="card"><div class="k">মোট ওয়ালেট দায়</div><div class="v">৳ {{money(s.liability)}}</div></div>
<div class="card"><div class="k">আজকের ডিপোজিট</div><div class="v">৳ {{money(s.today_dep)}}</div></div>
<div class="card"><div class="k">পেন্ডিং ডিপোজিট</div><div class="v">{{s.pend_dep}}</div></div>
<div class="card"><div class="k">পেন্ডিং উইথড্র</div><div class="v">{{s.pend_wd}}</div></div>
<div class="card"><div class="k">ডিপোজিট ভলিউম</div><div class="v">৳ {{money(s.dep_vol)}}</div></div>
<div class="card"><div class="k">উইথড্র ভলিউম</div><div class="v">৳ {{money(s.wd_vol)}}</div></div>
<div class="card"><div class="k">দেওয়া কমিশন</div><div class="v">৳ {{money(s.comm)}}</div></div>
<div class="card"><div class="k">রেফারেল বোনাস (প্রদত্ত)</div><div class="v">৳ {{money(s.ref_paid)}}</div></div>
<div class="card"><div class="k">পেন্ডিং রেফারেল</div><div class="v">{{s.ref_pend_n}} <span class="k">(৳{{money(s.ref_pend_amt)}})</span></div></div>
<div class="card"><div class="k">খোলা টিকিট</div><div class="v">{{s.open_tickets}}</div></div></div>
{% else %}<div class="g2"><div class="card"><div class="k">খোলা টিকিট</div><div class="v">{{s.open_tickets}}</div></div>
<div class="card"><div class="k">মোট ইউজার</div><div class="v">{{s.total}}</div></div></div>{% endif %}
{% if can('referrals') %}<h3>⏳ পেন্ডিং রেফারেল রিকোয়েস্ট</h3>""" + REF_LIST + """{% if rows %}<a class="btn s" style="width:100%;margin-bottom:14px" href="/admin/referrals">সব রেফারেল দেখুন</a>{% endif %}{% endif %}
{% if fin %}<div class="card"><b>লেজার রিকনসিলিয়েশন:</b>
{% if bad %}<span class="pill rejected">{{bad|length}}টি অমিল</span>{% for b in bad %}<div class="k">#{{b['member_id']}}: ব্যালেন্স {{b['balance']}} ≠ লেজার {{b['ledger_sum']}}</div>{% endfor %}
{% else %}<span class="pill approved">সব মিলেছে ✅</span>{% endif %}</div>
<div class="card"><h3>গত ১৪ দিন</h3><canvas id="ch"></canvas></div>
<script>fetch('/insight/data?days=14').then(r=>r.json()).then(j=>bars('ch',j.labels,[j.deposit,j.withdraw,j.commission],['#3b82f6','#ef4444','#22c55e']))</script>{% endif %}""",
                active="/admin", s=s, bad=bad, rows=pend, fin=fin)


# ---------------------------------------------------------------- admin: deposits / withdrawals
ACTIONS = {
    "deposit": [(("pending",), ("review", "যাচাইয়ে নিন"), "s"), (("pending", "review"), ("approve", "অ্যাপ্রুভ"), "g"),
                (("pending", "review"), ("reject", "রিজেক্ট"), "r")],
    "withdraw": [(("pending",), ("processing", "প্রসেসিং"), "s"), (("pending", "processing"), ("approve", "অ্যাপ্রুভ"), "g"),
                 (("approved", "processing"), ("paid", "পরিশোধ হয়েছে"), "g"),
                 (("pending", "processing", "approved"), ("reject", "রিজেক্ট"), "r")],
}
KIND_PERM = {"deposit": "deposits", "withdraw": "withdrawals"}


def _list_tx(kind, statuses, active, title):
    st = request.args.get("status", "open")
    where = "t.kind=? " + ("AND t.status IN (%s)" % ",".join("?" * len(statuses)) if st == "open" else "")
    args = [kind] + (list(statuses) if st == "open" else [])
    rows = qa("SELECT t.*,u.name,u.phone,u.member_id FROM tx t JOIN users u ON u.id=t.user_id WHERE %s ORDER BY t.id DESC LIMIT 100" % where, args)
    return page("""<h2>{{title}}</h2><div class="row" style="margin-bottom:10px"><a class="btn sm s" href="?status=open">খোলা</a><a class="btn sm s" href="?status=all">সব</a></div>
{% if not rows %}<div class="card empty">কিছু নেই</div>{% endif %}
{% for t in rows %}<div class="card"><b>৳ {{money(t['amount'])}}</b> · {{t['method']}} <span class="pill {{t['status']}}">{{t['status']}}</span>
<div class="k">#{{t['member_id']}} {{t['name']}} · {{t['phone']}} · {{t['created'][:16]}}</div>
<div>{{'TrxID' if t['kind']=='deposit' else 'নম্বর'}}: <b>{{t['trx'] or t['number']}}</b></div>
{% if t['screenshot'] %}<a href="/shot/{{t['screenshot']}}" target="_blank"><b>🖼 স্ক্রিনশট</b></a>{% endif %}
{% if t['note'] %}<div class="k">নোট: {{t['note']}}</div>{% endif %}
{% if t['status'] in statuses %}<form method="post" action="/admin/tx/{{t['id']}}" style="margin-top:8px" data-confirm="নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<input name="note" placeholder="নোট (ঐচ্ছিক)" maxlength="200"><div class="row">
{% for a,l,c in acts[t['kind']] %}{% if t['status'] in a %}<button name="act" value="{{l[0]}}" class="btn sm {{c}}">{{l[1]}}</button>{% endif %}{% endfor %}</div></form>{% endif %}</div>{% endfor %}""",
                active=active, rows=rows, title=title, statuses=statuses, acts=ACTIONS)


@app.route("/admin/deposits")
@staff_required("deposits")
def admin_deposits():
    return _list_tx("deposit", ("pending", "review"), "/admin/deposits", "ডিপোজিট রিকোয়েস্ট")


@app.route("/admin/withdrawals")
@staff_required("withdrawals")
def admin_withdrawals():
    return _list_tx("withdraw", ("pending", "processing", "approved"), "/admin/withdrawals", "উইথড্র রিকোয়েস্ট")


@app.route("/admin/tx/<int:i>", methods=["POST"])
@staff_required("deposits", "withdrawals")
def admin_tx(i):
    act, note = request.form.get("act"), request.form.get("note", "").strip()[:200]
    a = me()
    with atomic():
        t = q1("SELECT * FROM tx WHERE id=?", (i,))
        if not t or t["kind"] not in KIND_PERM:
            abort(404)
        if not has_perm(KIND_PERM[t["kind"]], a):  # permission is checked per transaction type
            abort(403)
        dep = t["kind"] == "deposit"
        allowed = {r[1][0] for r in ACTIONS[t["kind"]] if t["status"] in r[0]}
        if act not in allowed:  # blocks duplicate approval / invalid transitions
            err("এই রিকোয়েস্টে এখন এই কাজ সম্ভব নয় (হয়তো আগেই সম্পন্ন)।"); return back()
        new = {"review": "review", "approve": "approved", "reject": "rejected", "processing": "processing", "paid": "paid"}[act]
        if dep and act == "approve":
            post(t["user_id"], "deposit", t["amount"], "dep:%d" % i, "tx", i, "Deposit approved", a["member_id"])
            notify(t["user_id"], "ডিপোজিট অ্যাপ্রুভ", "৳%s আপনার ওয়ালেটে যুক্ত হয়েছে।" % money(t["amount"]))
        elif dep and act == "reject":
            notify(t["user_id"], "ডিপোজিট রিজেক্ট", "আপনার ৳%s ডিপোজিট রিকোয়েস্ট গৃহীত হয়নি।%s" % (money(t["amount"]), (" কারণ: " + note) if note else ""))
        elif not dep and act == "reject":
            post(t["user_id"], "withdraw_release", t["amount"], "wd:%d:release" % i, "tx", i, "Withdrawal rejected - funds released", a["member_id"])
            notify(t["user_id"], "উইথড্র রিজেক্ট", "৳%s ফেরত দেওয়া হয়েছে।%s" % (money(t["amount"]), (" কারণ: " + note) if note else ""))
        elif not dep:
            notify(t["user_id"], "উইথড্র আপডেট", "আপনার ৳%s উইথড্র এখন: %s" % (money(t["amount"]), new))
        db().execute("UPDATE tx SET status=?, note=COALESCE(NULLIF(?,''),note), updated=? WHERE id=?", (new, note, now(), i))
        audit("tx_" + act, "tx#%d %s ৳%s" % (i, t["kind"], t["amount"]))
    flash("সম্পন্ন: %s" % new)
    return back()


# ---------------------------------------------------------------- admin: users
@app.route("/admin/users")
@staff_required("users_view")
def admin_users():
    s = request.args.get("q", "").strip().lstrip("#")[:40]
    like = "%" + s + "%"
    rows = qa("SELECT * FROM users WHERE is_admin=0 AND (?='' OR name LIKE ? OR phone LIKE ? OR member_id LIKE ?) ORDER BY id DESC LIMIT 100",
              (s, like, like, like))
    return page("""<div class="card"><form><input name="q" value="{{s}}" placeholder="নাম / ফোন / মেম্বার আইডি"><button style="width:100%">খুঁজুন</button></form></div>
{% if not rows %}<div class="card empty">কোনো ইউজার নেই</div>{% endif %}
{% for x in rows %}<a href="/admin/users/{{x['id']}}"><div class="card"><b>#{{x['member_id']}} {{x['name']}}</b> {% if x['blocked'] %}<span class="pill rejected">blocked</span>{% endif %}
<div class="k">{{x['phone']}} · ৳ {{money(x['balance'])}}</div></div></a>{% endfor %}""", active="/admin/users", rows=rows, s=s)


@app.route("/admin/users/<int:i>")
@staff_required("users_view")
def admin_user(i):
    x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (i,))
    if not x:
        abort(404)
    full = has_perm("dashboard_fin") or has_perm("users_manage")
    led = qa("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 100", (i,)) if full else []
    logs = qa("SELECT * FROM login_history WHERE user_id=? ORDER BY id DESC LIMIT 10", (i,)) if has_perm("users_manage") else []
    txs = qa("SELECT * FROM tx WHERE user_id=? ORDER BY id DESC LIMIT 30", (i,))
    refs = q1("SELECT COUNT(*) n, COALESCE(SUM(status='approved'),0) a FROM referrals WHERE referrer_id=?", (i,))
    by = q1("SELECT member_id,name FROM users WHERE id=?", (x["referred_by"],)) if x["referred_by"] else None
    return page("""<div class="card"><h2>#{{x['member_id']}} {{x['name']}}</h2><p>📱 {{x['phone']}} · ব্যালেন্স <b>৳ {{money(x['balance'])}}</b> · কমিশন ৳ {{money(x['commission'])}}<br>
<span class="k">সর্বশেষ লগইন: {{x['last_login'] or '-'}} · রেফারেল কোড: {{x['referral_code']}} · রেফার করেছেন: {{refs['n']}} (অনুমোদিত {{refs['a']}}){% if by %} · রেফারার: #{{by['member_id']}} {{by['name']}}{% endif %}</span></p>
{% if can('users_manage') %}<div class="row"><form method="post" action="/admin/users/{{x['id']}}/block" data-confirm="নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<button class="btn {{'g' if x['blocked'] else 'r'}}">{{'আনব্লক' if x['blocked'] else 'ব্লক'}}</button></form>
<form method="post" action="/admin/users/{{x['id']}}/resetcode" data-confirm="নতুন রিসেট কোড তৈরি করবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}"><button class="btn s">পাসওয়ার্ড রিসেট কোড</button></form></div>{% endif %}</div>
{% if can('adjust') %}<div class="card"><h3>ব্যালেন্স সমন্বয় (কারণ আবশ্যক)</h3><form method="post" action="/admin/users/{{x['id']}}/adjust" data-confirm="লেজারে স্থায়ীভাবে রেকর্ড হবে। নিশ্চিত?">
<input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="idem" value="{{idem}}">
<label>পরিমাণ (যোগ: 100, বিয়োগ: -100)</label><input name="amount" type="number" step="0.01" required><label>কারণ</label><input name="reason" required maxlength="200"><button style="width:100%">সমন্বয় করুন</button></form></div>{% endif %}
{% if led %}<div class="card"><h3>ওয়ালেট লেজার</h3><div class="tw"><table><tr><th>ধরন</th><th>৳</th><th>নোট</th><th>কে</th><th>সময়</th></tr>
{% for l in led %}<tr><td>{{l['kind']}}</td><td>{{money(l['amount'])}}</td><td>{{l['note'] or ''}}</td><td>{{l['actor']}}</td><td>{{l['created'][:16]}}</td></tr>{% endfor %}</table></div></div>{% endif %}
<div class="card"><h3>লেনদেন</h3><div class="tw"><table>{% for t in txs %}<tr><td>{{t['kind']}}</td><td>{{money(t['amount'])}}</td><td>{{t['status']}}</td><td>{{(t['trx'] or t['number'] or '')}}</td></tr>{% endfor %}</table></div></div>
{% if logs %}<div class="card"><h3>লগইন ইতিহাস</h3><div class="tw"><table>{% for h in logs %}<tr><td>{{h['created'][:16]}}</td><td>{{h['ip']}}</td><td>{{'✅' if h['ok'] else '❌'}}</td></tr>{% endfor %}</table></div></div>{% endif %}""",
                active="/admin/users", x=x, led=led, logs=logs, txs=txs, refs=refs, by=by, idem=secrets.token_hex(8))


@app.route("/admin/users/<int:i>/block", methods=["POST"])
@staff_required("users_manage")
def admin_block(i):
    with atomic():
        db().execute("UPDATE users SET blocked=1-blocked, session_ver=session_ver+1 WHERE id=? AND is_admin=0", (i,))
        audit("toggle_block", "user#%d" % i)
    return redirect("/admin/users/%d" % i)


@app.route("/admin/users/<int:i>/resetcode", methods=["POST"])
@staff_required("users_manage")
def admin_resetcode(i):
    if not q1("SELECT 1 FROM users WHERE id=? AND is_admin=0", (i,)):
        abort(404)
    code = "".join(secrets.choice(CODE_ALPHA) for _ in range(8))
    with atomic():
        db().execute("UPDATE resets SET used=1 WHERE user_id=?", (i,))
        db().execute("INSERT INTO resets(user_id,token_hash,expires,created) VALUES(?,?,?,?)",
                     (i, hashlib.sha256(code.encode()).hexdigest(), (datetime.utcnow() + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S"), now()))
        audit("reset_code", "user#%d" % i)
    flash("রিসেট কোড (৩০ মিনিট, একবার ব্যবহারযোগ্য): %s — ইউজারকে সরাসরি জানান।" % code)
    return redirect("/admin/users/%d" % i)


@app.route("/admin/users/<int:i>/adjust", methods=["POST"])
@staff_required("adjust")
def admin_adjust(i):
    try:
        amt = round(float(request.form.get("amount", "0")), 2)
    except ValueError:
        amt = 0
    reason = request.form.get("reason", "").strip()[:200]
    idem = "adj:" + re.sub(r"\W", "", request.form.get("idem", ""))[:32]
    if not amt or amt != amt or not reason or abs(amt) > 10_000_000 or len(idem) < 6:
        err("সঠিক পরিমাণ ও কারণ দিন।"); return redirect("/admin/users/%d" % i)
    if not q1("SELECT 1 FROM users WHERE id=? AND is_admin=0", (i,)):
        abort(404)
    try:
        with atomic():
            if post(i, "admin_adjust", amt, idem, "admin", None, reason, me()["member_id"]):
                audit("adjust", "user#%d %+.2f %s" % (i, amt, reason))
                notify(i, "ব্যালেন্স সমন্বয়", "৳%s — %s" % (money(amt), reason))
                flash("সমন্বয় হয়েছে।")
            else:
                flash("এই অপারেশন আগেই হয়েছে।")
    except LedgerError as e:
        err("ব্যর্থ: " + str(e))
    return redirect("/admin/users/%d" % i)


# ---------------------------------------------------------------- admin: referrals
@app.route("/admin/referrals")
@staff_required("referrals")
def admin_referrals():
    st = request.args.get("status", "pending")
    if st not in ("pending", "approved", "rejected", "all"):
        st = "pending"
    rows = qa(REF_SQL + (" WHERE r.status=?" if st != "all" else " WHERE ?='all'") + " ORDER BY r.id DESC LIMIT 100", (st,))
    sm = q1("""SELECT COALESCE(SUM(status='pending'),0) p, COALESCE(SUM(status='approved'),0) a, COALESCE(SUM(status='rejected'),0) r,
               COALESCE(SUM(CASE WHEN status='pending' THEN amount END),0) pa, COALESCE(SUM(CASE WHEN status='approved' THEN amount END),0) aa FROM referrals""")
    return page("""<div class="g2"><div class="card"><div class="k">পেন্ডিং</div><div class="v">{{sm['p']}} <span class="k">(৳{{money(sm['pa'])}})</span></div></div>
<div class="card"><div class="k">অনুমোদিত (প্রদত্ত)</div><div class="v">{{sm['a']}} <span class="k">(৳{{money(sm['aa'])}})</span></div></div>
<div class="card"><div class="k">বাতিল</div><div class="v">{{sm['r']}}</div></div></div>
<div class="row" style="margin-bottom:10px">{% for k,l in [('pending','পেন্ডিং'),('approved','অনুমোদিত'),('rejected','বাতিল'),('all','সব')] %}<a class="btn sm {{'' if k==st else 's'}}" href="?status={{k}}">{{l}}</a>{% endfor %}</div>"""
                + REF_LIST, active="/admin/referrals", rows=rows, sm=sm, st=st)


@app.route("/admin/referrals/<int:i>", methods=["POST"])
@staff_required("referrals")
def admin_ref_act(i):
    act, note = request.form.get("act"), request.form.get("note", "").strip()[:200]
    if act not in ("approve", "reject"):
        abort(400)
    a = me()
    who = "%s (%s)" % (a["name"], a["member_id"])
    try:
        with atomic():
            r = q1("SELECT * FROM referrals WHERE id=?", (i,))
            if not r:
                abort(404)
            if r["status"] != "pending":  # duplicate approval / double click protection
                err("এই রেফারেল আগেই প্রক্রিয়া করা হয়েছে।"); return back("/admin/referrals")
            rf = q1("SELECT * FROM users WHERE id=?", (r["referrer_id"],))
            x = q1("SELECT * FROM users WHERE id=?", (r["referred_id"],))
            if not rf or not x or r["referrer_id"] == r["referred_id"] or x["referred_by"] != r["referrer_id"]:
                err("অবৈধ রেফারেল সম্পর্ক — অনুমোদন সম্ভব নয়।"); return back("/admin/referrals")
            if act == "approve" and rf["blocked"]:
                err("রেফারার ব্লকড। আনব্লক করুন অথবা বাতিল করুন।"); return back("/admin/referrals")
            new = "approved" if act == "approve" else "rejected"
            cur = db().execute("UPDATE referrals SET status=?, decided_by=?, decided_by_id=?, decided_at=?, note=? WHERE id=? AND status='pending'",
                               (new, who, a["id"], now(), note, i))
            if cur.rowcount != 1:
                raise LedgerError("duplicate decision")
            if act == "approve":
                if not post(rf["id"], "referral_bonus", r["amount"], "ref:%d:bonus" % i, "referral", i,
                            "Referral bonus for #%s" % x["member_id"], a["member_id"]):
                    raise LedgerError("duplicate credit")
                notify(rf["id"], "রেফারেল বোনাস অনুমোদিত", "#%s-এর রেফারেলের জন্য ৳%s আপনার ওয়ালেটে যুক্ত হয়েছে।" % (x["member_id"], money(r["amount"])))
            else:
                notify(rf["id"], "রেফারেল বাতিল", "#%s-এর রেফারেল বোনাস অনুমোদিত হয়নি।%s" % (x["member_id"], (" কারণ: " + note) if note else ""))
            audit("referral_" + act, "ref#%d referrer#%s referred#%s ৳%s" % (i, rf["member_id"], x["member_id"], r["amount"]))
    except LedgerError as e:
        err("ব্যর্থ: " + str(e)); return back("/admin/referrals")
    flash("রেফারেল %s।" % ("অনুমোদিত হয়েছে" if act == "approve" else "বাতিল হয়েছে"))
    return back("/admin/referrals")


# ---------------------------------------------------------------- admin: manual commission
@app.route("/admin/commission", methods=["GET", "POST"])
@staff_required("commissions")
def admin_commission():
    a = me()
    if request.method == "POST":
        uid = request.form.get("uid", type=int)
        amt = parse_amount(request.form.get("amount"))
        reason = request.form.get("reason", "").strip()[:200]
        token = re.sub(r"\W", "", request.form.get("idem", ""))[:32]
        x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (uid,)) if uid else None
        if not x or x["blocked"] or amt <= 0 or len(reason) < 3 or len(token) < 6:
            err("ইউজার নির্বাচন করুন এবং সঠিক পরিমাণ ও কারণ (কমপক্ষে ৩ অক্ষর) দিন।"); return redirect("/admin/commission" + ("?uid=%d" % uid if uid else ""))
        idem = "com:" + token
        try:
            with atomic():
                cur = db().execute("INSERT OR IGNORE INTO commissions(user_id,amount,reason,given_by_id,given_by,idem,created) VALUES(?,?,?,?,?,?,?)",
                                   (x["id"], amt, reason, a["id"], "%s (%s)" % (a["name"], a["member_id"]), idem, now()))
                if cur.rowcount == 0:
                    flash("এই কমিশন আগেই দেওয়া হয়েছে (ডুপ্লিকেট সাবমিট)।")
                else:
                    if not post(x["id"], "commission", amt, idem, "commission", cur.lastrowid, reason, a["member_id"]):
                        raise LedgerError("duplicate credit")
                    notify(x["id"], "কমিশন", "৳%s কমিশন যুক্ত হয়েছে — %s" % (money(amt), reason))
                    audit("commission", "#%s ৳%s %s" % (x["member_id"], money(amt), reason))
                    flash("৳%s কমিশন #%s-কে দেওয়া হয়েছে।" % (money(amt), x["member_id"]))
        except LedgerError as e:
            err("ব্যর্থ: " + str(e))
        return redirect("/admin/commission")
    s = request.args.get("q", "").strip().lstrip("#")[:40]
    like = "%" + s + "%"
    found = qa("SELECT * FROM users WHERE is_admin=0 AND (member_id=? OR name LIKE ? OR phone LIKE ?) ORDER BY id LIMIT 10", (s, like, like)) if s else []
    uid = request.args.get("uid", type=int)
    sel = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (uid,)) if uid else None
    hist = qa("SELECT c.*,u.member_id m,u.name n FROM commissions c JOIN users u ON u.id=c.user_id ORDER BY c.id DESC LIMIT 50")
    return page("""<div class="card"><h2>ম্যানুয়াল কমিশন</h2><p class="k">শুধু সম্পন্ন কাজ/সার্ভিসের বিনিময়ে দিন। কারণ বাধ্যতামূলক এবং ব্যবহারকারী নোটিফিকেশন পাবেন।</p>
<form><label>ইউজার খুঁজুন (মেম্বার আইডি / নাম / ফোন)</label><input name="q" value="{{s}}" required><button style="width:100%">খুঁজুন</button></form>
{% for f in found %}<a href="?uid={{f['id']}}&q={{s|urlencode}}"><div class="card" style="margin:10px 0 0"><b>#{{f['member_id']}} {{f['name']}}</b> {% if f['blocked'] %}<span class="pill rejected">blocked</span>{% endif %}
<div class="k">{{f['phone']}} · ৳ {{money(f['balance'])}}</div></div></a>{% endfor %}
{% if s and not found %}<div class="empty">কোনো ইউজার পাওয়া যায়নি</div>{% endif %}</div>
{% if sel %}<div class="card"><h3>প্রাপক: #{{sel['member_id']}} {{sel['name']}}</h3>
{% if sel['blocked'] %}<div class="msg error">ইউজারটি ব্লকড — কমিশন দেওয়া যাবে না।</div>{% else %}
<form method="post" data-confirm="লেজারে স্থায়ীভাবে রেকর্ড হবে। নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="idem" value="{{idem}}"><input type="hidden" name="uid" value="{{sel['id']}}">
<label>কমিশনের পরিমাণ (৳)</label><input name="amount" type="number" step="0.01" min="0.01" required><label>কারণ (আবশ্যক)</label><input name="reason" required minlength="3" maxlength="200">
<button style="width:100%" class="g">কমিশন দিন</button></form>{% endif %}</div>{% endif %}
<div class="card"><h3>কমিশন ইতিহাস</h3><div class="tw"><table><tr><th>ইউজার</th><th>৳</th><th>কারণ</th><th>কে দিয়েছেন</th><th>সময়</th></tr>
{% for h in hist %}<tr><td>#{{h['m']}} {{h['n']}}</td><td>{{money(h['amount'])}}</td><td>{{h['reason']}}</td><td>{{h['given_by']}}</td><td>{{h['created'][:16]}}</td></tr>{% endfor %}</table></div></div>""",
                active="/admin/commission", s=s, found=found, sel=sel, hist=hist, idem=secrets.token_hex(8))


# ---------------------------------------------------------------- admin: staff management (Super Admin only)
def _perm_boxes(selected):
    return [(p, PERM_LABELS[p], p in selected) for p in ADMIN_ASSIGNABLE]


def _form_perms():
    return ",".join(p for p in ADMIN_ASSIGNABLE if request.form.get("perm_" + p))


def _staff_target(i):
    t = q1("SELECT * FROM users WHERE id=? AND is_admin=1", (i,))
    if not t:
        abort(404)
    return t


STAFF_FORM_FIELDS = """<label>নাম</label><input name="name" required maxlength="60" value="{{(t['name'] if t else '')}}">
<label>রোল</label><select name="role">{% for k,l in roles %}<option value="{{k}}" {{'selected' if t and t['role']==k}}>{{l}}</option>{% endfor %}</select>
<div class="k">পারমিশন (শুধু "অ্যাডমিন" রোলের জন্য প্রযোজ্য; ফাইন্যান্স ও সাপোর্টের পারমিশন নির্দিষ্ট)</div>
{% for p,l,on in boxes %}<label class="ck"><input type="checkbox" name="perm_{{p}}" value="1" {{'checked' if on}}>{{l}}</label>{% endfor %}"""


@app.route("/admin/staff")
@staff_required("staff")
def admin_staff():
    rows = qa("SELECT * FROM users WHERE is_admin=1 ORDER BY id")
    roles = [(k, v) for k, v in ROLES.items() if k != "super_admin"]
    return page("""<div class="card"><h2>স্টাফ ম্যানেজমেন্ট</h2>
{% for x in rows %}<a href="/admin/staff/{{x['id']}}"><div class="card" style="margin:10px 0 0"><b>{{x['name']}}</b> <span class="pill">{{rn[x['role']] if x['role'] in rn else x['role']}}</span>
{% if x['blocked'] %}<span class="pill rejected">নিষ্ক্রিয়</span>{% else %}<span class="pill approved">সক্রিয়</span>{% endif %}
<div class="k">📱 {{x['phone']}} · {{x['member_id']}} · সর্বশেষ লগইন: {{(x['last_login'] or '-')[:16]}}</div></div></a>{% endfor %}</div>
<div class="card"><h3>নতুন স্টাফ</h3><form method="post" action="/admin/staff/new"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>মোবাইল নম্বর (লগইন আইডি)</label><input name="phone" required inputmode="numeric" maxlength="11">
<label>পাসওয়ার্ড (কমপক্ষে ৮ অক্ষর)</label><input name="pw" type="password" minlength="8" required>
""" + STAFF_FORM_FIELDS + """<button style="width:100%">স্টাফ তৈরি করুন</button></form></div>""",
                active="/admin/staff", rows=rows, rn=ROLES, roles=roles, t=None, boxes=_perm_boxes(ADMIN_DEFAULT))


@app.route("/admin/staff/new", methods=["POST"])
@staff_required("staff")
def admin_staff_new():
    n = request.form.get("name", "").strip()[:60]
    p = request.form.get("phone", "").strip()
    pw = request.form.get("pw", "")
    role = request.form.get("role")
    if not n or not re.fullmatch(r"01\d{9}", p) or len(pw) < 8 or role not in ROLES or role == "super_admin":
        err("নাম, সঠিক ১১ ডিজিটের নম্বর, ৮+ অক্ষরের পাসওয়ার্ড ও রোল দিন।"); return redirect("/admin/staff")
    perms = _form_perms() if role == "admin" else ""
    try:
        with atomic():
            cur = db().execute("INSERT INTO users(name,phone,pw,is_admin,role,perms,created,member_id) VALUES(?,?,?,1,?,?,?,?)",
                               (n, p, generate_password_hash(pw), role, perms, now(), "ST"))
            db().execute("UPDATE users SET member_id=? WHERE id=?", ("ST%d" % cur.lastrowid, cur.lastrowid))
            audit("staff_create", "staff#%d %s role=%s perms=%s" % (cur.lastrowid, p, role, perms))
    except sqlite3.IntegrityError:
        err("এই নম্বর আগেই ব্যবহৃত।"); return redirect("/admin/staff")
    flash("স্টাফ তৈরি হয়েছে।"); return redirect("/admin/staff")


@app.route("/admin/staff/<int:i>", methods=["GET", "POST"])
@staff_required("staff")
def admin_staff_edit(i):
    t = _staff_target(i)
    locked = t["role"] == "super_admin"
    if request.method == "POST":
        if locked:  # the Super Admin account can never be modified through the panel
            abort(403)
        n = request.form.get("name", "").strip()[:60]
        role = request.form.get("role")
        if not n or role not in ROLES or role == "super_admin":
            err("নাম ও সঠিক রোল দিন।"); return redirect("/admin/staff/%d" % i)
        perms = _form_perms() if role == "admin" else ""
        with atomic():
            db().execute("UPDATE users SET name=?, role=?, perms=? WHERE id=? AND is_admin=1 AND role<>'super_admin'", (n, role, perms, i))
            audit("staff_edit", "staff#%d role=%s perms=%s" % (i, role, perms))
        flash("সেভ হয়েছে।"); return redirect("/admin/staff/%d" % i)
    logs = qa("SELECT * FROM audit WHERE actor_id=? ORDER BY id DESC LIMIT 100", (i,))
    logins = qa("SELECT * FROM login_history WHERE user_id=? ORDER BY id DESC LIMIT 10", (i,))
    roles = [(k, v) for k, v in ROLES.items() if k != "super_admin"]
    return page("""<div class="card"><h2>{{t['name']}}</h2><p>📱 {{t['phone']}} · {{t['member_id']}} · <span class="pill">{{rn.get(t['role'], t['role'])}}</span>
{% if t['blocked'] %}<span class="pill rejected">নিষ্ক্রিয়</span>{% else %}<span class="pill approved">সক্রিয়</span>{% endif %}</p>
{% if locked %}<div class="k">সুপার অ্যাডমিনের তথ্য এখান থেকে পরিবর্তনযোগ্য নয় (Render Environment থেকে নিয়ন্ত্রিত)।</div>{% endif %}</div>
{% if not locked %}<div class="card"><h3>এডিট</h3><form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}">""" + STAFF_FORM_FIELDS + """<button style="width:100%">সেভ</button></form></div>
<div class="card"><div class="row"><form method="post" action="/admin/staff/{{t['id']}}/toggle" data-confirm="নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<button class="btn {{'g' if t['blocked'] else 'r'}}">{{'সক্রিয় করুন' if t['blocked'] else 'নিষ্ক্রিয় করুন'}}</button></form>
<form method="post" action="/admin/staff/{{t['id']}}/password" data-confirm="নতুন অস্থায়ী পাসওয়ার্ড তৈরি হবে এবং আগের সেশন বন্ধ হবে। নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<button class="btn s">পাসওয়ার্ড রিসেট</button></form></div></div>{% endif %}
<div class="card"><h3>অ্যাক্টিভিটি লগ</h3><div class="tw"><table>{% for a in logs %}<tr><td>{{a['created'][:16]}}</td><td>{{a['action']}}</td><td>{{a['detail']}}</td><td>{{a['ip'] or ''}}</td></tr>{% endfor %}</table></div></div>
<div class="card"><h3>লগইন ইতিহাস</h3><div class="tw"><table>{% for h in logins %}<tr><td>{{h['created'][:16]}}</td><td>{{h['ip']}}</td><td>{{'✅' if h['ok'] else '❌'}}</td></tr>{% endfor %}</table></div></div>""",
                active="/admin/staff", t=t, locked=locked, rn=ROLES, roles=roles, logs=logs, logins=logins,
                boxes=_perm_boxes((t["perms"] or "").split(",")))


@app.route("/admin/staff/<int:i>/toggle", methods=["POST"])
@staff_required("staff")
def admin_staff_toggle(i):
    t = _staff_target(i)
    if t["role"] == "super_admin" or t["id"] == me()["id"]:
        abort(403)
    with atomic():
        db().execute("UPDATE users SET blocked=1-blocked, session_ver=session_ver+1 WHERE id=? AND role<>'super_admin'", (i,))
        audit("staff_toggle", "staff#%d" % i)
    return redirect("/admin/staff/%d" % i)


@app.route("/admin/staff/<int:i>/password", methods=["POST"])
@staff_required("staff")
def admin_staff_password(i):
    t = _staff_target(i)
    if t["role"] == "super_admin":
        abort(403)
    tmp = "".join(secrets.choice(CODE_ALPHA) for _ in range(12))
    with atomic():
        db().execute("UPDATE users SET pw=?, session_ver=session_ver+1 WHERE id=? AND role<>'super_admin'", (generate_password_hash(tmp), i))
        audit("staff_password_reset", "staff#%d" % i)
    flash("অস্থায়ী পাসওয়ার্ড (একবারই দেখানো হবে): %s — স্টাফকে নিরাপদে জানান; তিনি প্রোফাইল থেকে বদলে নেবেন।" % tmp)
    return redirect("/admin/staff/%d" % i)


@app.route("/admin/profile", methods=["GET", "POST"])
@staff_required()
def admin_profile():
    u = me()
    if request.method == "POST":
        if u["role"] == "super_admin":
            abort(403)  # Super Admin password is controlled by ADMIN_PASSWORD env var
        if not check_password_hash(u["pw"], request.form.get("old", "")) or len(request.form.get("new", "")) < 8:
            err("পুরনো পাসওয়ার্ড ভুল অথবা নতুন পাসওয়ার্ড ৮ অক্ষরের কম।"); return redirect("/admin/profile")
        with atomic():
            db().execute("UPDATE users SET pw=?, session_ver=session_ver+1 WHERE id=?", (generate_password_hash(request.form["new"]), u["id"]))
            audit("password_change", "self")
        session.clear(); flash("পাসওয়ার্ড বদলেছে। আবার সাইন ইন করুন।"); return redirect("/login")
    return page("""<div class="card"><h2>{{u['name']}}</h2><p>📱 {{u['phone']}} · {{role_name}}</p></div>
{% if u['role']!='super_admin' %}<div class="card"><h3>পাসওয়ার্ড বদলান</h3><form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>পুরনো পাসওয়ার্ড</label><input name="old" type="password" required><label>নতুন পাসওয়ার্ড (৮+ অক্ষর)</label><input name="new" type="password" minlength="8" required>
<button style="width:100%">বদলান</button></form></div>{% else %}<div class="card k">সুপার অ্যাডমিনের পাসওয়ার্ড Render Environment (ADMIN_PASSWORD) থেকে নিয়ন্ত্রিত।</div>{% endif %}
<div class="card"><form method="post" action="/logout"><input type="hidden" name="_csrf" value="{{csrf_token}}"><button class="r" style="width:100%">লগআউট</button></form></div>""",
                active="/admin/profile")


# ---------------------------------------------------------------- admin: notices / tickets / settings / audit
@app.route("/admin/notices", methods=["GET", "POST"])
@staff_required("notices")
def admin_notices():
    if request.method == "POST":
        t, b = request.form.get("title", "").strip()[:100], request.form.get("body", "").strip()[:500]
        if t:
            db().execute("INSERT INTO notifications(user_id,title,body,created) VALUES(NULL,?,?,?)", (t, b, now()))
            audit("announcement", t); flash("প্রকাশিত হয়েছে।")
        return redirect("/admin/notices")
    rows = qa("SELECT * FROM notifications WHERE user_id IS NULL ORDER BY id DESC LIMIT 20")
    return page("""<div class="card"><h2>নোটিশ প্রকাশ</h2><form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}"><label>শিরোনাম</label><input name="title" required maxlength="100">
<label>বিস্তারিত</label><textarea name="body" rows="3" maxlength="500"></textarea><button style="width:100%">প্রকাশ করুন</button></form></div>
{% for n in rows %}<div class="card"><b>{{n['title']}}</b><div>{{n['body']}}</div><div class="k">{{n['created'][:16]}}</div></div>{% endfor %}""", active="/admin/notices", rows=rows)


@app.route("/admin/tickets", methods=["GET", "POST"])
@staff_required("tickets")
def admin_tickets():
    if request.method == "POST":
        tid, rep = request.form.get("id", type=int), request.form.get("reply", "").strip()[:500]
        a = me()
        with atomic():
            t = q1("SELECT * FROM tickets WHERE id=?", (tid,)) if tid else None
            if t and rep and t["status"] == "open":
                db().execute("UPDATE tickets SET reply=?, status='closed', replied_by=?, replied_at=? WHERE id=?",
                             (rep, "%s (%s)" % (a["name"], a["member_id"]), now(), tid))
                notify(t["user_id"], "সাপোর্ট উত্তর", rep); audit("ticket_reply", "ticket#%s" % tid); flash("উত্তর পাঠানো হয়েছে।")
        return redirect("/admin/tickets")
    rows = qa("SELECT t.*,u.member_id,u.name,u.phone FROM tickets t JOIN users u ON u.id=t.user_id ORDER BY (t.status='open') DESC, t.id DESC LIMIT 50")
    return page("""{% if not rows %}<div class="card empty">কোনো টিকিট নেই</div>{% endif %}{% for t in rows %}<div class="card"><b>{{t['subject']}}</b> <span class="pill {{'approved' if t['status']=='closed' else 'pending'}}">{{t['status']}}</span>
<div class="k">#{{t['member_id']}} {{t['name']}} · {{t['phone']}} · {{t['created'][:16]}}</div><div>{{t['message']}}</div>
{% if t['reply'] %}<div class="k">↳ {{t['reply']}}{% if t['replied_by'] %} — {{t['replied_by']}}{% endif %}</div>{% else %}<form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="id" value="{{t['id']}}">
<input name="reply" placeholder="উত্তর লিখুন" required maxlength="500"><button class="btn sm">পাঠান</button></form>{% endif %}
{% if can('users_view') %}<a class="k" href="/admin/users/{{t['user_id']}}">👤 ইউজার দেখুন</a>{% endif %}</div>{% endfor %}""", active="/admin/tickets", rows=rows)


@app.route("/admin/settings", methods=["GET", "POST"])
@staff_required("settings")
def admin_settings():
    keys = ("bkash", "nagad", "rocket", "min_deposit", "min_withdraw", "referral_bonus", "telegram_url", "welcome")
    if request.method == "POST":
        v = {k: request.form.get(k, "").strip() for k in keys}
        if v["telegram_url"] and not v["telegram_url"].startswith("https://"):
            err("টেলিগ্রাম লিংক https:// দিয়ে শুরু হতে হবে।"); return redirect("/admin/settings")
        for k in ("min_deposit", "min_withdraw", "referral_bonus"):
            if parse_amount(v[k]) <= 0:
                err("পরিমাণ সঠিক দিন।"); return redirect("/admin/settings")
        with atomic():
            for k in keys:
                db().execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (k, v[k][:2000]))
            audit("settings", "updated")
        flash("সেভ হয়েছে। (রেফারেল বোনাসের নতুন পরিমাণ শুধু নতুন রিকোয়েস্টে প্রযোজ্য।)"); return redirect("/admin/settings")
    st = {k: setting(k) for k in keys}
    return page("""<div class="card"><h2>সেটিংস</h2><form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>bKash নম্বর</label><input name="bkash" value="{{st.bkash}}"><label>Nagad নম্বর</label><input name="nagad" value="{{st.nagad}}"><label>Rocket নম্বর</label><input name="rocket" value="{{st.rocket}}">
<label>ন্যূনতম ডিপোজিট</label><input name="min_deposit" value="{{st.min_deposit}}"><label>ন্যূনতম উইথড্র</label><input name="min_withdraw" value="{{st.min_withdraw}}">
<label>রেফারেল বোনাস (৳, প্রতি সফল রেফার)</label><input name="referral_bonus" value="{{st.referral_bonus}}">
<label>টেলিগ্রাম সাপোর্ট URL</label><input name="telegram_url" value="{{st.telegram_url}}" placeholder="https://t.me/..."><label>স্বাগত বার্তা</label><textarea name="welcome" rows="8">{{st.welcome}}</textarea>
<button style="width:100%">সেভ</button></form></div>
<div class="card"><h3>ডাটাবেস ব্যাকআপ</h3><p class="k">নিয়মিত ডাউনলোড করে নিরাপদ জায়গায় রাখুন।</p>
<form method="post" action="/admin/backup"><input type="hidden" name="_csrf" value="{{csrf_token}}"><button class="s" style="width:100%">⬇ ব্যাকআপ নামান</button></form></div>""", active="/admin/settings", st=st)


@app.route("/admin/audit")
@staff_required("audit")
def admin_audit():
    rows = qa("SELECT * FROM audit ORDER BY id DESC LIMIT 150")
    fails = qa("SELECT * FROM login_history WHERE ok=0 ORDER BY id DESC LIMIT 15")
    return page("""<div class="card"><h2>অডিট লগ</h2><div class="tw"><table>{% for a in rows %}<tr><td>{{a['created'][:16]}}</td><td>{{a['actor']}}</td><td>{{a['action']}}</td><td>{{a['detail']}}</td></tr>{% endfor %}</table></div></div>
<div class="card"><h3>ব্যর্থ লগইন</h3><div class="tw"><table>{% for h in fails %}<tr><td>{{h['created'][:16]}}</td><td>{{h['phone']}}</td><td>{{h['ip']}}</td></tr>{% endfor %}</table></div></div>""", active="/admin/audit", rows=rows, fails=fails)


@app.route("/admin/backup", methods=["POST"])
@staff_required("backup")
def admin_backup():
    import tempfile
    tmp = os.path.join(tempfile.gettempdir(), "ewallet-backup-%s.db" % datetime.utcnow().strftime("%Y%m%d-%H%M%S"))
    dst = sqlite3.connect(tmp)
    db().backup(dst)
    dst.close()
    audit("backup_download", os.path.basename(tmp))
    return send_file(tmp, as_attachment=True, download_name=os.path.basename(tmp))


@app.route("/healthz")
def healthz():
    return "ok"


migrate()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
