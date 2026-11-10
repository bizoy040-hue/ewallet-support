"""E-Wallet Support v5 - single file app (Flask + SQLite by default, PostgreSQL/Supabase when DATABASE_URL is set).
Env: SECRET_KEY, ADMIN_PHONE, ADMIN_PASSWORD, DATABASE_PATH, UPLOAD_DIR, BASE_URL (optional)
     ADMIN_2FA_CODE_HASH (werkzeug hash of the admin security code, preferred) or ADMIN_SECURITY_CODE (plain, server-side only)
     DATABASE_URL (PostgreSQL), SUPABASE_URL, SUPABASE_SERVICE_KEY, SUPABASE_BUCKET (screenshot storage)
"""
import os, re, sqlite3, secrets, hashlib, time, csv, io, tempfile, zipfile, threading, gzip
from datetime import datetime, timedelta
from functools import wraps, lru_cache
from flask import (Flask, request, redirect, session, render_template_string, g, flash,
                   abort, send_file, jsonify, after_this_request, send_from_directory, Response)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")),
                  MAX_CONTENT_LENGTH=6 * 1024 * 1024,
                  PERMANENT_SESSION_LIFETIME=timedelta(days=7))
if os.environ.get("RENDER"):  # trust exactly one proxy hop (Render) for real client IP / https
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
DB = os.environ.get("DATABASE_PATH", "ewallet.db")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(os.path.dirname(os.path.abspath(DB)), "uploads"))
SITE = "E-Wallet Support"
METHODS = ("bKash", "Nagad", "Rocket")
SCHEMA_VERSION = 7
CODE_ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

# ---------------------------------------------------------------- roles & permissions (enforced server-side)
ROLES = {"super_admin": "সুপার অ্যাডমিন", "admin": "অ্যাডমিন", "finance": "ফাইন্যান্স স্টাফ", "support": "সাপোর্ট স্টাফ"}
PERM_LABELS = {
    "dashboard_fin": "আর্থিক পরিসংখ্যান দেখা", "deposits": "ডিপোজিট প্রসেস", "withdrawals": "উইথড্র প্রসেস",
    "users_view": "ইউজার/লেনদেন দেখা", "users_manage": "ইউজার ব্লক ও রিসেট কোড", "adjust": "ব্যালেন্স সমন্বয়",
    "referrals": "রেফারেল অনুমোদন", "commissions": "কমিশন প্রদান", "tickets": "সাপোর্ট টিকিট",
    "notices": "নোটিশ প্রকাশ", "audit": "অডিট লগ দেখা"}
PERM_LABELS.update({"requests": "ম্যানুয়াল রিকোয়েস্ট", "payment_numbers": "পেমেন্ট নম্বর দেখা", "pool_view": "কমিশন পুল দেখা",
                    "reports": "আর্থিক রিপোর্ট দেখা", "rates": "ইউজার কমিশন রেট বদলানো", "kyc": "KYC যাচাই",
                    "vip": "VIP অনুমোদন ও পরিবর্তন"})
ADMIN_ASSIGNABLE = tuple(PERM_LABELS)                       # what a Super Admin can grant to an "admin"
ADMIN_DEFAULT = tuple(p for p in ADMIN_ASSIGNABLE if p not in ("adjust", "vip"))
ROLE_FIXED = {"finance": frozenset({"dashboard_fin", "deposits", "withdrawals", "users_view", "referrals", "commissions"}),
              "support": frozenset({"tickets", "users_view"})}
ROLE_FIXED["finance"] = ROLE_FIXED["finance"] | frozenset({"requests", "payment_numbers", "pool_view", "reports"})
SUPER_ONLY = frozenset({"staff", "settings", "backup", "pool_fund", "rates_global"})

WELCOME_DEFAULT = ("আসসালামু আলাইকুম!\n\nআমাদের E-Wallet Support প্ল্যাটফর্মে আপনাকে স্বাগতম।\n\n"
                   "আপনার সময়, দক্ষতা ও প্রচেষ্টাকে কাজে লাগিয়ে আমাদের সঙ্গে কাজ করার সুযোগ গ্রহণ করুন।\n\n"
                   "আপনার যাত্রা শুরু হোক আজ থেকেই!")


def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


# Display-only Bangladesh time (UTC+6). The database keeps storing UTC (now()); nothing stored is ever rewritten.
# Every timestamp that reaches a page is converted exactly once when the HTML is built (see page()).
# Report pages already convert with _loc() and mark their output with ⁣ so they are skipped here (no double shift).
BD_OFFSET = timedelta(hours=6)
_MARK = "⁣"
_TS_RE = re.compile(r"(?<![⁣\d])(\d{4}-\d{2}-\d{2}) (\d{2}):(\d{2})( \(UTC\)| UTC\b)?")


def _bd_sub(m):
    try:
        d = datetime.strptime("%s %s:%s" % (m.group(1), m.group(2), m.group(3)), "%Y-%m-%d %H:%M") + BD_OFFSET
    except ValueError:
        return m.group(0)
    suf = m.group(4) or ""
    if suf:
        suf = " (BDT)" if "(" in suf else " BDT"
    return d.strftime("%Y-%m-%d %H:%M") + suf


def to_bdt(html):
    return _TS_RE.sub(_bd_sub, html).replace(_MARK, "")


@app.template_filter("bdd")
def _bdd(ts):
    """UTC timestamp string -> Bangladesh date (YYYY-MM-DD)."""
    try:
        return (datetime.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S") + BD_OFFSET).strftime("%Y-%m-%d")
    except ValueError:
        return str(ts or "")[:10]


# ---------------------------------------------------------------- database layer (SQLite default, PostgreSQL when DATABASE_URL is set)
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
PG = DATABASE_URL.startswith(("postgres://", "postgresql://"))
if PG:
    import psycopg
    from decimal import Decimal
    INTEGRITY = (sqlite3.IntegrityError, psycopg.errors.IntegrityError)
    DBERR = (sqlite3.Error, psycopg.Error)
else:
    INTEGRITY = (sqlite3.IntegrityError,)
    DBERR = (sqlite3.Error,)
ID_TABLES = frozenset("users tx ledger notifications audit login_history resets tickets referrals commissions requests "
                      "request_log payment_numbers payment_number_log admin_alerts".split())
TABLES = ["users", "tx", "settings", "meta", "ledger", "notifications", "audit", "login_history", "resets", "tickets",
          "referrals", "commissions", "requests", "request_log", "payment_numbers", "payment_number_log",
          "admin_alerts", "admin_alert_reads"]
PG_LOCK_KEY = 7343001  # global write lock == SQLite's BEGIN IMMEDIATE (every money-moving block runs under it)


class PGRow(tuple):
    """sqlite3.Row look-alike: row[0], row['col'], keys(), dict(row)."""
    def __new__(cls, keys, vals):
        r = tuple.__new__(cls, vals)
        r._k = list(keys)
        return r

    def __getitem__(self, i):
        if isinstance(i, str):
            try:
                return tuple.__getitem__(self, self._k.index(i))
            except ValueError:
                raise IndexError("No item with that key")
        return tuple.__getitem__(self, i)

    def keys(self):
        return list(self._k)


def _pyval(v):
    return float(v) if PG and isinstance(v, Decimal) else v


@lru_cache(maxsize=2048)
def _tr(sql):
    """SQLite-dialect SQL used by the app -> PostgreSQL. Returns (sql, wants_returning_id)."""
    s = sql.strip().rstrip(";")
    s = re.sub(r"member_id GLOB '\[0-9\]\*'", "member_id ~ '^[0-9]+$'", s)
    s = re.sub(r"datetime\(\s*'now'\s*,\s*'-(\d+) days'\s*\)",
               r"to_char((now() AT TIME ZONE 'UTC') - interval '\1 days','YYYY-MM-DD HH24:MI:SS')", s)
    s = re.sub(r"date\(\s*'now'\s*\)", "to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD')", s)
    s = re.sub(r"SUM\((\w+)='(\w+)'\)", r"SUM(CASE WHEN \1='\2' THEN 1 ELSE 0 END)", s)  # SQLite sums booleans, PostgreSQL cannot
    tail = ""
    if re.match(r"INSERT OR IGNORE INTO", s, re.I):
        s = re.sub(r"^INSERT OR IGNORE INTO", "INSERT INTO", s, flags=re.I)
        tail = " ON CONFLICT DO NOTHING"
    elif re.match(r"INSERT OR REPLACE INTO (settings|meta) ", s, re.I):
        s = re.sub(r"^INSERT OR REPLACE INTO", "INSERT INTO", s, flags=re.I)
        tail = " ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v"

    def outside(p):
        p = p.replace("%", "%%").replace("?", "%s")
        p = re.sub(r"\bLIKE\b", "ILIKE", p, flags=re.I)
        return re.sub(r"\bdate\(\s*([A-Za-z_][\w.]*)\s*\)", r"substr(\1,1,10)", p)
    parts = re.split(r"('(?:[^']|'')*')", s)
    s = "".join(p if i % 2 else outside(p) for i, p in enumerate(parts))
    m = re.match(r"INSERT INTO (\w+)", s, re.I)
    ret = bool(m and m.group(1).lower() in ID_TABLES)
    return s + tail + (" RETURNING id" if ret else ""), ret


class _PGCur:
    def __init__(self, cur=None, ret=False):
        self.lastrowid, self.rowcount, self._rows, self._i = None, 0, [], 0
        if cur is not None:
            self.rowcount = cur.rowcount
            if cur.description is not None:
                keys = [d[0] for d in cur.description]
                self._rows = [PGRow(keys, tuple(_pyval(v) for v in r)) for r in cur.fetchall()]
            if ret and self._rows:
                self.lastrowid = self._rows[0]["id"]

    def fetchone(self):
        if self._i < len(self._rows):
            self._i += 1
            return self._rows[self._i - 1]
        return None

    def fetchall(self):
        r, self._i = self._rows[self._i:], len(self._rows)
        return r

    def __iter__(self):
        return iter(self.fetchall())


class PGConn:
    """Gives the PostgreSQL connection the same tiny API the app already uses on sqlite3."""
    def __init__(self, c):
        self.c = c

    def execute(self, sql, args=()):
        u = sql.strip().upper()
        if u == "BEGIN IMMEDIATE":  # same guarantee as SQLite: one writer at a time, auto-released at COMMIT/ROLLBACK
            self.c.execute("BEGIN")
            self.c.execute("SELECT pg_advisory_xact_lock(%s)", (PG_LOCK_KEY,))
            return _PGCur()
        if u.startswith("PRAGMA"):
            return _PGCur()
        text, ret = _tr(sql)
        return _PGCur(self.c.execute(text, tuple(args)), ret)

    def executescript(self, sql):
        self.c.execute(sql)

    def close(self):
        _pg_release(self.c)


def _pg_connect():
    last = None
    for _ in range(2):
        try:
            return psycopg.connect(DATABASE_URL, autocommit=True, prepare_threshold=None, connect_timeout=10)
        except psycopg.OperationalError as e:
            last = e
            time.sleep(0.5)
    raise last


_PGPOOL, _PGPOOL_LOCK, _PGPOOL_MAX = [], threading.Lock(), 6


def _pg_acquire():
    """Re-use an idle PostgreSQL connection (saves a TLS+auth handshake on every request). Falls back to a fresh connection."""
    while True:
        with _PGPOOL_LOCK:
            item = _PGPOOL.pop() if _PGPOOL else None
        if not item:
            return _pg_connect()
        c, t = item
        try:
            if c.closed or c.broken:
                continue
            if time.time() - t > 20:
                c.execute("SELECT 1")  # idle for a while: make sure the server did not drop it
            return c
        except Exception:
            try:
                c.close()
            except Exception:
                pass


def _pg_release(c):
    try:
        if c.closed or c.broken or c.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
            c.close()  # never put a connection with an open/failed transaction back
            return
        with _PGPOOL_LOCK:
            if len(_PGPOOL) < _PGPOOL_MAX:
                _PGPOOL.append((c, time.time()))
                return
        c.close()
    except Exception:
        try:
            c.close()
        except Exception:
            pass


def db():
    if "db" not in g:
        if PG:
            g.db = PGConn(_pg_acquire())
        else:
            g.db = sqlite3.connect(DB, timeout=30, isolation_level=None)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys=ON")
            g.db.execute("PRAGMA busy_timeout=30000")
    return g.db


# ---------------------------------------------------------------- screenshot storage (local folder or Supabase Storage)
SHOT_RE = re.compile(r"[0-9a-f]{32}\.(jpg|png|webp)")
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "").strip()
SUPABASE_BUCKET = os.environ.get("SUPABASE_BUCKET", "screenshots").strip()
STORAGE = "supabase" if (SUPABASE_URL and SUPABASE_KEY) else "local"
MIME = {"jpg": "image/jpeg", "png": "image/png", "webp": "image/webp"}


class StorageError(Exception):
    pass


def _sb(method, path, **kw):
    import requests
    h = {"Authorization": "Bearer " + SUPABASE_KEY, "apikey": SUPABASE_KEY}
    h.update(kw.pop("headers", {}))
    try:
        return requests.request(method, SUPABASE_URL + "/storage/v1" + path, headers=h, timeout=25, **kw)
    except requests.RequestException as e:
        raise StorageError("storage unreachable: %s" % e.__class__.__name__)


def store_put(name, data):
    if STORAGE == "local":
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        with open(os.path.join(UPLOAD_DIR, name), "wb") as fh:
            fh.write(data)
        return
    r = _sb("POST", "/object/%s/%s" % (SUPABASE_BUCKET, name), data=data,
            headers={"Content-Type": MIME[name.rsplit(".", 1)[1]], "x-upsert": "false"})
    if r.status_code not in (200, 201):
        raise StorageError("upload failed (%s)" % r.status_code)


def store_get(name):
    if not SHOT_RE.fullmatch(name):
        return None
    if STORAGE == "local":
        p = os.path.join(UPLOAD_DIR, name)
        if not os.path.isfile(p):
            return None
        with open(p, "rb") as fh:
            return fh.read()
    r = _sb("GET", "/object/authenticated/%s/%s" % (SUPABASE_BUCKET, name))
    if r.status_code == 200:
        return r.content
    if r.status_code in (400, 404):
        return None
    raise StorageError("download failed (%s)" % r.status_code)


def store_delete(name):
    if not name or not SHOT_RE.fullmatch(name):
        return
    try:
        if STORAGE == "local":
            os.remove(os.path.join(UPLOAD_DIR, name))
        else:
            _sb("DELETE", "/object/%s/%s" % (SUPABASE_BUCKET, name))
    except (OSError, StorageError):
        pass


def store_list():
    if STORAGE == "local":
        return sorted(n for n in os.listdir(UPLOAD_DIR) if SHOT_RE.fullmatch(n)) if os.path.isdir(UPLOAD_DIR) else []
    names, off = [], 0
    while True:
        r = _sb("POST", "/object/list/%s" % SUPABASE_BUCKET,
                json={"prefix": "", "limit": 100, "offset": off, "sortBy": {"column": "name", "order": "asc"}})
        if r.status_code != 200:
            raise StorageError("list failed (%s)" % r.status_code)
        page_ = r.json()
        names += [o["name"] for o in page_ if SHOT_RE.fullmatch(o.get("name", ""))]
        if len(page_) < 100:
            return sorted(names)
        off += 100


def optimize_image(data):
    """Returns (bytes, ext) re-encoded as a downscaled WebP (EXIF stripped), or (None, None) if the file is not a readable image.
    Without Pillow the original bytes are kept (validated by magic bytes only)."""
    ext = ("jpg" if data[:3] == b"\xff\xd8\xff" else "png" if data[:4] == b"\x89PNG"
           else "webp" if data[:4] == b"RIFF" and data[8:12] == b"WEBP" else None)
    if not ext:
        return None, None
    try:
        from PIL import Image, ImageOps
    except ImportError:
        return data, ext
    Image.MAX_IMAGE_PIXELS = 40_000_000
    try:
        im = Image.open(io.BytesIO(data))
        im.load()
        im = ImageOps.exif_transpose(im)
        if im.mode in ("RGBA", "LA", "P"):
            im = im.convert("RGBA")
            bg = Image.new("RGB", im.size, "white")
            bg.paste(im, mask=im.split()[3])
            im = bg
        elif im.mode != "RGB":
            im = im.convert("RGB")
        im.thumbnail((1600, 1600))
        out = io.BytesIO()
        im.save(out, "WEBP", quality=80, method=4)
    except Exception:
        return None, None
    return (out.getvalue(), "webp") if out.tell() < len(data) else (data, ext)


# ---------------------------------------------------------------- PostgreSQL schema (mirrors the SQLite v4 schema; money = NUMERIC(14,2))
_TS = "TEXT DEFAULT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS')"
_ID = "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY"
PG_DDL = """
CREATE TABLE IF NOT EXISTS users(id %(ID)s, name TEXT, phone TEXT UNIQUE, pw TEXT,
    balance NUMERIC(14,2) DEFAULT 0, commission NUMERIC(14,2) DEFAULT 0, is_admin INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0,
    member_id TEXT, created TEXT, last_login TEXT, session_ver INTEGER DEFAULT 0, comm_rate_note TEXT, role TEXT, perms TEXT,
    referral_code TEXT, referred_by BIGINT, signup_ip TEXT);
CREATE TABLE IF NOT EXISTS tx(id %(ID)s, user_id BIGINT, kind TEXT, method TEXT, amount NUMERIC(14,2), trx TEXT,
    status TEXT DEFAULT 'pending', created %(TS)s, norm_trx TEXT, note TEXT, screenshot TEXT, updated TEXT, number TEXT);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS ledger(id %(ID)s, user_id BIGINT NOT NULL, kind TEXT NOT NULL, amount NUMERIC(14,2) NOT NULL,
    ref_type TEXT, ref_id BIGINT, idem TEXT UNIQUE, note TEXT, actor TEXT, created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_ledger_user ON ledger(user_id);
CREATE TABLE IF NOT EXISTS notifications(id %(ID)s, user_id BIGINT, title TEXT, body TEXT, is_read INTEGER DEFAULT 0, created TEXT, link TEXT);
CREATE TABLE IF NOT EXISTS audit(id %(ID)s, actor TEXT, action TEXT, detail TEXT, created TEXT, actor_id BIGINT, ip TEXT);
CREATE TABLE IF NOT EXISTS login_history(id %(ID)s, user_id BIGINT, phone TEXT, ip TEXT, ok INTEGER, created TEXT);
CREATE TABLE IF NOT EXISTS resets(id %(ID)s, user_id BIGINT, token_hash TEXT, expires TEXT, used INTEGER DEFAULT 0, created TEXT);
CREATE TABLE IF NOT EXISTS tickets(id %(ID)s, user_id BIGINT, subject TEXT, message TEXT, reply TEXT, status TEXT DEFAULT 'open',
    created TEXT, replied_by TEXT, replied_at TEXT);
CREATE TABLE IF NOT EXISTS referrals(id %(ID)s, referrer_id BIGINT NOT NULL REFERENCES users(id),
    referred_id BIGINT NOT NULL UNIQUE REFERENCES users(id), code TEXT, amount NUMERIC(14,2) NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', note TEXT, created TEXT NOT NULL, decided_by TEXT, decided_by_id BIGINT, decided_at TEXT,
    CHECK(referrer_id<>referred_id), CHECK(status IN('pending','approved','rejected')));
CREATE INDEX IF NOT EXISTS ix_ref_referrer ON referrals(referrer_id);
CREATE INDEX IF NOT EXISTS ix_ref_status ON referrals(status);
CREATE TABLE IF NOT EXISTS commissions(id %(ID)s, user_id BIGINT NOT NULL REFERENCES users(id),
    amount NUMERIC(14,2) NOT NULL CHECK(amount>0), reason TEXT NOT NULL, given_by_id BIGINT, given_by TEXT, idem TEXT UNIQUE, created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_comm_user ON commissions(user_id);
CREATE TABLE IF NOT EXISTS requests(id %(ID)s, order_id TEXT NOT NULL, user_id BIGINT NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL CHECK(kind IN('deposit','withdraw')), amount NUMERIC(14,2) NOT NULL CHECK(amount>0),
    method TEXT NOT NULL, pay_number TEXT NOT NULL, instructions TEXT, expires_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','submitted','review','approved','rejected','expired','cancelled')),
    trx TEXT, norm_trx TEXT, screenshot TEXT, submitted_at TEXT, created_by_id BIGINT, created_by TEXT, created TEXT NOT NULL,
    decided_by_id BIGINT, decided_by TEXT, decided_at TEXT, reject_reason TEXT, updated TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS ux_req_order ON requests(order_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_req_trx ON requests(norm_trx) WHERE norm_trx IS NOT NULL AND norm_trx<>'';
CREATE INDEX IF NOT EXISTS ix_req_user ON requests(user_id);
CREATE INDEX IF NOT EXISTS ix_req_status ON requests(status);
CREATE TABLE IF NOT EXISTS request_log(id %(ID)s, request_id BIGINT NOT NULL REFERENCES requests(id), action TEXT NOT NULL,
    from_status TEXT, to_status TEXT, actor TEXT, actor_id BIGINT, note TEXT, created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_reqlog_req ON request_log(request_id);
CREATE TABLE IF NOT EXISTS payment_numbers(id %(ID)s, user_id BIGINT NOT NULL REFERENCES users(id), method TEXT NOT NULL,
    account_type TEXT NOT NULL, number TEXT NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL, UNIQUE(user_id, method, number));
CREATE INDEX IF NOT EXISTS ix_pn_user ON payment_numbers(user_id);
CREATE TABLE IF NOT EXISTS payment_number_log(id %(ID)s, user_id BIGINT, pn_id BIGINT, action TEXT, method TEXT, account_type TEXT,
    number TEXT, old TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS admin_alerts(id %(ID)s, title TEXT, body TEXT, link TEXT, perm TEXT, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin_alert_reads(alert_id BIGINT NOT NULL, admin_id BIGINT NOT NULL, PRIMARY KEY(alert_id, admin_id));
CREATE INDEX IF NOT EXISTS ix_tx_user ON tx(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_refcode ON users(referral_code) WHERE referral_code IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_dep_trx ON tx(norm_trx) WHERE kind='deposit' AND norm_trx<>'';
CREATE OR REPLACE FUNCTION ewallet_forbid_change() RETURNS trigger AS $f$
BEGIN RAISE EXCEPTION '%% is immutable', TG_TABLE_NAME USING ERRCODE = '23000'; END $f$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS ledger_immutable ON ledger;
CREATE TRIGGER ledger_immutable BEFORE UPDATE OR DELETE ON ledger FOR EACH ROW EXECUTE FUNCTION ewallet_forbid_change();
DROP TRIGGER IF EXISTS ledger_no_truncate ON ledger;
CREATE TRIGGER ledger_no_truncate BEFORE TRUNCATE ON ledger FOR EACH STATEMENT EXECUTE FUNCTION ewallet_forbid_change();
DROP TRIGGER IF EXISTS reqlog_immutable ON request_log;
CREATE TRIGGER reqlog_immutable BEFORE UPDATE OR DELETE ON request_log FOR EACH ROW EXECUTE FUNCTION ewallet_forbid_change();
DROP TRIGGER IF EXISTS reqlog_no_truncate ON request_log;
CREATE TRIGGER reqlog_no_truncate BEFORE TRUNCATE ON request_log FOR EACH STATEMENT EXECUTE FUNCTION ewallet_forbid_change();
DO $r$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['users','tx','settings','meta','ledger','notifications','audit','login_history','resets','tickets',
      'referrals','commissions','requests','request_log','payment_numbers','payment_number_log','admin_alerts','admin_alert_reads'] LOOP
    EXECUTE format('ALTER TABLE public.%%I ENABLE ROW LEVEL SECURITY', t);
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN
    EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon'; END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN
    EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM authenticated'; END IF;
END $r$;
""" % {"ID": _ID, "TS": _TS}


# ---------------------------------------------------------------- Phase 2: additive schema (shared by SQLite and PostgreSQL)
# Every change is "ADD COLUMN IF MISSING" or "CREATE TABLE IF NOT EXISTS". Nothing is dropped, renamed or rewritten.
# (table, column, sqlite type, postgres type)
V5_COLUMNS = [
    ("users", "blocked_reason", "TEXT", "TEXT"), ("users", "blocked_at", "TEXT", "TEXT"),
    ("notifications", "title_en", "TEXT", "TEXT"), ("notifications", "body_en", "TEXT", "TEXT"),
    ("users", "comm_rate", "REAL", "NUMERIC(7,3)"),
    ("requests", "flow", "TEXT", "TEXT"), ("requests", "commission", "REAL", "NUMERIC(14,2)"), ("requests", "commission_rate", "REAL", "NUMERIC(7,3)"),
    ("requests", "purpose", "TEXT", "TEXT"), ("requests", "purpose_en", "TEXT", "TEXT"), ("requests", "client_decided_at", "TEXT", "TEXT"),
    ("requests", "pay_type", "TEXT", "TEXT"), ("requests", "extra_commission", "REAL", "NUMERIC(14,2)"),
    ("users", "vip_level", "TEXT", "TEXT"), ("users", "vip_rate", "REAL", "NUMERIC(7,3)"), ("tx", "account_type", "TEXT", "TEXT"),
    ("requests", "cancel_fee", "REAL", "NUMERIC(14,2)"), ("requests", "cancel_by", "TEXT", "TEXT"),
    # @@COLUMNS
]
# (name, CREATE TABLE template, [index statements], immutable?)  {ID}=primary key, {BIG}=integer ref, {NUM}=money
V5_TABLES = [
    ("balance_adjustments",
     "CREATE TABLE IF NOT EXISTS balance_adjustments(id {ID}, user_id {BIG} NOT NULL REFERENCES users(id), "
     "direction TEXT NOT NULL CHECK(direction IN('credit','debit')), amount {NUM} NOT NULL CHECK(amount>0), reason TEXT NOT NULL, "
     "reference TEXT, norm_ref TEXT, verified INTEGER DEFAULT 0, ledger_idem TEXT UNIQUE, actor TEXT, actor_id {BIG}, created TEXT NOT NULL)",
     ["CREATE UNIQUE INDEX IF NOT EXISTS ux_adj_ref ON balance_adjustments(norm_ref) WHERE direction='credit' AND norm_ref IS NOT NULL",
      "CREATE INDEX IF NOT EXISTS ix_adj_user ON balance_adjustments(user_id)"], True),
    ("pool_account",
     "CREATE TABLE IF NOT EXISTS pool_account(id {ID}, balance {NUM} NOT NULL DEFAULT 0 CHECK(balance>=0), updated TEXT)", [], False),
    ("pool_ledger",
     "CREATE TABLE IF NOT EXISTS pool_ledger(id {ID}, kind TEXT NOT NULL CHECK(kind IN('fund','payout','reversal','withdraw')), amount {NUM} NOT NULL, "
     "source_type TEXT, holding_account TEXT, reference TEXT, norm_ref TEXT, event_date TEXT, user_id {BIG}, ref_type TEXT, ref_id {BIG}, "
     "ledger_idem TEXT UNIQUE, idem TEXT NOT NULL UNIQUE, balance_after {NUM} NOT NULL, note TEXT, actor TEXT, created TEXT NOT NULL, "
     "CHECK((kind IN('fund','reversal') AND amount>0) OR (kind IN('payout','withdraw') AND amount<0)))",
     ["CREATE UNIQUE INDEX IF NOT EXISTS ux_pool_fund_ref ON pool_ledger(norm_ref) WHERE kind='fund' AND norm_ref IS NOT NULL",
      "CREATE INDEX IF NOT EXISTS ix_pool_created ON pool_ledger(created)", "CREATE INDEX IF NOT EXISTS ix_pool_kind ON pool_ledger(kind)"], True),
    ("company_ledger",
     "CREATE TABLE IF NOT EXISTS company_ledger(id {ID}, kind TEXT NOT NULL CHECK(kind IN('client_payment')), amount {NUM} NOT NULL CHECK(amount>0), "
     "user_id {BIG}, ref_type TEXT, ref_id {BIG}, idem TEXT NOT NULL UNIQUE, note TEXT, actor TEXT, created TEXT NOT NULL)", [], True),
    ("commission_rate_log",
     "CREATE TABLE IF NOT EXISTS commission_rate_log(id {ID}, scope TEXT NOT NULL, user_id {BIG}, old_rate {RATE}, new_rate {RATE}, reason TEXT NOT NULL, "
     "idem TEXT UNIQUE, actor TEXT, actor_id {BIG}, created TEXT NOT NULL)", [], True),
    ("pool_attestations",
     "CREATE TABLE IF NOT EXISTS pool_attestations(id {ID}, declared_balance {NUM} NOT NULL, ledger_balance {NUM} NOT NULL, difference {NUM} NOT NULL, "
     "holding_account TEXT NOT NULL, note TEXT, idem TEXT UNIQUE, actor TEXT, actor_id {BIG}, created TEXT NOT NULL)", [], True),
    ("user_warnings",
     "CREATE TABLE IF NOT EXISTS user_warnings(id {ID}, user_id {BIG} NOT NULL REFERENCES users(id), request_id {BIG}, message TEXT NOT NULL, "
     "admin_id {BIG}, admin TEXT, created TEXT NOT NULL)",
     ["CREATE INDEX IF NOT EXISTS ix_warn_user ON user_warnings(user_id)", "CREATE INDEX IF NOT EXISTS ix_warn_req ON user_warnings(request_id)"], True),
    ("vip_applications",
     "CREATE TABLE IF NOT EXISTS vip_applications(id {ID}, user_id {BIG} NOT NULL REFERENCES users(id), level TEXT NOT NULL, rate {RATE} NOT NULL, "
     "status TEXT NOT NULL DEFAULT 'pending', balance_at {NUM}, deposit_ids TEXT, note TEXT, admin TEXT, admin_id {BIG}, created TEXT NOT NULL, decided TEXT)",
     ["CREATE UNIQUE INDEX IF NOT EXISTS ux_vip_pending ON vip_applications(user_id) WHERE status='pending'",
      "CREATE INDEX IF NOT EXISTS ix_vip_status ON vip_applications(status)"], False),
    ("vip_deposit_use",
     "CREATE TABLE IF NOT EXISTS vip_deposit_use(id {ID}, tx_id {BIG} NOT NULL UNIQUE, app_id {BIG} NOT NULL, user_id {BIG} NOT NULL, created TEXT)",
     ["CREATE INDEX IF NOT EXISTS ix_vipdu_user ON vip_deposit_use(user_id)"], False),
    ("vip_log",
     "CREATE TABLE IF NOT EXISTS vip_log(id {ID}, user_id {BIG} NOT NULL, action TEXT NOT NULL, old_level TEXT, new_level TEXT, rate {RATE}, "
     "reason TEXT, actor TEXT, actor_id {BIG}, created TEXT NOT NULL)", [], True),
    # @@TABLES
]
V5_INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_users_member ON users(member_id)",
    "CREATE INDEX IF NOT EXISTS ix_ledger_created ON ledger(created)",
    "CREATE INDEX IF NOT EXISTS ix_ledger_kind ON ledger(kind)",
    "CREATE INDEX IF NOT EXISTS ix_tx_created ON tx(created)",
    "CREATE INDEX IF NOT EXISTS ix_notif_user ON notifications(user_id)",
    "CREATE INDEX IF NOT EXISTS ix_notif_user_read ON notifications(user_id,is_read)",
    "CREATE INDEX IF NOT EXISTS ix_alert_created ON admin_alerts(created)",
    "CREATE INDEX IF NOT EXISTS ix_login_user ON login_history(user_id)",
    "CREATE INDEX IF NOT EXISTS ix_login_phone ON login_history(phone,created)",
    "CREATE INDEX IF NOT EXISTS ix_audit_actor ON audit(actor_id)",
    "CREATE INDEX IF NOT EXISTS ix_req_user_status ON requests(user_id,status)",
    "CREATE INDEX IF NOT EXISTS ix_tx_kind_status ON tx(kind,status)",
]
V5_NEW_TABLES = [t[0] for t in V5_TABLES]
ID_TABLES = ID_TABLES | frozenset(V5_NEW_TABLES)  # @@IDTABLES_FIX
TABLES = TABLES + V5_NEW_TABLES


def _v5_tpl(sql, pg):
    return sql.format(ID=_ID if pg else "INTEGER PRIMARY KEY", BIG="BIGINT" if pg else "INTEGER", NUM="NUMERIC(14,2)" if pg else "REAL",
                      RATE="NUMERIC(7,3)" if pg else "REAL")


def _v5_pg_ddl():
    out = ["ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s;" % (t, c, p) for t, c, s, p in V5_COLUMNS]
    for name, ddl, idx, immutable in V5_TABLES:
        out.append(_v5_tpl(ddl, True) + ";")
        out += [i + ";" for i in idx]
        if immutable:
            out.append("DROP TRIGGER IF EXISTS %s_immutable ON %s;" % (name, name))
            out.append("CREATE TRIGGER %s_immutable BEFORE UPDATE OR DELETE ON %s FOR EACH ROW EXECUTE FUNCTION ewallet_forbid_change();" % (name, name))
            out.append("DROP TRIGGER IF EXISTS %s_no_truncate ON %s;" % (name, name))
            out.append("CREATE TRIGGER %s_no_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION ewallet_forbid_change();" % (name, name))
    out += [i + ";" for i in V5_INDEXES]
    out.append("DO $r2$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY[%s] LOOP "
               "EXECUTE format('ALTER TABLE public.%%I ENABLE ROW LEVEL SECURITY', t); END LOOP; END $r2$;"
               % ",".join("'%s'" % n for n in V5_NEW_TABLES))
    return "\n".join(out).replace("%%I", "%I")


PG_DDL += "\n" + _v5_pg_ddl()


def _v5_schema_sqlite(c):
    for t, col, sdecl, _p in V5_COLUMNS:
        _addcol(c, t, col, sdecl)
    for name, ddl, idx, immutable in V5_TABLES:
        c.execute(_v5_tpl(ddl, False))
        for i in idx:
            c.execute(i)
        if immutable:
            for ev in ("update", "delete"):
                c.execute("CREATE TRIGGER IF NOT EXISTS %s_no_%s BEFORE %s ON %s BEGIN SELECT RAISE(ABORT,'%s is immutable'); END"
                          % (name, ev, ev.upper(), name, name))
    for i in V5_INDEXES:
        c.execute(i)



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


def _seed_defaults(c):
    defaults = {"bkash": "", "nagad": "", "rocket": "", "min_deposit": "50", "min_withdraw": "100",
                "telegram_url": "", "tg_enabled": "1", "tg_username": "", "tg_label_bn": "", "tg_label_en": "", "welcome": WELCOME_DEFAULT, "commission_note": "", "referral_bonus": "50",
                "site_name": SITE, "default_theme": "auto", "signup_open": "1", "notif_sound": "1", "req_expiry_hours": "24",
                "comm_rate_default": "5", "comm_rate_max": "10", "report_tz_hours": "6", "req_cancel_fee": "100"}
    for k, v in defaults.items():
        c.execute("INSERT OR IGNORE INTO settings VALUES(?,?)", (k, v))
    c.execute("INSERT OR IGNORE INTO pool_account(id,balance,updated) VALUES(1,0,?)", (now(),))  # the single pool row; starts at 0
    c.execute("INSERT OR IGNORE INTO meta VALUES('pool_since',?)", (now(),))  # commission/bonus credits before this moment are "pre-pool legacy"; after it, every one must be pool-backed


def _sync_admin(c):
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


def pg_schema(c):
    """Create / upgrade-in-place (IF NOT EXISTS only) the PostgreSQL schema inside one locked transaction. Never drops data."""
    c.execute("BEGIN IMMEDIATE")
    try:
        c.executescript(PG_DDL)
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise


def migrate_pg():
    c = PGConn(_pg_connect())
    try:
        pg_schema(c)
        c.execute("BEGIN IMMEDIATE")
        try:
            _seed_defaults(c)
            c.execute("INSERT OR REPLACE INTO meta VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
            _sync_admin(c)
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
    finally:
        c.close()


def migrate():
    """Non-destructive, idempotent. Never drops/clears/rewrites existing users, balances, member ids or history."""
    if PG:
        return migrate_pg()
    if STORAGE == "local":
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
    CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY, order_id TEXT NOT NULL,
        user_id INTEGER NOT NULL REFERENCES users(id),
        kind TEXT NOT NULL CHECK(kind IN('deposit','withdraw')), amount REAL NOT NULL CHECK(amount>0),
        method TEXT NOT NULL, pay_number TEXT NOT NULL, instructions TEXT, expires_at TEXT,
        status TEXT NOT NULL DEFAULT 'pending'
            CHECK(status IN('pending','submitted','review','approved','rejected','expired','cancelled')),
        trx TEXT, norm_trx TEXT, screenshot TEXT, submitted_at TEXT,
        created_by_id INTEGER, created_by TEXT, created TEXT NOT NULL,
        decided_by_id INTEGER, decided_by TEXT, decided_at TEXT, reject_reason TEXT, updated TEXT);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_req_order ON requests(order_id);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_req_trx ON requests(norm_trx) WHERE norm_trx IS NOT NULL AND norm_trx<>'';
    CREATE INDEX IF NOT EXISTS ix_req_user ON requests(user_id);
    CREATE INDEX IF NOT EXISTS ix_req_status ON requests(status);
    CREATE TABLE IF NOT EXISTS request_log(id INTEGER PRIMARY KEY, request_id INTEGER NOT NULL REFERENCES requests(id),
        action TEXT NOT NULL, from_status TEXT, to_status TEXT, actor TEXT, actor_id INTEGER, note TEXT,
        created TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS ix_reqlog_req ON request_log(request_id);
    CREATE TRIGGER IF NOT EXISTS reqlog_no_update BEFORE UPDATE ON request_log
        BEGIN SELECT RAISE(ABORT,'request log is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS reqlog_no_delete BEFORE DELETE ON request_log
        BEGIN SELECT RAISE(ABORT,'request log is immutable'); END;
    CREATE TABLE IF NOT EXISTS payment_numbers(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
        method TEXT NOT NULL, account_type TEXT NOT NULL, number TEXT NOT NULL,
        created TEXT NOT NULL, updated TEXT NOT NULL, UNIQUE(user_id, method, number));
    CREATE INDEX IF NOT EXISTS ix_pn_user ON payment_numbers(user_id);
    CREATE TABLE IF NOT EXISTS payment_number_log(id INTEGER PRIMARY KEY, user_id INTEGER, pn_id INTEGER,
        action TEXT, method TEXT, account_type TEXT, number TEXT, old TEXT, created TEXT);
    CREATE TABLE IF NOT EXISTS admin_alerts(id INTEGER PRIMARY KEY, title TEXT, body TEXT, link TEXT, perm TEXT,
        created TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS admin_alert_reads(alert_id INTEGER NOT NULL, admin_id INTEGER NOT NULL,
        PRIMARY KEY(alert_id, admin_id));
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
    _addcol(c, "notifications", "link", "TEXT")
    _v5_schema_sqlite(c)  # Phase 2 additive schema
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
    _seed_defaults(c)
    _ov = c.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
    if _ov and str(_ov[0]).isdigit() and int(_ov[0]) < 4:  # one-time: existing 'admin' staff get the two new permissions
        for r in c.execute("SELECT id,perms FROM users WHERE role='admin'").fetchall():
            have = [p for p in (r["perms"] or "").split(",") if p]
            for p in ("requests", "payment_numbers"):
                if p not in have:
                    have.append(p)
            c.execute("UPDATE users SET perms=? WHERE id=?", (",".join(have), r["id"]))
    c.execute("INSERT OR REPLACE INTO meta VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
    _sync_admin(c)
    c.execute("COMMIT")
    try:  # DB-level duplicate-TrxID guard (skipped if legacy data already has duplicates)
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_dep_trx ON tx(norm_trx) WHERE kind='deposit' AND norm_trx<>''")
    except INTEGRITY:
        pass
    c.close()


def _settings():
    """All global settings (+ the signed-in user's own language key) in ONE query per request instead of one query per setting() call."""
    st = getattr(g, "_st", None)
    if st is None:
        uid = session.get("uid")
        rows = db().execute("SELECT k,v FROM settings WHERE substr(k,1,6)<>'ulang:' OR k=?", ("ulang:%s" % (uid or 0),)).fetchall()
        st = g._st = {r["k"]: r["v"] for r in rows}
    return st


def setting(k, d=""):
    st = _settings()
    if k in st:
        return st[k]
    if k.startswith("ulang:"):
        return d
    return d


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
    bal = "round(balance+CAST(? AS NUMERIC),2)" if PG else "round(balance+?,2)"
    db().execute("UPDATE users SET balance=%s%s WHERE id=?" % (bal, extra), (amount, user_id))
    return True


class atomic:
    def __enter__(self):
        db().execute("BEGIN IMMEDIATE")

    def __exit__(self, et, ev, tb):
        db().execute("ROLLBACK" if et else "COMMIT")
        return False


def notify(user_id, title, body="", link=None, title_en=None, body_en=None):
    db().execute("INSERT INTO notifications(user_id,title,body,created,link,title_en,body_en) VALUES(?,?,?,?,?,?,?)",
                 (user_id, title, body, now(), link, title_en, body_en))


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
    if "uid" in session and not r.headers.get("Cache-Control"):
        r.headers["Cache-Control"] = "no-store"
    try:  # gzip text responses (HTML ~3-5x smaller) when the proxy in front does not already do it
        if (r.status_code == 200 and not r.direct_passthrough and "gzip" in request.headers.get("Accept-Encoding", "")
                and not r.headers.get("Content-Encoding") and r.mimetype in ("text/html", "text/css", "application/javascript", "application/json")):
            data = r.get_data()
            if len(data) > 800:
                r.set_data(gzip.compress(data, 5))
                r.headers["Content-Encoding"] = "gzip"
                r.headers.add("Vary", "Accept-Encoding")
    except Exception:
        pass
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


# ---------------------------------------------------------------- admin second factor (security code)
TF_TTL = 300        # seconds the "password OK, code pending" step stays valid
TF_MAX_FAILS = 5    # wrong codes allowed per 15 minutes (per account and per IP)


def _tf_configured():
    return bool(os.environ.get("ADMIN_2FA_CODE_HASH", "").strip() or os.environ.get("ADMIN_SECURITY_CODE", ""))


def _tf_code_ok(code):
    """The secret lives only in a server-side environment variable (hash preferred); never in code or in the browser."""
    h = os.environ.get("ADMIN_2FA_CODE_HASH", "").strip()
    if h:
        try:
            return check_password_hash(h, code)
        except Exception:
            return False
    s = os.environ.get("ADMIN_SECURITY_CODE", "")
    if not s:
        return False
    return secrets.compare_digest(hashlib.sha256(code.encode("utf-8")).digest(), hashlib.sha256(s.encode("utf-8")).digest())


def _tf_locked(phone, ip):
    since = (datetime.utcnow() - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
    n = q1("SELECT COUNT(*) c FROM login_history WHERE ok=0 AND created>? AND (phone=? OR (ip=? AND SUBSTR(phone,1,4)='2fa:'))",
           (since, "2fa:" + phone, ip))["c"]
    return n >= TF_MAX_FAILS


# ---------------------------------------------------------------- UI shell
@app.context_processor
def _ctx():
    u = me()
    unread = notif_badges().get("*", 0) if u else 0  # same single query that feeds the per-feature badges
    return dict(csrf_token=csrf(), u=u, site=(setting("site_name") or SITE)[:60], unread=unread, money=money, can=has_perm, nb=nb,
                role_name=ROLES.get(u["role"], "") if u else "", tg=tg_url_active(), tg_label=tg_label(), lang=cur_lang(), rk=req_label, rdt=req_dtype, kycs=kyc_status, kycl=KYC_LABEL, ref_reward=referral_reward_amount,
                acct_lbl=ACCT_LABEL, mcol=METHOD_COLOR, xc_ok=xc_ok, is_wd=is_wd, ptl=PAY_TYPE_LABEL)


CSS = """
:root{--b:#1E90FF;--b2:#1668D0;--bt:#0E6BC8;--aq:#DFF7F5;--aq2:#BDEEE8;--aqs:#DFF7F5;--g:#0EA371;--okt:#0B7A50;--bg:#F1FAF9;--card:#fff;--fld:#F7FCFC;--tint:#EEF9F8;--tx:#0B2540;--mut:#5A7587;--ln:#D6EBEA;--rd:#dc2626;--glow:#1E90FF26}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#06121D;--card:#0D1E2F;--fld:#0A1927;--tint:#10283B;--tx:#E4F1F8;--mut:#8CA8BB;--ln:#1A3449;--bt:#5DB6FF;--okt:#34D399;--aq:#0F3A44;--aq2:#165463;--aqs:#0B2A33;--glow:#1E90FF40}}
*{box-sizing:border-box}body{margin:0;background:var(--bg) linear-gradient(180deg,var(--aqs) 0,transparent 340px) no-repeat;color:var(--tx);font-family:'Hind Siliguri',system-ui,sans-serif;padding-bottom:84px}
a{color:inherit;text-decoration:none}
.lgsw{background:#ffffff33;border-radius:99px;padding:3px 11px;font-size:13px;margin-right:12px}.top b{flex:1}
.top{background:linear-gradient(100deg,#1E90FF,#1668D0);color:#fff;padding:14px 16px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:5;box-shadow:0 8px 24px -12px #1E90FF99}
.top .pwa-dl{background:#ffffff33;padding:0;width:30px;height:30px;border-radius:99px;font-size:15px;line-height:1;margin-right:10px;display:inline-flex;align-items:center;justify-content:center}@media(display-mode:standalone){.top .pwa-dl{display:none}}
.top b{font-size:17px}.bell{position:relative;font-size:20px}.dot{position:absolute;top:-6px;right:-8px;background:#ef4444;border-radius:99px;font-size:11px;padding:0 5px}
main{max-width:620px;margin:0 auto;padding:14px}
.card{background:var(--card);border-radius:18px;padding:16px;margin-bottom:14px;box-shadow:0 4px 14px #0A3D6614;border:1px solid var(--ln)}
.hero{background:radial-gradient(120% 90% at 100% 0%,#DFF7F547 0,#DFF7F500 55%),linear-gradient(125deg,#1E90FF,#1668D0);color:#fff;border:0;box-shadow:0 16px 34px -16px #1E90FFB3}
.hero .bal{font-size:34px;font-weight:700;margin:4px 0 12px}.hero small{opacity:.85}
.row{display:flex;gap:10px;flex-wrap:wrap}.row>*{flex:1}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px}.g2 .card{margin:0}
.k{color:var(--mut);font-size:13px}.v{font-size:20px;font-weight:700}
.btn,button{background:linear-gradient(135deg,#1E90FF,#1668D0);color:#fff;border:0;border-radius:13px;padding:11px 16px;font:inherit;font-weight:600;cursor:pointer;display:inline-block;text-align:center;box-shadow:0 4px 10px #1E90FF40;transition:transform .12s ease,box-shadow .12s ease,filter .12s ease}.btn:active,button:active{transform:scale(.97);filter:brightness(.95)}.top button,.hxc button{box-shadow:none}
.btn.g{background:linear-gradient(135deg,#0EA371,#0B7A50);box-shadow:0 4px 10px #0EA37140}.btn.r{background:linear-gradient(135deg,#dc2626,#b91c1c);box-shadow:0 4px 10px #dc262640}.btn.s{background:linear-gradient(135deg,#4E7189,#37586D);box-shadow:0 4px 10px #4E718940}.btn.w{background:#ffffff26}.btn.sm{padding:6px 10px;font-size:13px}
button[disabled]{opacity:.6}
input,select,textarea{width:100%;padding:12px;border:1px solid var(--ln);border-radius:12px;background:var(--fld);color:var(--tx);font:inherit;margin:4px 0 12px;transition:border-color .15s ease,box-shadow .15s ease}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--b);box-shadow:0 0 0 3px var(--glow)}
input::placeholder,textarea::placeholder{color:#8AA2B5}
input[type=checkbox]{width:auto;margin:0 6px 0 0;accent-color:var(--b)}
label{font-size:14px;color:var(--mut)}label.ck{display:block;margin:6px 0;color:var(--tx)}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:8px 6px;border-bottom:1px solid var(--ln);text-align:left}th{font-size:12px;font-weight:700;color:var(--bt);background:var(--tint)}tbody tr:hover td{background:var(--tint)}
.tw{overflow-x:auto}
.pill{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;background:var(--ln)}
.pill.approved,.pill.paid{background:#DDF8EC;color:#0B6B47}.pill.rejected{background:#FFE4E6;color:#991b1b}
.pill.pending,.pill.review,.pill.processing{background:#FEF3C7;color:#92400E}
.msg{padding:11px 14px;border-radius:12px;margin-bottom:12px;background:var(--aq);color:#0B4F6C;box-shadow:inset 3px 0 0 var(--b);word-break:break-word}.msg.error{background:#FFE4E6;color:#991b1b;box-shadow:inset 3px 0 0 #EF4444}
.nav{position:fixed;bottom:0;left:0;right:0;background:var(--card);border-top:1px solid var(--ln);border-radius:22px 22px 0 0;box-shadow:0 -10px 28px -16px #1E90FF59;display:flex;justify-content:space-around;padding:7px 6px calc(9px + env(safe-area-inset-bottom,0px));z-index:6}
.nav a{text-align:center;font-size:11.5px;font-weight:600;color:var(--mut);flex:1;transition:color .2s ease}.nav a.on{color:var(--c2,var(--b));font-weight:800}.nav i{display:flex;align-items:center;justify-content:center;width:48px;height:30px;margin:0 auto 2px;border-radius:15px;font-style:normal;color:var(--c2,var(--mut));background:var(--t,transparent);transition:background .15s ease,color .15s ease}.nav i svg{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;shape-rendering:geometricPrecision}.nav a.on i{color:#fff;background:linear-gradient(135deg,#1E90FF,#1672D6);box-shadow:0 4px 10px -3px #1E90FF80}.nav a.on::before{content:"";position:absolute;top:-7px;left:50%;width:24px;height:3px;margin-left:-12px;border-radius:0 0 4px 4px;background:var(--c2)}.nav a{--c1:#7CC4FF;--c2:#1672D6;--t:#DFF7F5;--s:#1E90FF70}.nav i svg .d{fill:currentColor;fill-opacity:.2}.nav a.on i svg .d{fill-opacity:.3}.nav a.on i svg{stroke-width:2.1}.nav a:active i{transform:scale(.92)}.nav a[href="/history"].on{color:var(--bt)}.nav a[href="/history"].on i{color:var(--bt);background:#BDEEE8}.nav a[href="/history"].on::before{background:#BDEEE8}:root[data-theme=dark] .nav a[href="/history"].on i{color:#9FD6FF;background:#12324D}@media(prefers-color-scheme:dark){:root:not([data-theme=light]) .nav a[href="/history"].on i{color:#9FD6FF;background:#12324D}}@media(prefers-color-scheme:dark){:root:not([data-theme=light]) .nav a.on{color:var(--c1)}:root:not([data-theme=light]) .nav a:not(.on) i{color:var(--c1)}}:root[data-theme=dark] .nav a.on{color:var(--c1)}:root[data-theme=dark] .nav a:not(.on) i{color:var(--c1)}
.welcome{white-space:pre-line;line-height:1.8;font-size:15px;border-left:4px solid var(--b)}
.empty{text-align:center;color:var(--mut);padding:22px}
.foot{color:var(--mut);font-size:12px;text-align:center;padding:10px}
.adm{overflow-x:auto;white-space:nowrap;padding-bottom:4px;margin-bottom:6px}
.adm a.t{display:inline-block;padding:7px 12px;border-radius:99px;background:var(--card);border:1px solid var(--ln);margin:0 4px 8px 0;font-size:14px}
.adm a.t.on{background:linear-gradient(135deg,var(--b),var(--b2));border-color:var(--b2);color:#fff}
.copybox{background:var(--aqs);border:1px dashed var(--aq2);border-radius:12px;padding:10px;word-break:break-all;font-size:14px;margin:6px 0 10px;user-select:all}
.code{font-size:26px;font-weight:700;letter-spacing:3px;text-align:center}
canvas{width:100%;height:170px}
:root[data-theme=dark]{--bg:#06121D;--card:#0D1E2F;--fld:#0A1927;--tint:#10283B;--tx:#E4F1F8;--mut:#8CA8BB;--ln:#1A3449;--bt:#5DB6FF;--okt:#34D399;--aq:#0F3A44;--aq2:#165463;--aqs:#0B2A33;--glow:#1E90FF40}
.dot[hidden]{display:none}
[hidden]{display:none!important}
.adm{display:flex;flex-wrap:wrap;gap:8px;overflow:visible;white-space:normal}.adm a.t{white-space:nowrap}.adm a.t{display:inline-flex;align-items:center;gap:6px;margin:0 0 8px}
.mg{display:grid;grid-template-columns:repeat(auto-fill,minmax(92px,1fr));gap:12px;margin-bottom:14px}
.mt{position:relative;aspect-ratio:1/1;background:var(--card);border:1px solid var(--ln);border-radius:20px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;padding:8px;text-align:center;font-size:13px;font-weight:600;line-height:1.25;box-shadow:0 4px 14px #0A3D6614;-webkit-tap-highlight-color:transparent;transition:transform .12s ease,box-shadow .2s ease}
.mt:active{transform:scale(.95)}.mt:hover{box-shadow:0 6px 18px #0A3D6624}
.mt i{font-style:normal;font-size:28px;width:50px;height:50px;border-radius:16px;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#E8F9F7,#CDEFEB)}
.mt span.lb{display:block;overflow-wrap:anywhere}
.bd2{background:#ef4444;color:#fff;border-radius:99px;font-size:11px;font-weight:700;min-width:20px;height:20px;line-height:20px;text-align:center;padding:0 6px;display:inline-block}
.mt .bd2{position:absolute;top:8px;right:8px}
.nav a{position:relative}.nav a .bd2{position:absolute;top:-4px;left:calc(50% + 13px);min-width:18px;height:18px;line-height:18px;font-size:10px;padding:0 5px}
.pill.submitted{background:#DCEEFF;color:#0B4F9C}.pill.expired,.pill.cancelled{background:#D6EBEA;color:#456170}
.hxt{display:flex;gap:6px;background:var(--card);border:1px solid var(--ln);border-radius:14px;padding:4px;margin-bottom:12px}
.hxt a{flex:1;text-align:center;padding:9px 4px;border-radius:11px;font-weight:600;font-size:14px;color:var(--mut)}
.hxt a.on{background:linear-gradient(135deg,var(--b),var(--b2));color:#fff}
.hxc{background:var(--card);border:1px solid var(--ln);border-radius:14px;padding:2px 12px;margin-bottom:9px;box-shadow:0 2px 8px #0A3D6612}
.hxr{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:5px 0;border-bottom:1px solid var(--ln);font-size:13px;line-height:1.35}
.hxr:last-child{border-bottom:0}
.hxr>span:first-child{color:var(--mut);flex-shrink:0;white-space:nowrap}
.hxr>b{font-weight:600;text-align:right;min-width:0;overflow-wrap:anywhere}
.hxr .neg{color:#dc2626}.hxr .pos{color:var(--okt)}.hxr .na{color:var(--mut);font-weight:400}
.hxr .gft{font-size:14px;margin-right:5px}
.hxr .cmv{display:inline-block;color:#0B6B47;background:#DDF8EC;border:1px solid #7FE3B8;border-radius:99px;padding:1px 10px;font-weight:700}
:root[data-theme=dark] .hxr .cmv{color:#7FE3B8;background:#0F4D3A66;border-color:#0B6B47}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]) .hxr .cmv{color:#7FE3B8;background:#0F4D3A66;border-color:#0B6B47}}
.hxc{cursor:pointer;-webkit-tap-highlight-color:transparent;transition:box-shadow .28s ease,border-color .28s ease,transform .12s ease}
.hxc:active{transform:scale(.994)}.hxc:focus-visible{outline:2px solid var(--b);outline-offset:2px}
.hxr{transition:padding .28s ease,font-size .28s ease}
.hxc.open{border-color:var(--b);box-shadow:0 6px 18px #0A3D6624}.hxc.open>.hxr{padding:8px 0;font-size:14px}
.hxc:not(.open)>.hxr:nth-child(8){border-bottom:0}
.hxd{display:grid;grid-template-rows:0fr;opacity:0;transition:grid-template-rows .3s ease,opacity .3s ease}
.hxd>div{overflow:hidden;min-height:0}.hxc.open .hxd{grid-template-rows:1fr;opacity:1}
body.hx1 .hxc:not(.open),body.hx1 .hxl{display:none}
@media(prefers-reduced-motion:reduce){.hxc,.hxr,.hxd{transition:none}}
.hxr .pill{padding:1px 9px;font-size:12px;font-weight:600;line-height:1.5;white-space:nowrap}
.hxc .pill.pending,.hxc .pill.review,.hxc .pill.processing,.hxc .pill.submitted{background:#FFEFD9;color:#c2410c}
.hxc .pill.approved::before,.hxc .pill.approved::after{content:"✓";color:var(--okt);font-weight:800}
.hxc .pill.approved::before{margin-right:5px}.hxc .pill.approved::after{margin-left:5px}
.hero2{background:radial-gradient(120% 90% at 100% 0%,#DFF7F547 0,#DFF7F500 55%),linear-gradient(125deg,#1E90FF,#1668D0);color:#fff;border-radius:22px;padding:20px;margin-bottom:14px;box-shadow:0 6px 18px #1E90FF47}
.menu{padding:6px 8px}
.li{display:flex;align-items:center;gap:14px;width:100%;padding:12px 8px;background:transparent;color:var(--tx);border:0;border-radius:0;font:inherit;text-align:left;cursor:pointer}
.li+.li,form+.li,.li+form{border-top:1px solid var(--ln)}
.li .ic{width:38px;height:38px;flex:0 0 38px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:19px;background:linear-gradient(135deg,#E8F9F7,#CDEFEB)}
.li .lt{flex:1}.li .ch{color:var(--mut);font-size:22px}.li .bd{background:#ef4444;color:#fff;border-radius:99px;font-size:11px;padding:1px 8px}
.li.out{color:var(--rd)}
.hero .btn.w{background:linear-gradient(180deg,#fff 0%,#DFF7F5 100%);color:#0B4A8F;font-weight:700;font-size:13px;line-height:1.25;border-radius:14px;padding:11px 4px;border:1px solid #ffffffd9;box-shadow:0 9px 18px -5px #06304F80,inset 0 1px 0 #fff,inset 0 -1px 0 #BFE9E4;display:flex;align-items:center;justify-content:center;gap:5px}.qa{display:grid;grid-template-columns:1fr 1fr;gap:10px}.qb{position:relative;display:flex;align-items:center;gap:10px;min-height:55px;padding:8.5px 10.5px;border-radius:15px;color:#0B3556;background:linear-gradient(160deg,#FFFFFF 0%,#E8F9F7 100%);border:1px solid #CBEBE7;box-shadow:0 1px 2px #0A5A8C1f,0 8px 16px -8px #0A5A8C40,inset 0 1px 0 #fff,inset 0 -1px 0 #CFEFEB;-webkit-tap-highlight-color:transparent;touch-action:manipulation;transition:transform .12s ease-out,box-shadow .15s ease-out,background .15s ease-out,border-color .15s ease-out}.qb:active{transform:scale(.97);background:linear-gradient(160deg,#E8F9F7 0%,#D3F3EF 100%);border-color:#A9DED8;box-shadow:0 1px 3px -1px #0A5A8C40,inset 0 1px 2px #1672D61f}@media(hover:hover){.qb:hover{border-color:#B4E4DE;box-shadow:0 2px 4px #0A5A8C1f,0 12px 20px -10px #0A5A8C59,inset 0 1px 0 #fff,inset 0 -1px 0 #CFEFEB;transform:translateY(-1px)}}.qb:focus-visible{outline:2px solid #fff;outline-offset:2px}.qi{flex:none;width:35px;height:35px;border-radius:11px;display:flex;align-items:center;justify-content:center;background:linear-gradient(145deg,#F0FCFB 0%,#DFF7F5 55%,#CDEFEB 100%);color:var(--qc,#1672D6);box-shadow:inset 0 0 0 1px #1672D61f,0 2px 4px -1px #1672D633,inset 0 1px 0 #ffffffd9;transition:transform .12s ease-out}.qb:active .qi{transform:scale(.94)}.qi svg{width:17.5px;height:17.5px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}.ql{flex:1;min-width:0;font-weight:700;font-size:12.5px;line-height:1.25;letter-spacing:.1px;overflow-wrap:anywhere}.qn{position:absolute;top:-6px;right:-3px;min-width:20px;height:20px;line-height:20px;padding:0 6px;border-radius:99px;background:#ef4444;color:#fff;font-size:11.5px;font-weight:700;text-align:center;box-shadow:0 0 0 2px #fff}.qb{--qc:#1672D6}@media(max-width:340px){.qb{gap:8px;padding:8px}.qi{width:30px;height:30px}.ql{font-size:11.5px}}@media(prefers-reduced-motion:reduce){.qb{transition:none}.qb:hover,.qb:active{transform:none}}
.hero .btn.w:active{box-shadow:0 2px 6px #0A3D6640}
.tkr{display:flex;align-items:center;gap:10px;margin:0 0 12px;padding:7px 12px 7px 7px;border-radius:16px;background:var(--card);border:1px solid var(--ln);box-shadow:0 4px 14px #0A3D6614;overflow:hidden}
.tkr-b{flex:none;width:30px;height:30px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:16px;background:linear-gradient(135deg,#1E90FF,#1668D0);box-shadow:0 3px 8px #1E90FF55}
.tkr-w{flex:1;min-width:0;overflow:hidden;-webkit-mask-image:linear-gradient(90deg,transparent,#000 5%,#000 95%,transparent);mask-image:linear-gradient(90deg,transparent,#000 5%,#000 95%,transparent)}
.tkr-t{display:inline-block;white-space:nowrap;padding-left:100%;font-weight:600;font-size:14px;color:var(--tx);animation:tkr var(--d,16s) linear infinite;will-change:transform}
.tkr:active .tkr-t{animation-play-state:paused}
@keyframes tkr{from{transform:translateX(0)}to{transform:translateX(-100%)}}
@media(prefers-reduced-motion:reduce){.tkr-t{animation:none;padding-left:0;white-space:normal}}
.fab{position:fixed;right:16px;bottom:88px;width:54px;height:54px;border-radius:50%;background:linear-gradient(135deg,#1E90FF,#1668D0);color:#fff;display:flex;align-items:center;justify-content:center;font-size:25px;box-shadow:0 6px 18px #0A3D6655;z-index:7}
details.set{padding:0}details.set summary{padding:14px 16px;font-weight:600;cursor:pointer;list-style:none}
details.set summary::-webkit-details-marker{display:none}details.set>form,details.set>div{padding:0 16px 16px}
.new{border-left:4px solid var(--b)}
.hl{white-space:pre-line}
img.shot{max-width:100%;border-radius:12px;margin:8px 0;border:1px solid var(--ln)}
#ld{position:fixed;top:0;left:0;height:3px;width:0;opacity:0;background:linear-gradient(90deg,#1E90FF,#1668D0);z-index:99;transition:width .35s ease,opacity .25s ease;pointer-events:none;border-radius:0 3px 3px 0;box-shadow:0 0 8px #1E90FF88}
.sp{display:inline-block;width:14px;height:14px;border:2px solid #ffffff66;border-top-color:#fff;border-radius:50%;vertical-align:-2px;animation:spn .7s linear infinite}
@keyframes spn{to{transform:rotate(360deg)}}
@media(prefers-reduced-motion:reduce){.sp{animation-duration:1.6s}#ld{transition:none}}
.mg{grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:12px}
.mt{border-radius:22px;padding:6px;gap:7px;font-size:12.5px}
.mt i{width:48px;height:48px;font-size:26px;border-radius:16px}
.mt .bd2{top:7px;right:7px}
.cc-h{margin:2px 2px 4px;font-size:18px;font-weight:700}.cc-sub{margin:0 2px 12px;color:var(--mut);font-size:13px}.li{min-height:62px;box-sizing:border-box}button.li{box-shadow:none;margin:0;font-weight:400;text-align:left;line-height:1.4;-webkit-appearance:none;appearance:none;transition:none}button.li:active{transform:none;filter:none}details.cg summary::after{content:"▾";float:right;color:var(--mut)}details.cg[open] summary::after{content:"▴"}.gdot{display:none;width:9px;height:9px;border-radius:50%;background:#ef4444;margin-left:8px;vertical-align:middle}details.cg:has(.bd2:not([hidden])) .gdot{display:inline-block}details.cg .mg{margin-bottom:0}
/* ===== Dodger Blue + Soft Aqua theme extensions ===== */
::selection{background:#1E90FF33}
@media(hover:hover){.btn:hover,button:hover{filter:brightness(1.06)}.adm a.t:hover{border-color:var(--b)}.mt:hover{border-color:var(--aq2)}}
.btn:focus-visible,button:focus-visible,.adm a.t:focus-visible{outline:2px solid var(--b);outline-offset:2px}
:root[data-theme=dark] .top{background:linear-gradient(100deg,#1B7FE0,#1259B0)}:root[data-theme=dark] .hero{background:radial-gradient(120% 90% at 100% 0%,#DFF7F52e 0,#DFF7F500 55%),linear-gradient(125deg,#1B7FE0,#1259B0);box-shadow:0 16px 34px -16px #000a}:root[data-theme=dark] .hero2{background:radial-gradient(120% 90% at 100% 0%,#DFF7F52e 0,#DFF7F500 55%),linear-gradient(125deg,#1B7FE0,#1259B0)}:root[data-theme=dark] .nav a{--t:#1E90FF26}:root[data-theme=dark] .mt i,:root[data-theme=dark] .li .ic{background:linear-gradient(135deg,#123B4A,#0F2F44)}:root[data-theme=dark] .pill.approved,:root[data-theme=dark] .pill.paid{background:#0F3D31;color:#6EE7B7}:root[data-theme=dark] .pill.rejected{background:#4A1D24;color:#FCA5A5}:root[data-theme=dark] .pill.pending,:root[data-theme=dark] .pill.review,:root[data-theme=dark] .pill.processing{background:#4A3512;color:#FCD34D}:root[data-theme=dark] .pill.submitted{background:#0F3555;color:#8CCBFF}:root[data-theme=dark] .pill.expired,:root[data-theme=dark] .pill.cancelled{background:#1A3449;color:#9DB4C4}:root[data-theme=dark] .hxc .pill.pending,:root[data-theme=dark] .hxc .pill.review,:root[data-theme=dark] .hxc .pill.processing,:root[data-theme=dark] .hxc .pill.submitted{background:#4A3512;color:#FCD34D}:root[data-theme=dark] .hxc.hy .hy-tt .pill{background:#1A3449;color:#9DB4C4}:root[data-theme=dark] .hxc.hy .hy-tt .pill.pending,:root[data-theme=dark] .hxc.hy .hy-tt .pill.review,:root[data-theme=dark] .hxc.hy .hy-tt .pill.processing,:root[data-theme=dark] .hxc.hy .hy-tt .pill.submitted{background:#4A3512;color:#FCD34D}:root[data-theme=dark] .hxc.hy .hy-tt .pill.approved,:root[data-theme=dark] .hxc.hy .hy-tt .pill.paid{background:#0F3D31;color:#6EE7B7}:root[data-theme=dark] .hxc.hy .hy-tt .pill.rejected{background:#4A1D24;color:#FCA5A5}:root[data-theme=dark] .msg{background:#0F3A44;color:#A8EDE6}:root[data-theme=dark] .msg.error{background:#4A1D24;color:#FCA5A5}:root[data-theme=dark] .au-msg{background:#0F3D31;color:#6EE7B7}:root[data-theme=dark] .au-msg.error{background:#4A1D24;color:#FCA5A5}:root[data-theme=dark] .ur-b{background:#1A3449;color:#9DB4C4}:root[data-theme=dark] .ur-b.pending,:root[data-theme=dark] .ur-b.review{background:#4A3512;color:#FCD34D}:root[data-theme=dark] .ur-b.submitted{background:#0F3555;color:#8CCBFF}:root[data-theme=dark] .ur-b.approved{background:#0F3D31;color:#6EE7B7}:root[data-theme=dark] .ur-b.rejected{background:#4A1D24;color:#FCA5A5}:root[data-theme=dark] .ur-b.expired,:root[data-theme=dark] .ur-b.cancelled{background:#1A3449;color:#9DB4C4}:root[data-theme=dark] body.auth{background:#0A2A4A}:root[data-theme=dark] body.auth::before{background:radial-gradient(90% 60% at 100% 0%,#DFF7F522,#DFF7F500 60%),linear-gradient(165deg,#0F5FB5,#082F57)}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]) .top{background:linear-gradient(100deg,#1B7FE0,#1259B0)}:root:not([data-theme=light]) .hero{background:radial-gradient(120% 90% at 100% 0%,#DFF7F52e 0,#DFF7F500 55%),linear-gradient(125deg,#1B7FE0,#1259B0);box-shadow:0 16px 34px -16px #000a}:root:not([data-theme=light]) .hero2{background:radial-gradient(120% 90% at 100% 0%,#DFF7F52e 0,#DFF7F500 55%),linear-gradient(125deg,#1B7FE0,#1259B0)}:root:not([data-theme=light]) .nav a{--t:#1E90FF26}:root:not([data-theme=light]) .mt i,:root:not([data-theme=light]) .li .ic{background:linear-gradient(135deg,#123B4A,#0F2F44)}:root:not([data-theme=light]) .pill.approved,:root:not([data-theme=light]) .pill.paid{background:#0F3D31;color:#6EE7B7}:root:not([data-theme=light]) .pill.rejected{background:#4A1D24;color:#FCA5A5}:root:not([data-theme=light]) .pill.pending,:root:not([data-theme=light]) .pill.review,:root:not([data-theme=light]) .pill.processing{background:#4A3512;color:#FCD34D}:root:not([data-theme=light]) .pill.submitted{background:#0F3555;color:#8CCBFF}:root:not([data-theme=light]) .pill.expired,:root:not([data-theme=light]) .pill.cancelled{background:#1A3449;color:#9DB4C4}:root:not([data-theme=light]) .hxc .pill.pending,:root:not([data-theme=light]) .hxc .pill.review,:root:not([data-theme=light]) .hxc .pill.processing,:root:not([data-theme=light]) .hxc .pill.submitted{background:#4A3512;color:#FCD34D}:root:not([data-theme=light]) .hxc.hy .hy-tt .pill{background:#1A3449;color:#9DB4C4}:root:not([data-theme=light]) .hxc.hy .hy-tt .pill.pending,:root:not([data-theme=light]) .hxc.hy .hy-tt .pill.review,:root:not([data-theme=light]) .hxc.hy .hy-tt .pill.processing,:root:not([data-theme=light]) .hxc.hy .hy-tt .pill.submitted{background:#4A3512;color:#FCD34D}:root:not([data-theme=light]) .hxc.hy .hy-tt .pill.approved,:root:not([data-theme=light]) .hxc.hy .hy-tt .pill.paid{background:#0F3D31;color:#6EE7B7}:root:not([data-theme=light]) .hxc.hy .hy-tt .pill.rejected{background:#4A1D24;color:#FCA5A5}:root:not([data-theme=light]) .msg{background:#0F3A44;color:#A8EDE6}:root:not([data-theme=light]) .msg.error{background:#4A1D24;color:#FCA5A5}:root:not([data-theme=light]) .au-msg{background:#0F3D31;color:#6EE7B7}:root:not([data-theme=light]) .au-msg.error{background:#4A1D24;color:#FCA5A5}:root:not([data-theme=light]) .ur-b{background:#1A3449;color:#9DB4C4}:root:not([data-theme=light]) .ur-b.pending,:root:not([data-theme=light]) .ur-b.review{background:#4A3512;color:#FCD34D}:root:not([data-theme=light]) .ur-b.submitted{background:#0F3555;color:#8CCBFF}:root:not([data-theme=light]) .ur-b.approved{background:#0F3D31;color:#6EE7B7}:root:not([data-theme=light]) .ur-b.rejected{background:#4A1D24;color:#FCA5A5}:root:not([data-theme=light]) .ur-b.expired,:root:not([data-theme=light]) .ur-b.cancelled{background:#1A3449;color:#9DB4C4}:root:not([data-theme=light]) body.auth{background:#0A2A4A}:root:not([data-theme=light]) body.auth::before{background:radial-gradient(90% 60% at 100% 0%,#DFF7F522,#DFF7F500 60%),linear-gradient(165deg,#0F5FB5,#082F57)}}
"""

JS = """
var _ldT=null;
function ldShow(){var b=document.getElementById('ld');if(!b)return;clearTimeout(_ldT);b.style.opacity='1';b.style.width='12%';
 _ldT=setTimeout(function(){b.style.width='70%'},120);setTimeout(function(){if(b.style.opacity==='1')b.style.width='88%'},1500)}
function ldHide(){var b=document.getElementById('ld');if(!b)return;clearTimeout(_ldT);b.style.width='100%';setTimeout(function(){b.style.opacity='0';setTimeout(function(){b.style.width='0'},250)},180)}
document.addEventListener('submit',function(e){var f=e.target,c=f.dataset.confirm;
 if(c&&!confirm(c)){e.preventDefault();return}
 ldShow();
 setTimeout(function(){f.querySelectorAll('button').forEach(function(b){b.style.minWidth=b.offsetWidth+'px';b.disabled=true;b.dataset.h=b.innerHTML;b.innerHTML='<span class="sp"></span>'})},0);});
window.addEventListener('pageshow',function(e){if(e.persisted){ldHide();document.querySelectorAll('button[data-h]').forEach(function(b){b.disabled=false;b.innerHTML=b.dataset.h;b.removeAttribute('data-h')})}});
(function(){var seq=0,SKIPS=['/login','/signup','/forgot','/static','/shot','/lang','/logout','/manifest.json','/service-worker.js','/assets','/healthz','/admin/backup'];
 function skip(p){return SKIPS.some(function(x){return p===x||p.indexOf(x+'/')===0})}
 function ok(a,e){if(e.defaultPrevented||e.button||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey)return false;
  if(a.target&&a.target!=='_self'||a.hasAttribute('download')||a.dataset.copy!==undefined||a.dataset.share!==undefined)return false;
  var u;try{u=new URL(a.href,location.href)}catch(x){return false}
  if(u.origin!==location.origin||skip(u.pathname))return false;
  if(u.pathname===location.pathname&&u.search===location.search&&u.hash)return false;return u}
 function swap(html,url,push){var d=new DOMParser().parseFromString(html,'text/html');if(!d.body||!d.querySelector('main'))return false;
  document.title=d.title;document.documentElement.lang=d.documentElement.lang;
  var nb=d.body;document.body.className=nb.className;
  ['poll','snd'].forEach(function(k){if(nb.dataset[k]!==undefined)document.body.dataset[k]=nb.dataset[k];else delete document.body.dataset[k]});
  var cur=document.body,keep=document.getElementById('ld');
  ['.top','main','.nav','.fab'].forEach(function(sel){var o=cur.querySelector(sel),n=nb.querySelector(sel);
   if(o&&n)o.replaceWith(document.importNode(n,true));else if(o&&!n)o.remove();else if(!o&&n){var m=cur.querySelector('main');if(sel==='.top')cur.insertBefore(document.importNode(n,true),cur.firstChild);else if(sel==='main'){}else m.after(document.importNode(n,true))}});
  document.querySelectorAll('main script').forEach(function(o){var n=document.createElement('script');n.textContent=o.textContent;o.replaceWith(n)});
  if(push)history.pushState({},'',url);window.scrollTo(0,0);paintToggles();
  if(typeof pollNotif==='function')pollNotif();return true}
 function go(url,push){var my=++seq;ldShow();
  fetch(url,{credentials:'same-origin',headers:{'X-Soft-Nav':'1'}}).then(function(r){
   var ct=r.headers.get('content-type')||'';
   var rp=new URL(r.url).pathname;if(ct.indexOf('text/html')<0||(r.redirected&&(rp==='/login'||rp==='/signup'))){location.href=url;return null}
   return r.text().then(function(t){return{t:t,u:r.url}})}).then(function(x){
   if(!x||my!==seq)return;
   if(!swap(x.t,x.u||url,push)){location.href=url;return}ldHide()}).catch(function(){location.href=url})}
 document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a[href]');if(!a)return;var u=ok(a,e);if(!u)return;
  e.preventDefault();go(u.href,true)});
 window.addEventListener('popstate',function(){go(location.href,false)})})();
function copyText(t,btn){var done=function(){if(btn){var o=btn.dataset.o||btn.textContent;btn.dataset.o=o;btn.textContent='✅ কপি হয়েছে';setTimeout(function(){btn.textContent=o},1800)}};
 if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(done,function(){fb()})}else{fb()}
 function fb(){var a=document.createElement('textarea');a.value=t;a.style.position='fixed';a.style.opacity='0';document.body.appendChild(a);a.select();
  try{document.execCommand('copy');done()}catch(x){prompt('কপি করুন:',t)}document.body.removeChild(a)}}
document.addEventListener('click',function(e){var b=e.target.closest('[data-copy]');if(b){e.preventDefault();copyText(b.dataset.copy,b);return}
 b=e.target.closest('[data-share]');if(b){e.preventDefault();var t=b.dataset.text,u=b.dataset.share;
  if(navigator.share){navigator.share({title:document.title,text:t,url:u}).catch(function(){})}else{copyText(t+' '+u,b)}}});
function bars(id,labels,series,colors){var c=document.getElementById(id);if(!c)return;var w=c.width=c.offsetWidth*2,h=c.height=340,x=c.getContext('2d');
 var mx=1;series.forEach(function(s){s.forEach(function(v){mx=Math.max(mx,v)})});var n=labels.length,gw=(w-40)/n;
 x.font='20px sans-serif';x.fillStyle='#8AA2B5';
 for(var i=0;i<n;i++){series.forEach(function(s,j){var bh=(h-60)*s[i]/mx,bw=gw/(series.length+1);x.fillStyle=colors[j];x.fillRect(30+i*gw+j*bw,h-30-bh,bw-3,bh)});
  if(n<=16||i%2==0){x.fillStyle='#8AA2B5';x.fillText(labels[i],30+i*gw,h-8)}}}
function lsGet(k){try{return localStorage.getItem(k)}catch(e){return null}}
function lsSet(k,v){try{localStorage.setItem(k,v)}catch(e){}}
function curTheme(){var t=document.documentElement.getAttribute('data-theme');if(t)return t;
 return(window.matchMedia&&matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light'}
function paintToggles(){var a=document.getElementById('thv');if(a)a.textContent=curTheme()==='dark'?'চালু':'বন্ধ';
 var b=document.getElementById('sndv');if(b)b.textContent=sndOn()?'চালু':'বন্ধ';
 var c=document.getElementById('bnv');if(c)c.textContent=nfLabel()}
function toggleTheme(){var n=curTheme()==='dark'?'light':'dark';document.documentElement.setAttribute('data-theme',n);lsSet('theme',n);paintToggles()}
var _ac=null;
function sndOn(){var v=lsGet('snd');if(v===null)v=(document.body&&document.body.dataset.snd)||'1';return v==='1'}
function beep(){try{var C=window.AudioContext||window.webkitAudioContext;if(!C)return;_ac=_ac||new C();var o=_ac.createOscillator(),g=_ac.createGain();
 o.connect(g);g.connect(_ac.destination);o.frequency.value=880;g.gain.value=.08;o.start();o.stop(_ac.currentTime+.18)}catch(e){}}
function setSnd(v){lsSet('snd',v?'1':'0');paintToggles();if(v){unlockAudio();playChime().then(function(ok){if(!ok)beep()})}}
/* ===== browser notifications + chime (additive; the in-app bell/badges above are untouched) ===== */
var _au=null,_auOk=false;
function chimeEl(){if(!_au){_au=new Audio('/static/sounds/notification.mp3?v=1');_au.preload='auto';_au.volume=1}return _au}
function unlockAudio(){if(_auOk)return;try{var a=chimeEl();a.muted=true;var p=a.play();
 var done=function(){a.pause();a.currentTime=0;a.muted=false;_auOk=true};
 if(p&&p.then)p.then(done,function(){a.muted=false});else done()}catch(e){}}
function playChime(){try{var a=chimeEl();a.muted=false;a.currentTime=0;var p=a.play();
 return p&&p.then?p.then(function(){return true},function(){return false}):Promise.resolve(true)}catch(e){return Promise.resolve(false)}}
function nfSupported(){return 'Notification' in window&&'serviceWorker' in navigator}
function nfPerm(){return nfSupported()?Notification.permission:'unsupported'}
function nfActive(){return nfPerm()==='granted'&&lsGet('nf')!=='0'}
function nfEn(){return document.documentElement.lang==='en'}
function nfLabel(){var p=nfPerm(),en=nfEn();
 if(p==='unsupported')return en?'Not supported':'সাপোর্টেড নয়';
 if(p==='denied')return en?'Blocked':'ব্লক করা';
 if(p==='granted')return nfActive()?(en?'On':'চালু'):(en?'Off':'বন্ধ');
 return en?'Tap to enable':'চালু করুন'}
function nfShow(it,site,quiet){if(!nfActive())return;
 var o={body:it.body||'',icon:'/static/icons/icon-192.png',tag:'ewn-'+it.id,renotify:false,silent:!!quiet,data:{url:it.url||'/',id:it.id}},t=(site?site+' · ':'')+(it.title||'');
 var fb=function(){try{new Notification(t,o)}catch(e){}};
 try{navigator.serviceWorker.getRegistration('/').then(function(r){if(r&&r.showNotification)return r.showNotification(t,o);fb()}).catch(fb)}catch(e){fb()}}
function nfNotify(items,site){if(!items||!items.length)return;
 var top=items[items.length-1],sk='nsnd:'+nfNotify.uid,heard=parseInt(lsGet(sk)||'0',10)||0,go=function(q){items.forEach(function(it){nfShow(it,site,q)})};
 if(!sndOn()){go(true);return}  // sound switched off in the site: native notifications stay silent
 if(top.id<=heard){go(true);return}  // another tab already played the chime for this notification
 lsSet(sk,String(top.id));  // claimed before playing: the sound plays once per notification
 playChime().then(function(ok){go(ok)})}  // if the browser blocked the chime, let the OS notification sound play instead
function nfCheck(j){if(!j||j.uid==null)return;var key='nl:'+j.uid,st=lsGet(key),seen=st===null?NaN:parseInt(st,10);
 if(isNaN(seen)){lsSet(key,String(j.latest));return}  // first run on this device: remember the current position, never replay old notifications
 if(j.latest<seen){lsSet(key,String(j.latest));return}
 if(j.latest===seen)return;
 lsSet(key,String(j.latest));  // claim first so a second open tab does not notify the same ids again
 if(!nfActive()&&!sndOn())return;
 fetch('/api/notif/new?after='+seen,{credentials:'same-origin',cache:'no-store'}).then(function(r){return r.ok?r.json():null}).then(function(n){
  if(!n||!n.items||!n.items.length){return}
  nfNotify.uid=j.uid;
  if(n.count>n.items.length){var top=n.items[n.items.length-1];n.items=[{id:top.id,title:nfEn()?'New notifications':'নতুন নোটিফিকেশন',body:nfEn()?(n.count+' new notifications'):(n.count+'টি নতুন নোটিফিকেশন'),url:'/'+(n.admin?'admin/alerts':'notifications')}]}
  nfNotify(n.items,n.site)}).catch(function(){lsSet(key,String(seen))})}
function enableBrowserNotif(){unlockAudio();
 if(!nfSupported()){alert(nfEn()?'This browser does not support notifications. On iPhone, add the site to the Home Screen first.':'এই ব্রাউজারে নোটিফিকেশন সাপোর্ট নেই। iPhone-এ আগে সাইটটি Home Screen-এ যুক্ত করুন।');return}
 var p=Notification.permission;
 if(p==='denied'){alert(nfEn()?'Notifications are blocked for this site. Allow them from the browser/site settings, then try again.':'এই সাইটের নোটিফিকেশন ব্লক করা আছে। ব্রাউজারের সাইট সেটিংস থেকে অনুমতি দিয়ে আবার চেষ্টা করুন।');return}
 if(p==='granted'){if(lsGet('nf')==='0'){lsSet('nf','1');paintToggles();nfTest()}else{lsSet('nf','0');paintToggles()}return}
 lsSet('nfAsk','1');
 var done=function(r){if(r==='granted'){lsSet('nf','1');nfTest()}paintToggles()};
 try{var q=Notification.requestPermission(done);if(q&&q.then)q.then(done)}catch(e){}}
function nfTest(){var site=(document.querySelector('.top b')||{}).textContent||'';
 var it={id:'t'+Date.now(),title:nfEn()?'Notifications enabled':'নোটিফিকেশন চালু হয়েছে',body:nfEn()?'You will now see alerts here.':'এখন থেকে নতুন নোটিফিকেশন এখানে দেখাবে।',url:'/'};
 (sndOn()?playChime():Promise.resolve(false)).then(function(ok){nfShow(it,site,ok)})}
(function(){var first=function(){document.removeEventListener('click',first,true);document.removeEventListener('keydown',first,true);document.removeEventListener('touchend',first,true);
 unlockAudio();  // one-time sound activation: the first tap anywhere lets the page play the chime later
 if(document.body&&document.body.dataset.poll&&nfSupported()&&Notification.permission==='default'&&lsGet('nfAsk')===null){lsSet('nfAsk','1');  // asked once, never again automatically
  try{var q=Notification.requestPermission(function(r){if(r==='granted')lsSet('nf','1');paintToggles()});if(q&&q.then)q.then(function(r){if(r==='granted')lsSet('nf','1');paintToggles()})}catch(e){}}};
 document.addEventListener('click',first,true);document.addEventListener('keydown',first,true);document.addEventListener('touchend',first,true);
 document.addEventListener('visibilitychange',function(){if(!document.hidden&&typeof pollNotif==='function')pollNotif()})})();
var _last=null;
function pollNotif(){if(document.hidden&&!nfActive())return;  // background tabs keep polling only when browser notifications are on
 fetch('/api/notif',{credentials:'same-origin',cache:'no-store'}).then(function(r){return r.ok?r.json():null}).then(function(j){
  if(!j)return;var d=document.getElementById('nd');if(d){d.textContent=j.unread;d.hidden=!j.unread}
  if(j.badges){document.querySelectorAll('[data-bd]').forEach(function(el){var n=j.badges[el.dataset.bd]||0;el.textContent=n>99?'99+':n;el.hidden=!n})}
  nfCheck(j);_last=j.latest}).catch(function(){})}
function applyBadges(j){var d=document.getElementById('nd');if(d){d.textContent=j.unread;d.hidden=!j.unread}
 if(j.badges){document.querySelectorAll('[data-bd]').forEach(function(el){var n=j.badges[el.dataset.bd]||0;el.textContent=n>99?'99+':n;el.hidden=!n})}}
var _rq=Promise.resolve();
function markRead(el){if(!el||el.dataset.rd==='1')return;el.dataset.rd='1';el.classList.remove('new');
 var box=el.closest('[data-csrf]'),b=new URLSearchParams();b.set('id',el.dataset.nid);b.set('_csrf',box?box.dataset.csrf:'');
 _rq=_rq.then(function(){return fetch('/api/notif/read',{method:'POST',body:b,credentials:'same-origin',keepalive:true}).then(function(r){return r.ok?r.json():null}).then(function(j){if(j)applyBadges(j)}).catch(function(){})})}
function autoRead(){var box=document.getElementById('nlist');if(!box)return;var els=box.querySelectorAll('[data-nid]');
 if(!('IntersectionObserver' in window)){els.forEach(function(e){markRead(e)});return}
 var t={},io=new IntersectionObserver(function(es){es.forEach(function(en){var id=en.target.dataset.nid;
  if(en.isIntersecting){if(!t[id])t[id]=setTimeout(function(){markRead(en.target);io.unobserve(en.target)},700)}
  else if(t[id]){clearTimeout(t[id]);delete t[id]}})},{threshold:[.5]});
 els.forEach(function(e){io.observe(e)})}
paintToggles();
if(document.body&&document.body.dataset.poll){pollNotif();setInterval(pollNotif,20000)}
function pwTog(b){var w=b.closest('.au-f'),i=w&&w.querySelector('input');if(!i)return;var show=i.type==='password';
 i.type=show?'text':'password';b.classList.toggle('on',show);b.setAttribute('aria-pressed',show?'true':'false')}
document.addEventListener('click',function(e){var b=e.target.closest&&e.target.closest('[data-pwtoggle]');if(!b)return;e.preventDefault();pwTog(b)});
document.addEventListener('keydown',function(e){var t=e.target;if((e.key==='Enter'||e.key===' ')&&t.matches&&t.matches('[data-pwtoggle]')){e.preventDefault();pwTog(t)}});
document.addEventListener('input',function(e){var i=e.target;if(!i.matches||!i.matches('[data-pwmeter]'))return;
 var w=i.closest('.au-fw'),m=w&&w.querySelector('.au-meter');if(!m)return;var v=i.value,n=0;
 if(v.length>=6)n++;if(v.length>=9)n++;if(/[A-Za-z]/.test(v)&&/[0-9]/.test(v))n++;if(/[^A-Za-z0-9]/.test(v)||(/[a-z]/.test(v)&&/[A-Z]/.test(v)))n++;
 if(v.length)n=Math.max(1,n);m.dataset.s=n;var t=m.querySelector('em'),en=document.documentElement.lang==='en';
 if(t)t.textContent=n?(en?['','Weak','Fair','Good','Strong']:['','দুর্বল','মোটামুটি','ভালো','শক্তিশালী'])[n]:''});
"""

BASE = """<!doctype html><html lang="{{lang}}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{site}}</title>
<link rel="manifest" href="/manifest.json"><meta name="theme-color" content="#1E90FF"><meta name="mobile-web-app-capable" content="yes">
<meta name="application-name" content="E-Wallet Support"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-title" content="E-Wallet">
<link rel="icon" type="image/png" sizes="192x192" href="/static/icons/icon-192.png"><link rel="icon" type="image/png" sizes="512x512" href="/static/icons/icon-512.png"><link rel="apple-touch-icon" sizes="180x180" href="/static/icons/apple-touch-icon.png">
<script>(function(){var dp=null,w=window;
w.addEventListener('beforeinstallprompt',function(e){e.preventDefault();dp=e});
w.addEventListener('appinstalled',function(){dp=null;var b=document.getElementById('pwa-install');if(b)b.style.display='none'});
document.addEventListener('DOMContentLoaded',function(){var b=document.getElementById('pwa-install');if(!b)return;
if(navigator.standalone===true){b.style.display='none';return}
b.addEventListener('click',function(){if(dp){var p=dp;dp=null;p.prompt();return}
alert(document.documentElement.lang==='en'?'To install: open the Chrome menu (\u22EE) and tap "Install app" or "Add to Home screen".':'ইনস্টল করতে: Chrome মেনু (\u22EE) খুলে "Install app" বা "Add to Home screen" চাপুন।')})});
if('serviceWorker' in navigator)w.addEventListener('load',function(){navigator.serviceWorker.register('/service-worker.js',{scope:'/'}).catch(function(){})})})();</script>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="preload" as="style" href="https://fonts.googleapis.com/css2?family=Hind+Siliguri:wght@400;600;700&display=swap" onload="this.onload=null;this.rel='stylesheet'">
<noscript><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Hind+Siliguri:wght@400;600;700&display=swap"></noscript>
<link rel="stylesheet" href="/assets/app.css?v={{av}}">
<script>try{var t=localStorage.getItem('theme')||'{{dtheme}}';if(t==='dark'||t==='light')document.documentElement.setAttribute('data-theme',t)}catch(e){}</script></head>
<body{% if authpage %} class="auth"{% endif %}{% if u %} data-poll="1" data-snd="{{snd}}"{% endif %}>
<div id="ld"></div>
<div class="top"><b>{{site}}</b><button type="button" id="pwa-install" class="pwa-dl" aria-label="Download App" title="Download App">📲</button><a class="lgsw" href="/lang/{{'bn' if lang=='en' else 'en'}}?next={{nxt|urlencode}}">{{'বাংলা' if lang=='en' else 'English'}}</a>
{% if u and not u['is_admin'] %}<span><a class="bell" href="/notifications">🔔<span class="dot" id="nd"{% if not unread %} hidden{% endif %}>{{unread}}</span></a></span>
{% elif u %}<span><span style="font-size:13px;margin-right:14px">{{role_name}}</span><a class="bell" href="/admin/alerts">🔔<span class="dot" id="nd"{% if not unread %} hidden{% endif %}>{{unread}}</span></a></span>
{% else %}<span><a href="/login">সাইন ইন</a> · <a href="/signup">সাইন আপ</a></span>{% endif %}</div>
<main>{% for c,m in msgs %}<div class="msg {{c}}">{{m}}</div>{% endfor %}
{% if u and u['is_admin'] %}<div class="adm"><a class="t {{'on' if active=='/admin'}}" href="/admin">🏠 ড্যাশবোর্ড</a><a class="t {{'on' if active not in ('/admin','/admin/request-history')}}" href="/admin/menu">☰ কন্ট্রোল সেন্টার <span class="bd2" data-bd="*"{% if not nb('*') %} hidden{% endif %}>{{nb('*')}}</span></a>{% if can('requests') %}<a class="t" href="/admin/request-history" style="background:#1668D0;border-color:#1668D0;color:#fff{{';box-shadow:0 0 0 3px #1668D04d' if active=='/admin/request-history'}}">🧾 রিকোয়েস্ট হিস্ট্রি</a><a class="t" href="/admin/requests/new" style="background:#0EA371;border-color:#0EA371;color:#fff">➕ রিকোয়েস্ট পাঠান</a>{% endif %}</div>{% endif %}
{{body|safe}}
{% if foot %}<div class="foot">{{foot}}</div>{% endif %}</main>
{% if u and not u['is_admin'] %}<div class="nav">
<a class="{{'on' if active=='/'}}" href="/"><i><svg viewBox="0 0 24 24" aria-hidden="true"><path class="d" d="M4 10.6 12 4l8 6.6V19a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1z"/><path d="M9.5 20v-5a1 1 0 0 1 1-1h3a1 1 0 0 1 1 1v5"/></svg></i>হোম</a><a class="{{'on' if active=='/history'}}" href="/history"><i><svg viewBox="0 0 24 24" aria-hidden="true"><circle class="d" cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/></svg></i>হিস্ট্রি<span class="bd2" data-bd="/history"{% if not nb('/history') %} hidden{% endif %}>{{nb('/history')}}</span></a>
<a class="{{'on' if active=='/vip'}}" href="/vip"><i><svg viewBox="0 0 24 24" aria-hidden="true"><path class="d" d="M3 8l4.5 4L12 5l4.5 7L21 8l-2 11H5z"/></svg></i>VIP<span class="bd2" data-bd="/vip"{% if not nb('/vip') %} hidden{% endif %}>{{nb('/vip')}}</span></a><a class="{{'on' if active=='/insight'}}" href="/insight"><i><svg viewBox="0 0 24 24" aria-hidden="true"><rect class="d" x="4" y="13" width="4" height="7" rx="1"/><rect class="d" x="10" y="9" width="4" height="11" rx="1"/><rect class="d" x="16" y="4" width="4" height="16" rx="1"/></svg></i>ইনসাইট<span class="bd2" data-bd="/insight"{% if not nb('/insight') %} hidden{% endif %}>{{nb('/insight')}}</span></a>
<a class="{{'on' if active=='/account'}}" href="/account"><i><svg viewBox="0 0 24 24" aria-hidden="true"><circle class="d" cx="12" cy="8" r="4"/><path class="d" d="M4.5 20.5a7.5 7.5 0 0 1 15 0z"/></svg></i>অ্যাকাউন্ট<span class="bd2" data-bd="/account"{% if not nb('/account') %} hidden{% endif %}>{{nb('/account')}}</span></a></div>{% endif %}
{% if fab %}<a class="fab" href="{{fab_href}}"{% if fab_tg %} target="_blank" rel="noopener"{% endif %} aria-label="{{fab_label}}" title="{{fab_label}}">💬</a>{% endif %}
<script src="/assets/app.js?v={{av}}"></script></body></html>"""

AUTH_CSS = """
body.auth{background:#1668D0;padding-bottom:0;min-height:100vh;min-height:100dvh;overflow-x:hidden;color:var(--tx)}
body.auth::before{content:"";position:fixed;inset:0;z-index:-1;background:radial-gradient(90% 60% at 100% 0%,#DFF7F533,#DFF7F500 60%),linear-gradient(165deg,#2B9BFF,#1668D0)}
body.auth #ld{z-index:50}
body.auth .top{background:none;box-shadow:none;position:relative;max-width:440px;margin:0 auto;padding:calc(10px + env(safe-area-inset-top,0px)) 18px 0}
body.auth .top>span{display:none}
body.auth .top b{display:flex;align-items:center;gap:10px;font-size:17px;font-weight:700;letter-spacing:.2px}
body.auth .top b::before{content:"";flex:0 0 34px;height:34px;border-radius:10px;background:#ffffff26 url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='white' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M3 7.5A2.5 2.5 0 0 1 5.5 5H18a1 1 0 0 1 1 1v2'/%3E%3Cpath d='M3 7.5V17a2 2 0 0 0 2 2h13a1 1 0 0 0 1-1v-3'/%3E%3Cpath d='M21 9.5h-5a2.5 2.5 0 0 0 0 5h5z'/%3E%3C/svg%3E") center/20px no-repeat}
body.auth main{max-width:440px;margin:0 auto;padding:0 16px calc(16px + env(safe-area-inset-bottom,0px))}
.au-hero{color:#fff;padding:14px 4px 14px}
.au-ht{min-width:0}
.au-badge{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;padding:3px 10px;border-radius:99px;background:#ffffff1f;margin-bottom:8px}
.au-badge svg{width:14px;height:14px}
.au-hero h1{margin:0 0 3px;font-size:26px;line-height:1.2;font-weight:700}
.au-hero p{margin:0;font-size:14px;line-height:1.45;opacity:.9}
.au-card{background:var(--card);border-radius:20px;padding:16px;box-shadow:0 10px 30px -10px #06304F59;animation:auUp .2s ease-out both}
@keyframes auUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.au-seg{position:relative;display:grid;grid-template-columns:1fr 1fr;background:var(--bg);border-radius:14px;padding:4px;margin-bottom:16px}
.au-seg a{position:relative;z-index:1;display:flex;align-items:center;justify-content:center;gap:7px;padding:10px 6px;border-radius:11px;font-weight:700;font-size:14.5px;color:var(--mut);transition:color .12s}
.au-seg a svg{width:17px;height:17px;flex:none}
.au-seg a.on{color:#fff}
.au-ind{position:absolute;z-index:0;top:4px;bottom:4px;left:4px;width:calc(50% - 4px);border-radius:11px;background:linear-gradient(100deg,#1E90FF,#1668D0);box-shadow:0 3px 8px #1E90FF40}
.au-seg.up .au-ind{transform:translateX(100%)}
.au-msg{display:flex;gap:9px;align-items:flex-start;padding:9px 12px;border-radius:12px;margin-bottom:12px;font-size:13.5px;line-height:1.5;word-break:break-word;background:#DDF8EC;color:#0B6B47}
.au-msg svg{width:18px;height:18px;flex:none;margin-top:2px}
.au-msg.error{background:#FFE4E6;color:#991b1b}
.au-form label{display:block;font-size:13.5px;font-weight:600;color:var(--tx);margin:0 0 5px}
.au-lr{display:flex;justify-content:space-between;align-items:baseline;gap:8px}
.au-lr a{font-size:13px;font-weight:600;color:var(--bt);margin-bottom:5px}
:root[data-theme=dark] .au-lr a{color:#5DB6FF}
.au-fw{margin-bottom:13px}
.au-f{position:relative}
.au-f>svg.ic{position:absolute;left:14px;top:50%;width:19px;height:19px;margin-top:-9.5px;color:var(--mut);pointer-events:none}
.au-f:focus-within>svg.ic{color:var(--bt)}
.au-f input{width:100%;height:48px;margin:0;padding:0 44px;font-size:16px;border:1px solid var(--ln);border-radius:12px;background:var(--bg);color:var(--tx);outline:0;transition:border-color .12s,box-shadow .12s}
.au-f input::placeholder{color:#8AA2B5}
.au-f input:focus{border-color:#1E90FF;background:var(--card);box-shadow:0 0 0 3px #1E90FF22}
.au-f .eye{position:absolute;right:4px;top:50%;width:40px;height:40px;margin-top:-20px;display:flex;align-items:center;justify-content:center;border-radius:10px;color:var(--mut);cursor:pointer}
.au-f .eye svg{width:20px;height:20px}
.au-f .eye .e2{display:none}.au-f .eye.on .e1{display:none}.au-f .eye.on .e2{display:block}
.au-f .eye.on{color:var(--bt)}
.au-meter{display:grid;grid-template-columns:repeat(4,1fr);gap:5px;margin-top:7px;align-items:center}
.au-meter b{height:4px;border-radius:4px;background:var(--ln)}
.au-meter em{grid-column:1/-1;font-style:normal;font-size:12px;font-weight:600;color:var(--mut);margin-top:2px}.au-meter em:empty{display:none}
.au-meter[data-s="1"] b:nth-child(-n+1){background:#ef4444}
.au-meter[data-s="2"] b:nth-child(-n+2){background:#f59e0b}
.au-meter[data-s="3"] b:nth-child(-n+3){background:#2BC4A8}
.au-meter[data-s="4"] b:nth-child(-n+4){background:#0EA371}
.au-chip{display:flex;align-items:center;gap:8px;padding:7px 12px;border-radius:12px;background:var(--aq);color:#0B6B6B;font-size:13px;font-weight:600;margin-bottom:12px}
.au-chip svg{width:17px;height:17px;flex:none}
:root[data-theme=dark] .au-chip{background:#0B3236;color:#8EE7DD}
.au-card button.au-btn{width:100%;height:50px;margin-top:4px;border-radius:13px;font-size:16.5px;font-weight:700;display:flex;align-items:center;justify-content:center;gap:9px;
 background:linear-gradient(100deg,#1E90FF,#1668D0);box-shadow:0 4px 12px -3px #1E90FF60;transition:transform .08s}
.au-btn svg{width:19px;height:19px}
.au-btn:active{transform:scale(.97)}
.au-alt{display:flex;align-items:center;gap:12px;margin:14px 0 10px;color:var(--mut);font-size:13px}
.au-alt::before,.au-alt::after{content:"";flex:1;height:1px;background:var(--ln)}
.au-card a.au-ghost{display:flex;align-items:center;justify-content:center;gap:8px;height:46px;border-radius:13px;border:1.5px solid #1E90FF44;color:var(--bt);font-weight:700;font-size:15px;transition:transform .08s}
.au-ghost:active{transform:scale(.97)}
.au-ghost svg{width:18px;height:18px}
:root[data-theme=dark] .au-card a.au-ghost{color:#9BD1FF}
.au-back{display:inline-flex;align-items:center;gap:6px;font-size:14px;font-weight:700;color:var(--bt);margin-bottom:10px}
.au-back svg{width:18px;height:18px}
:root[data-theme=dark] .au-back{color:#5DB6FF}
.au-steps{margin:0 0 12px;padding:0;list-style:none;counter-reset:s}
.au-steps li{counter-increment:s;display:flex;gap:11px;align-items:flex-start;font-size:13.5px;line-height:1.5;color:var(--tx);padding:5px 0}
.au-steps li::before{content:counter(s);flex:0 0 24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:12.5px;color:#fff;background:#1E90FF}
.au-steps a{color:var(--bt);font-weight:700}
.au-trust{display:flex;justify-content:center;flex-wrap:wrap;gap:6px 16px;margin:14px 0 0;color:#ffffffcc;font-size:12px;font-weight:600}
.au-trust div{display:flex;align-items:center;gap:5px}
.au-trust svg{width:15px;height:15px}
.au-note{margin:0 0 12px;font-size:13.5px;line-height:1.45;color:var(--mut)}
body.auth a,body.auth button{touch-action:manipulation;-webkit-tap-highlight-color:transparent}
@media(max-width:360px){.au-hero h1{font-size:23px}.au-card{padding:14px 12px}}
@media(max-height:680px){.au-trust{display:none}.au-hero{padding:8px 4px}}
@media(prefers-reduced-motion:reduce){.au-card{animation:none!important}}
"""
CSS += AUTH_CSS

ASSET_V = hashlib.sha1((CSS + JS).encode("utf-8")).hexdigest()[:10]


def _asset(body, mime):
    r = Response(body, mimetype=mime)
    r.headers["Cache-Control"] = "public, max-age=31536000, immutable"  # URL carries a content hash (?v=), so a change busts the cache
    return r


@app.route("/assets/app.css")
def asset_css():
    return _asset(CSS, "text/css")


@app.route("/assets/app.js")
def asset_js():
    return _asset(JS, "application/javascript")


# (path, label, permission or None = any staff)
ADMIN_TABS = [("/admin", "ড্যাশবোর্ড", None), ("/admin/alerts", "🔔 নোটিফিকেশন", None),
              ("/admin/requests", "রিকোয়েস্ট", "requests"), ("/admin/deposits", "ডিপোজিট", "deposits"),
              ("/admin/withdrawals", "উইথড্র", "withdrawals"), ("/admin/users", "ইউজার", "users_view"), ("/admin/kyc", "KYC", "kyc"),
              ("/admin/payment-numbers", "পেমেন্ট নম্বর", "payment_numbers"),
              ("/admin/referrals", "রেফারেল", "referrals"), ("/admin/vip", "VIP", "vip"), ("/admin/commission", "কমিশন", "commissions"), ("/admin/pool", "কমিশন পুল", "pool_view"),
              ("/admin/reports", "রিপোর্ট", "reports"), ("/admin/reconcile", "মিলানো", "reports"),
              ("/admin/staff", "স্টাফ", "staff"), ("/admin/tickets", "টিকিট", "tickets"),
              ("/admin/notices", "নোটিশ", "notices"), ("/admin/content", "কনটেন্ট", "notices"), ("/admin/settings", "সেটিংস", "settings"),
              ("/admin/audit", "অডিট লগ", "audit"), ("/admin/profile", "প্রোফাইল", None)]


@lru_cache(maxsize=512)
def _tpl(src):
    return app.jinja_env.from_string(src)  # compile each distinct template once per process (render_template_string recompiles on every request)


def render_str(src, **ctx):
    app.update_template_context(ctx)
    return _tpl(src).render(ctx)


def page(tpl, active="", foot="", authpage=False, **ctx):
    from flask import get_flashed_messages
    msgs = get_flashed_messages(with_categories=True)
    msgs = [(("error" if c == "error" else ""), m) for c, m in msgs]
    if authpage:  # sign in / sign up / reset pages show their messages inside the card
        ctx["amsgs"], msgs = msgs, []
    body = render_str(tpl, **ctx)
    u = me()
    lang, tgu = cur_lang(), tg_url_active()
    html = render_str(BASE, body=body, av=ASSET_V, msgs=msgs, active=active, foot=foot, authpage=authpage,
                                  fab=bool(u and not u["is_admin"] and active == "/"), lang=lang, nxt=request.path,
                                  fab_href=tgu or "/support", fab_tg=bool(tgu), fab_label=tg_label() if tgu else ("Support" if lang == "en" else "সাপোর্ট"),
                                  dtheme=setting("default_theme", "auto"), snd=setting("notif_sound", "1"))
    html = to_bdt(html)
    return tr(html) if lang == "en" else html


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


# ---------------------------------------------------------------- Phase 1: language (bn/en), Telegram support, editable Terms
import json as _json
from urllib.parse import urlparse as _urlparse, urlencode

LANGS = ("bn", "en")
TG_HOSTS = ("t.me", "telegram.me", "telegram.dog")
TG_USER_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{4,31}")

# Bangla -> English phrases. Applied only to whole phrases (never inside a longer Bangla word), only when English is selected.
EN_PHRASES = {
    # navigation / top bar
    "হোম": "Home", "হিস্ট্রি": "History", "অনুরোধ": "Requests", "ইনসাইট": "Insights", "অ্যাকাউন্ট": "Account",
    "সাইন ইন": "Sign in", "সাইন আপ": "Sign up", "লগআউট": "Log out", "সাপোর্ট": "Support",
    # dashboard
    "উপলব্ধ ব্যালেন্স": "Available balance", "ডিপোজিট": "Deposit", "উইথড্র": "Withdraw",
    "পেন্ডিং উইথড্র": "Pending withdrawals", "মোট ডিপোজিট": "Total deposits", "মোট উইথড্র": "Total withdrawals",
    "মোট কমিশন": "Total commission", "আজকের আয়": "Today's earnings", "মেম্বার আইডি": "Member ID",
    "ব্যালেন্স": "Balance",
    # statuses
    "অপেক্ষমাণ": "Pending", "জমা হয়েছে": "Submitted", "যাচাইয়ে": "Under review", "অনুমোদিত": "Approved",
    "রিজেক্ট": "Rejected", "মেয়াদোত্তীর্ণ": "Expired", "বাতিল": "Cancelled",
    # auth
    "মোবাইল নম্বর": "Mobile number", "পাসওয়ার্ড": "Password", "নাম": "Name", "নতুন অ্যাকাউন্ট": "New account",
    "পাসওয়ার্ড ভুলে গেছেন": "Forgot password", "পাসওয়ার্ড রিসেট": "Password reset", "রিসেট কোড": "Reset code",
    "নতুন পাসওয়ার্ড": "New password", "পাসওয়ার্ড বদলান": "Change password", "পুরনো পাসওয়ার্ড": "Old password",
    "রেফারেল কোড (ঐচ্ছিক)": "Referral code (optional)", "পাসওয়ার্ড (কমপক্ষে ৬ অক্ষর)": "Password (at least 6 characters)",
    "আগেই অ্যাকাউন্ট আছে": "Already have an account",
    "অ্যাকাউন্ট তৈরি হয়েছে। সাইন ইন করুন।": "Account created. Please sign in.",
    "পাসওয়ার্ড বদলেছে। সাইন ইন করুন।": "Password changed. Please sign in.",
    "পাসওয়ার্ড বদলেছে। আবার সাইন ইন করুন।": "Password changed. Please sign in again.",
    "নম্বর/পাসওয়ার্ড ভুল অথবা অ্যাকাউন্ট ব্লকড/নিষ্ক্রিয়।": "Wrong number/password, or the account is blocked/inactive.",
    "এই নম্বর দিয়ে আগেই অ্যাকাউন্ট আছে।": "An account already exists with this number.",
    "অনেক চেষ্টা হয়েছে, পরে আবার চেষ্টা করুন।": "Too many attempts. Please try again later.",
    "অনেকবার ভুল হয়েছে। ১৫ মিনিট পরে চেষ্টা করুন।": "Too many wrong attempts. Try again after 15 minutes.",
    "বর্তমানে নতুন সাইন আপ বন্ধ আছে।": "New sign-ups are currently closed.",
    "নাম, সঠিক ১১ ডিজিটের মোবাইল নম্বর ও কমপক্ষে ৬ অক্ষরের পাসওয়ার্ড দিন।": "Enter your name, a valid 11-digit mobile number and a password of at least 6 characters.",
    "রেফারেল কোডটি সঠিক নয়। কোড ঠিক করুন বা ফাঁকা রেখে সাইন আপ করুন।": "The referral code is not valid. Correct it or leave it blank.",
    "টেলিগ্রামে": "Telegram", "সাপোর্টে": "Support",
    "আপনার নাম, মোবাইল নম্বর ও মেম্বার আইডি জানান।": "Tell them your name, mobile number and member ID.",
    "স্টাফ একটি ৩০ মিনিটের এককালীন কোড দেবেন।": "Staff will give you a one-time code valid for 30 minutes.",
    "নিচে কোডটি দিয়ে নতুন পাসওয়ার্ড সেট করুন।": "Use the code below to set a new password.",
    "তথ্য সঠিক নয়।": "The information is not correct.",
    "কোডটি ভুল, মেয়াদোত্তীর্ণ বা ব্যবহৃত।": "The code is wrong, expired or already used.",
    # deposit / withdraw
    "নতুন ডিপোজিট রিকোয়েস্ট": "New deposit request", "নতুন উইথড্র রিকোয়েস্ট": "New withdrawal request",
    "মাধ্যম": "Method", "পরিমাণ": "Amount", "আপনার নম্বর": "Your number", "রিকোয়েস্ট করুন": "Submit request",
    "জমা দিন": "Submit", "রিকোয়েস্ট": "Request", "সেট করা হয়নি": "Not set",
    "ডিপোজিট রিকোয়েস্ট জমা হয়েছে। যাচাই করা হবে।": "Deposit request submitted. It will be verified.",
    "উইথড্র রিকোয়েস্ট জমা হয়েছে, টাকা রিজার্ভ করা হয়েছে।": "Withdrawal request submitted; the amount has been reserved.",
    "ব্যালেন্স অপর্যাপ্ত।": "Insufficient balance.",
    "অনেক রিকোয়েস্ট হয়েছে।": "Too many requests.", "তথ্য ঠিক আছে? জমা দেবেন?": "Is the information correct? Submit?",
    # history / notifications / insight
    "কোনো লেনদেন নেই": "No transactions", "ধরন": "Type", "অবস্থা": "Status", "সময়": "Time",
    "ওয়ালেট লেজার": "Wallet ledger", "নোট": "Note", "নোটিফিকেশন": "Notifications",
    "কোনো নোটিফিকেশন নেই": "No notifications", "খুলুন": "Open", "৭ দিন": "7 days", "৩০ দিন": "30 days",
    "৯০ দিন": "90 days", "কমিশন ও রেফারেল": "Commission & referral",
    # referral
    "আমার রেফারেল কোড": "My referral code", "আপনার রেফারেল কোড": "Your referral code", "লিংক কপি": "Copy link",
    "শেয়ার": "Share", "কোড কপি": "Copy code", "আপনাকে রেফার করেছেন": "Referred you",
    "মোট রেফার": "Total referrals", "অপেক্ষমাণ": "Pending", "মোট বোনাস আয়": "Total bonus earned",
    "রেফারেল ইতিহাস": "Referral history", "এখনো কেউ আপনার কোডে যোগ দেয়নি": "Nobody has joined with your code yet",
    "সদস্য": "Member", "তারিখ": "Date", "ইনভাইট ও আর্ন": "Invite & Earn",
    # support
    "বিষয় ও বার্তা দিন।": "Enter a subject and a message.", "টিকিট জমা হয়েছে।": "Ticket submitted.",
    "বিষয়": "Subject", "বার্তা": "Message", "টিকিট জমা দিন": "Submit ticket", "যাচাই": "Verify",
    "↳ সাপোর্ট:": "↳ Support:",
    # account
    "ডার্ক মোড": "Dark mode", "নোটিফিকেশন সাউন্ড": "Notification sound", "ব্রাউজার নোটিফিকেশন": "Browser notifications", "📲 ব্রাউজার:": "📲 Browser:", "সেটিংস": "Settings",
    "পেমেন্ট নম্বর ব্যবস্থাপনা": "Manage payment numbers", "ফিডব্যাক": "Feedback", "আমাদের সম্পর্কে": "About us",
    "সাম্প্রতিক লগইন": "Recent logins", "শর্তাবলি": "Terms", "শর্তাবলি ও তথ্য": "Terms & Information",
    "ভাষা": "Language", "বদলান": "Change", "এই ফিচারটি শীঘ্রই আসছে।": "This feature is coming soon.",
    "অ্যাকাউন্টে ফিরুন": "Back to account", "ফিরে যান": "Go back", "পেজ পাওয়া যায়নি।": "Page not found.",
    "এই কাজের অনুমতি আপনার নেই।": "You do not have permission for this action.",
    # admin tabs
    "ড্যাশবোর্ড": "Dashboard", "ইউজার": "Users", "পেমেন্ট নম্বর": "Payment numbers", "রেফারেল": "Referrals",
    "কমিশন": "Commission", "স্টাফ": "Staff", "টিকিট": "Tickets", "নোটিশ": "Notices", "অডিট লগ": "Audit log",
    "প্রোফাইল": "Profile", "কনটেন্ট": "Content", "কমিশন পুল": "Commission pool", "রিপোর্ট": "Reports", "মিলানো": "Reconciliation", "🔔 নোটিফিকেশন": "🔔 Notifications",
    "সুপার অ্যাডমিন": "Super admin", "অ্যাডমিন": "Admin", "ফাইন্যান্স স্টাফ": "Finance staff", "সাপোর্ট স্টাফ": "Support staff",
    "সেভ": "Save", "সেভ হয়েছে।": "Saved.",
    # request kinds
    "অ্যাডমিনের পাঠানো ডিপোজিট/উইথড্র অনুরোধ এখানে দেখা যায়।": "Deposit/withdrawal requests sent by the admin appear here.",
    "কোনো অনুরোধ নেই": "No requests",
    "লেভেল": "Level", "পেমেন্ট স্ক্রিনশট": "Payment screenshot", "ঐচ্ছিক": "optional", "উপলব্ধ": "Available",
    "নতুন নম্বর যোগ করুন": "Add a new number", "যোগ করুন": "Add", "এখনো কোনো নম্বর যোগ করা হয়নি": "No number added yet",
    "পার্সোনাল": "Personal", "এজেন্ট": "Agent", "মার্চেন্ট": "Merchant", "আপনার মতামত": "Your feedback", "পাঠান": "Send",
    "জানান": "Tell us", "আমাদের সেবা কেমন লাগছে বা কী উন্নতি করা যায়": "How do you like our service, or what can we improve",
    "নির্দেশনা": "Instructions", "পেমেন্ট মাধ্যম": "Payment method", "পেমেন্ট নম্বর": "Payment number",
    "← সব অনুরোধ": "← All requests",
    "ডিপোজিট রিকোয়েস্ট": "Deposit request", "উইথড্র/পেমেন্ট রিকোয়েস্ট": "Withdrawal / payment request", "উদ্দেশ্য": "Purpose",
    "উদ্দেশ্য (Purpose)": "Purpose", "মূল পরিমাণ (আপনার ওয়ালেট থেকে কাটা হবে)": "Principal (will be deducted from your wallet)",
    "কমিশন": "Commission", "নিট ওয়ালেট পরিবর্তন": "Net wallet change", "বর্তমান ব্যালেন্স": "Current balance", "অনুমোদনের পর ব্যালেন্স": "Balance after approval",
    "✅ অনুমোদন করুন": "✅ Approve", "❌ বাতিল করুন": "❌ Reject", "আপনার রেট": "Your rate", "রেট": "Rate",
    "কমিশন কোম্পানির প্রচারণা পুল থেকে দেওয়া হয়": "Commission is paid from the company promotional pool",
    "আপনার ব্যালেন্স এই অনুরোধের জন্য পর্যাপ্ত নয়।": "Your balance is not enough for this request.",
    "অনুমোদন করলে সঙ্গে সঙ্গে সম্পন্ন হবে; আর কোনো অ্যাডমিন অনুমোদন লাগবে না। বাতিল করলে আপনার ব্যালেন্স অপরিবর্তিত থাকবে।":
        "Approving completes it immediately; no further admin approval is needed. If you reject, your balance does not change.",
    "উদ্দেশ্য, মূল পরিমাণ ও কমিশন দেখে নিশ্চিত?": "Have you checked the purpose, principal and commission? Confirm?",
    "অনুরোধটির মেয়াদ শেষ হয়েছে।": "This request has expired.",
    "আপনার ব্যালেন্স অপর্যাপ্ত — কিছুই কাটা হয়নি।": "Your balance is insufficient; nothing was deducted.",
    "অনুরোধ বাতিল করা হয়েছে।": "Request rejected.",
    # referral rewards (first approved Add Money)
    "রেফারেল রিওয়ার্ড": "Referral reward", "বর্তমান রিওয়ার্ড": "Current reward", "ডিপোজিটের অপেক্ষায়": "Awaiting first deposit",
    "পেইড": "Paid", "মোট রেফার": "Total referrals", "রিওয়ার্ড পেইড": "Rewards paid", "মোট রেফারেল আয়": "Total referral earnings",
    "প্রথম ডিপোজিট বাকি": "Awaiting first deposit",
    "রিওয়ার্ড সেটিংস": "Reward settings", "রিওয়ার্ড ইতিহাস": "Reward history", "রিওয়ার্ড দিন": "Pay reward",
    "রিওয়ার্ডের পরিমাণ (৳)": "Reward amount (৳)", "রিওয়ার্ড সেভ করুন": "Save reward",
    # authentication pages
    "স্বাগতম": "Welcome", "নিরাপদ ডিজিটাল ওয়ালেট": "Secure digital wallet",
    "আপনার ওয়ালেটে নিরাপদে সাইন ইন করুন": "Sign in to your wallet securely", "কয়েক সেকেন্ডেই অ্যাকাউন্ট খুলুন": "Create your account in seconds",
    "সাপোর্টের সহায়তায় নিরাপদে পাসওয়ার্ড বদলান": "Change your password safely with support's help",
    "পাসওয়ার্ড দেখান বা লুকান": "Show or hide password", "অ্যাকাউন্ট নেই?": "Don't have an account?",
    "নতুন অ্যাকাউন্ট খুলুন": "Create a new account", "আগেই অ্যাকাউন্ট আছে?": "Already have an account?",
    "আপনার পুরো নাম": "Your full name", "যেমন: AB12CD34": "e.g. AB12CD34", "রেফারেল কোড প্রয়োগ হয়েছে": "Referral code applied",
    "সুরক্ষিত লগইন": "Secure login", "লেজার-ভিত্তিক হিসাব": "Ledger-based accounting", "যাচাইকৃত ডিপোজিট": "Verified deposits",
    "আপনার নাম, মোবাইল নম্বর ও মেম্বার আইডি সাপোর্টকে জানান।": "Tell support your name, mobile number and member ID.",
    "টেলিগ্রামে মেসেজ করুন": "Message us on Telegram",
    "স্টাফ একটি ৩০ মিনিটের এককালীন কোড দেবেন।": "Staff will give you a one-time code valid for 30 minutes.",
    "নিচে কোডটি দিয়ে নতুন পাসওয়ার্ড সেট করুন।": "Enter the code below and set a new password.",
    "অ্যাডমিন যাচাই": "Admin verification", "আপনার সিকিউরিটি কোড লিখুন": "Enter your security code",
    "অ্যাডমিন সিকিউরিটি কোড": "Admin security code", "কোড যাচাই করুন": "Verify code",
    "পাসওয়ার্ড সঠিক হয়েছে। চালিয়ে যেতে আলাদা অ্যাডমিন সিকিউরিটি কোডটি দিন।": "Password accepted. Enter your separate admin security code to continue.",
}
for _k, _v in {"পেমেন্ট প্রোভাইডার": "Payment Provider", "পেমেন্ট টাইপ": "Payment Type", "অ্যাডমিনের নির্দেশনা": "Admin Instructions",
               "কীভাবে পেমেন্ট করবেন": "How to pay", "রিকোয়েস্ট হিস্ট্রি": "Request History", "অনুরোধ বাতিল করুন": "Cancel request",
               "অ্যাডমিনের সতর্কবার্তা": "Admin warning", "এক্সট্রা কমিশন": "Extra commission", "ওয়ালেটে যুক্ত হয়েছে": "Added to your wallet",
               "মোট ওয়ালেটে যুক্ত": "Total added to wallet", "বাতিল ফি": "Cancellation fee", "বাতিলের পর ব্যালেন্স": "Balance after cancellation",
               "হ্যাঁ, বাতিল করুন": "Yes, cancel", "ফিরে যান": "Go back", "অপেক্ষমাণ": "Pending", "সফল": "Success"}.items():
    EN_PHRASES.setdefault(_k, _v)
_EN_RE = re.compile(r"(?<![\u0980-\u09FF])(" + "|".join(re.escape(k) for k in sorted(EN_PHRASES, key=len, reverse=True))
                    + r")(?![\u0980-\u09FF])")
_BN_DIGITS = str.maketrans("০১২৩৪৫৬৭৮৯", "0123456789")


def tr(html):
    """English mode: swap known Bangla phrases for English and Bangla digits for 0-9. Pure display; never touches stored data."""
    return _EN_RE.sub(lambda m: EN_PHRASES[m.group(1)], html).translate(_BN_DIGITS)


def cur_lang():
    """Logged-in user's saved choice, else the 'lang' cookie, else Bangla (default)."""
    if hasattr(g, "_lang"):
        return g._lang
    lang = None
    u = me()
    if u:
        lang = setting("ulang:%d" % u["id"], None)
    if lang not in LANGS:
        lang = request.cookies.get("lang")
    if lang not in LANGS:
        lang = "bn"
    g._lang = lang
    return lang


@app.route("/lang/<code>")
def set_lang(code):
    if code not in LANGS:
        abort(404)
    u = me()
    if u:
        db().execute("INSERT OR REPLACE INTO settings VALUES(?,?)", ("ulang:%d" % u["id"], code))
    nxt = request.args.get("next", "/")
    if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt or "\n" in nxt or "\r" in nxt:
        nxt = "/"  # local paths only (no open redirect)
    r = redirect(nxt)
    r.set_cookie("lang", code, max_age=365 * 86400, samesite="Lax", httponly=True, secure=bool(os.environ.get("RENDER")))
    return r


# ---- Telegram support (nothing hardcoded: URL, username, on/off and labels all come from settings)
def _tg_https(url):
    return url.startswith("https://") and len(url) <= 300 and " " not in url


def tg_url_active():
    if setting("tg_enabled", "1") != "1":
        return ""
    url = setting("telegram_url", "").strip()
    if not url:
        un = setting("tg_username", "").strip().lstrip("@")
        if TG_USER_RE.fullmatch(un):
            url = "https://t.me/" + un
    return url if _tg_https(url) else ""


def tg_label():
    lang = cur_lang()
    v = setting("tg_label_" + lang, "").strip()
    return v or ("Contact us on Telegram" if lang == "en" else "টেলিগ্রামে যোগাযোগ")


# ---- Terms / About content (editable from the admin panel, stored in settings key terms_json)
DISCLAIMER_EN = "This is an independent platform; it is not an official service of bKash, Nagad or Rocket."
TERMS_DEFAULT = {
    "title": {"bn": "শর্তাবলি ও তথ্য", "en": "Terms & Information"},
    "points": [
        {"bn": "এই প্ল্যাটফর্মে কোনো আয়ের নিশ্চয়তা দেওয়া হয় না।", "en": "This platform does not guarantee any income."},
        {"bn": "ডিপোজিট যাচাইয়ের পর ওয়ালেটে যুক্ত হয়।", "en": "A deposit is added to your wallet after verification."},
        {"bn": "উইথড্র রিকোয়েস্ট অনুমোদনের পর পরিশোধ হয়।", "en": "A withdrawal is paid after the request is approved."},
        {"bn": "কমিশন ম্যানুয়ালি কারণসহ প্রদান করা হয় এবং লেজারে সংরক্ষিত থাকে।",
         "en": "Commission is given with a stated reason and is recorded in the ledger."},
        {"bn": "রেফার করা ব্যক্তির প্রথম অনুমোদিত ডিপোজিটের পরই রেফারেল বোনাস ওয়ালেটে যুক্ত হয়; ভুয়া/স্ব-রেফারেল বাতিল হবে।",
         "en": "A referral bonus is added only after the referred person's first approved deposit; fake or self-referrals are cancelled."},
        {"bn": "প্রতিটি লেনদেন অডিটযোগ্য লেজারে রেকর্ড হয়।", "en": "Every transaction is recorded in an auditable ledger."},
    ],
    "instructions": {"bn": "", "en": ""},
    "disclaimer": {"bn": DISCLAIMER, "en": DISCLAIMER_EN},
}


def terms_get():
    d = _json.loads(_json.dumps(TERMS_DEFAULT))
    try:
        s = _json.loads(setting("terms_json", "") or "null")
    except ValueError:
        s = None
    if isinstance(s, dict):
        for k in ("title", "instructions", "disclaimer"):
            if isinstance(s.get(k), dict):
                d[k] = {l: str(s[k].get(l, ""))[:2000] for l in LANGS}
        if isinstance(s.get("points"), list):
            d["points"] = [{l: str(p.get(l, ""))[:500] for l in LANGS} for p in s["points"][:30] if isinstance(p, dict)]
    return d


@app.route("/about")
def about():
    t, lang = terms_get(), cur_lang()
    pick = lambda d: d.get(lang) or d.get("bn") or ""
    return page("""<div class="card"><h2>{{title}}</h2>
{% if ins %}<div class="hl" style="white-space:pre-line">{{ins}}</div>{% endif %}
{% for p in pts %}<div style="white-space:pre-line;margin:6px 0">• {{p}}</div>{% endfor %}
{% if disc %}<p class="k" style="white-space:pre-line">{{disc}}</p>{% endif %}</div>""",
                title=pick(t["title"]), ins=pick(t["instructions"]), disc=pick(t["disclaimer"]),
                pts=[pick(p) for p in t["points"] if pick(p)])


@app.route("/admin/content")
@staff_required("notices")
def admin_content():
    t = terms_get()
    return page("""<div class="card"><h2>📄 শর্তাবলি ও তথ্য (বাংলা + English)</h2>
<p class="k">এখানে সেভ করলেই ক্লায়েন্টের "শর্তাবলি ও তথ্য" পেজে সঙ্গে সঙ্গে বদলে যাবে — নতুন ডিপ্লয় লাগে না।</p>
<form method="post" action="/admin/content/terms" data-confirm="সেভ করবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>শিরোনাম (বাংলা)</label><input name="title_bn" value="{{t['title']['bn']}}" maxlength="120" required>
<label>Title (English)</label><input name="title_en" value="{{t['title']['en']}}" maxlength="120">
<label>নির্দেশনা (বাংলা)</label><textarea name="ins_bn" rows="3" maxlength="2000">{{t['instructions']['bn']}}</textarea>
<label>Instructions (English)</label><textarea name="ins_en" rows="3" maxlength="2000">{{t['instructions']['en']}}</textarea>
<h3>পয়েন্ট সমূহ</h3><p class="k">মুছতে "মুছুন" টিক দিন। নতুন যোগ করতে নিচের ফাঁকা ঘরে লিখুন (সর্বোচ্চ ৩০টি)।</p>
{% for p in pts %}<div class="card" style="margin:8px 0"><div class="k">পয়েন্ট {{loop.index}}</div>
<textarea name="pbn" rows="2" maxlength="500" placeholder="বাংলা">{{p['bn']}}</textarea>
<textarea name="pen" rows="2" maxlength="500" placeholder="English">{{p['en']}}</textarea>
<label style="display:flex;gap:8px;align-items:center"><input type="checkbox" name="pdel" value="{{loop.index0}}" style="width:auto"> মুছুন</label></div>{% endfor %}
<label>ডিসক্লেইমার (বাংলা)</label><textarea name="disc_bn" rows="2" maxlength="2000">{{t['disclaimer']['bn']}}</textarea>
<label>Disclaimer (English)</label><textarea name="disc_en" rows="2" maxlength="2000">{{t['disclaimer']['en']}}</textarea>
<button style="width:100%">সেভ</button></form>
<a class="btn s" href="/about" target="_blank" style="width:100%;margin-top:8px">👁 ক্লায়েন্ট পেজ দেখুন</a></div>
{% if can_tg %}<div class="card"><h2>✈ Telegram সাপোর্ট</h2>
<form method="post" action="/admin/content/telegram" data-confirm="সেভ করবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label style="display:flex;gap:8px;align-items:center"><input type="checkbox" name="enabled" value="1" style="width:auto" {{'checked' if tg_on}}> সাপোর্ট বাটন চালু</label>
<label>Telegram URL (https://t.me/...)</label><input name="url" value="{{tg_url}}" maxlength="300" placeholder="https://t.me/yourname">
<label>Telegram ইউজারনেম (ঐচ্ছিক; URL ফাঁকা থাকলে এটি দিয়ে লিংক হবে)</label><input name="username" value="{{tg_user}}" maxlength="33" placeholder="yourname">
<label>বাটনের লেখা (বাংলা)</label><input name="label_bn" value="{{tg_bn}}" maxlength="40" placeholder="টেলিগ্রামে যোগাযোগ">
<label>Button label (English)</label><input name="label_en" value="{{tg_en}}" maxlength="40" placeholder="Contact us on Telegram">
<button style="width:100%">সেভ</button></form></div>{% endif %}""",
                active="/admin/content", t=t, pts=t["points"] + [{"bn": "", "en": ""}] * 2, can_tg=has_perm("settings"),
                tg_on=setting("tg_enabled", "1") == "1", tg_url=setting("telegram_url"), tg_user=setting("tg_username"),
                tg_bn=setting("tg_label_bn"), tg_en=setting("tg_label_en"))


@app.route("/admin/content/terms", methods=["POST"])
@staff_required("notices")
def admin_content_terms():
    f = request.form
    title_bn, title_en = f.get("title_bn", "").strip()[:120], f.get("title_en", "").strip()[:120]
    if not title_bn:
        err("বাংলা শিরোনাম আবশ্যক।"); return redirect("/admin/content")
    dele = set(f.getlist("pdel"))
    pts = []
    for i, (b, e) in enumerate(zip(f.getlist("pbn"), f.getlist("pen"))):
        b, e = b.strip()[:500], e.strip()[:500]
        if str(i) not in dele and (b or e):
            pts.append({"bn": b, "en": e})
    if len(pts) > 30:
        err("সর্বোচ্চ ৩০টি পয়েন্ট রাখা যায়।"); return redirect("/admin/content")
    data = {"title": {"bn": title_bn, "en": title_en},
            "instructions": {"bn": f.get("ins_bn", "").strip()[:2000], "en": f.get("ins_en", "").strip()[:2000]},
            "disclaimer": {"bn": f.get("disc_bn", "").strip()[:2000], "en": f.get("disc_en", "").strip()[:2000]},
            "points": pts}
    with atomic():
        db().execute("INSERT OR REPLACE INTO settings VALUES(?,?)", ("terms_json", _json.dumps(data, ensure_ascii=False)))
        audit("terms_edit", "points=%d" % len(pts))
    flash("সেভ হয়েছে।")
    return redirect("/admin/content")


@app.route("/admin/content/telegram", methods=["POST"])
@staff_required("settings")
def admin_content_telegram():
    f = request.form
    url, un = f.get("url", "").strip(), f.get("username", "").strip().lstrip("@")
    on = "1" if f.get("enabled") == "1" else "0"
    lb, le = f.get("label_bn", "").strip()[:40], f.get("label_en", "").strip()[:40]
    if url:
        p = _urlparse(url)
        if not _tg_https(url) or (p.hostname or "").lower() not in TG_HOSTS:
            err("লিংক https://t.me/... আকারে দিন।"); return redirect("/admin/content")
    if un and not TG_USER_RE.fullmatch(un):
        err("ইউজারনেম ৫–৩২ অক্ষর (ইংরেজি অক্ষর, সংখ্যা, _)।"); return redirect("/admin/content")
    if on == "1" and not (url or un):
        err("চালু করতে URL বা ইউজারনেম দিন।"); return redirect("/admin/content")
    with atomic():
        for k, v in (("tg_enabled", on), ("telegram_url", url), ("tg_username", un), ("tg_label_bn", lb), ("tg_label_en", le)):
            db().execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (k, v))
        audit("telegram_settings", "enabled=%s url=%s user=%s" % (on, url, un))
    flash("সেভ হয়েছে।")
    return redirect("/admin/content")



# ---------------------------------------------------------------- authentication pages: shared premium layout (sign in / sign up / reset)
AUTH_ICONS = {'phone': '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="6.5" y="2.8" width="11" height="18.4" rx="2.6"/><path d="M10.5 18h3"/></svg>', 'lock': '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4.5" y="10.5" width="15" height="10" rx="2.6"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/><circle cx="12" cy="15.5" r="1.1" fill="currentColor"/></svg>', 'user': '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4.5 20.5a7.5 7.5 0 0 1 15 0"/></svg>', 'gift': '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3.5" y="8.5" width="17" height="4" rx="1.2"/><path d="M5 12.5V20h14v-7.5M12 8.5V20"/><path d="M12 8.5C10.5 8.5 8 8 8 6a2 2 0 0 1 4 0v2.5zm0 0c1.5 0 4-.5 4-2.5a2 2 0 0 0-4 0"/></svg>', 'key': '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="15" r="4"/><path d="M11 12l8-8M16 7l2.5 2.5M13.5 9.5l2 2"/></svg>', 'eye': '<span class="eye" role="button" tabindex="0" data-pwtoggle aria-pressed="false" aria-label="পাসওয়ার্ড দেখান বা লুকান"><svg class="e1" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg><svg class="e2" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 3l18 18M10.6 6.2A10 10 0 0 1 12 5.5c6.4 0 10 6.5 10 6.5a17 17 0 0 1-3.2 3.9M6.5 7.6A16.6 16.6 0 0 0 2 12s3.6 6.5 10 6.5a9.7 9.7 0 0 0 4-.9"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg></span>', 'arrow': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6"/></svg>', 'back': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 12H5M11 6l-6 6 6 6"/></svg>', 'login': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4M10 16l4-4-4-4M14 12H4"/></svg>', 'plus': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="10" cy="8" r="3.6"/><path d="M3.5 20a6.5 6.5 0 0 1 13 0M19 8v6M16 11h6"/></svg>', 'shield': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7.5 3v5.5c0 4.6-3.1 8.3-7.5 9.5-4.4-1.2-7.5-4.9-7.5-9.5V6z"/><path d="M8.8 12l2.4 2.4 4.2-4.6"/></svg>', 'ledger': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="3.5" width="14" height="17" rx="2.4"/><path d="M8.5 8.5h7M8.5 12h7M8.5 15.5h4"/></svg>', 'verified': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M8.2 12.2l2.6 2.6 5-5.4"/></svg>', 'alert': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5M12 16.4v.1"/></svg>', 'ok': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M8 12.3l2.7 2.7L16 9.5"/></svg>'}


def _auth_tpl(t):
    return re.sub(r"@@(\w+)@@", lambda m: AUTH_ICONS[m.group(1)], t)


AUTH_TOP = _auth_tpl("""<section class="au-hero"><div class="au-ht"><span class="au-badge">@@shield@@নিরাপদ ডিজিটাল ওয়ালেট</span>
{% if mode=='in' %}<h1>স্বাগতম</h1><p>আপনার ওয়ালেটে নিরাপদে সাইন ইন করুন</p>
{% elif mode=='up' %}<h1>নতুন অ্যাকাউন্ট</h1><p>কয়েক সেকেন্ডেই অ্যাকাউন্ট খুলুন</p>
{% elif mode=='tf' %}<h1>অ্যাডমিন যাচাই</h1><p>আপনার সিকিউরিটি কোড লিখুন</p>
{% else %}<h1>পাসওয়ার্ড রিসেট</h1><p>সাপোর্টের সহায়তায় নিরাপদে পাসওয়ার্ড বদলান</p>{% endif %}</div>
</section>
<div class="au-card">
{% if mode in ('in','up') %}<div class="au-seg {{mode}}" role="tablist"><i class="au-ind"></i>
<a href="/login" role="tab" class="{{'on' if mode=='in'}}" aria-selected="{{'true' if mode=='in' else 'false'}}">@@login@@সাইন ইন</a>
<a href="/signup{% if ref %}?ref={{ref}}{% endif %}" role="tab" class="{{'on' if mode=='up'}}" aria-selected="{{'true' if mode=='up' else 'false'}}">@@plus@@নতুন অ্যাকাউন্ট</a></div>
{% else %}<a class="au-back" href="/login">@@back@@সাইন ইন</a>{% endif %}
{% for c,m in amsgs %}<div class="au-msg {{c}}" role="alert">{% if c=='error' %}@@alert@@{% else %}@@ok@@{% endif %}<span>{{m}}</span></div>{% endfor %}""")

AUTH_BOTTOM = _auth_tpl("""</div>
<div class="au-trust"><div>@@shield@@সুরক্ষিত লগইন</div><div>@@ledger@@লেজার-ভিত্তিক হিসাব</div><div>@@verified@@যাচাইকৃত ডিপোজিট</div></div>""")

LOGIN_FORM = _auth_tpl("""<form method="post" class="au-form"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<div class="au-fw"><label for="au-ph">মোবাইল নম্বর</label><div class="au-f">@@phone@@<input id="au-ph" name="phone" required inputmode="numeric" autocomplete="username" placeholder="01XXXXXXXXX"></div></div>
<div class="au-fw"><div class="au-lr"><label for="au-pw">পাসওয়ার্ড</label><a href="/forgot">পাসওয়ার্ড ভুলে গেছেন?</a></div>
<div class="au-f">@@lock@@<input id="au-pw" name="pw" type="password" required autocomplete="current-password" placeholder="••••••••">@@eye@@</div></div>
<button class="au-btn">সাইন ইন @@arrow@@</button></form>
<div class="au-alt">অ্যাকাউন্ট নেই?</div>
<a class="au-ghost" href="/signup">@@plus@@নতুন অ্যাকাউন্ট খুলুন</a>""")

SIGNUP_FORM = _auth_tpl("""<form method="post" class="au-form"><input type="hidden" name="_csrf" value="{{csrf_token}}">
{% if ref %}<div class="au-chip">@@ok@@রেফারেল কোড প্রয়োগ হয়েছে</div>{% endif %}
<div class="au-fw"><label for="au-nm">নাম</label><div class="au-f">@@user@@<input id="au-nm" name="name" required maxlength="60" autocomplete="name" placeholder="আপনার পুরো নাম"></div></div>
<div class="au-fw"><label for="au-ph">মোবাইল নম্বর</label><div class="au-f">@@phone@@<input id="au-ph" name="phone" required inputmode="numeric" maxlength="11" autocomplete="tel" placeholder="01XXXXXXXXX"></div></div>
<div class="au-fw"><label for="au-pw">পাসওয়ার্ড (কমপক্ষে ৬ অক্ষর)</label><div class="au-f">@@lock@@<input id="au-pw" name="pw" type="password" required minlength="6" autocomplete="new-password" placeholder="••••••••" data-pwmeter>@@eye@@</div>
<div class="au-meter" data-s="0"><b></b><b></b><b></b><b></b><em></em></div></div>
<div class="au-fw"><label for="au-rf">রেফারেল কোড (ঐচ্ছিক)</label><div class="au-f">@@gift@@<input id="au-rf" name="ref" value="{{ref}}" maxlength="12" autocapitalize="characters" autocomplete="off" placeholder="যেমন: AB12CD34"></div></div>
<button class="au-btn">নতুন অ্যাকাউন্ট খুলুন @@arrow@@</button></form>
<div class="au-alt">আগেই অ্যাকাউন্ট আছে?</div>
<a class="au-ghost" href="/login">@@login@@সাইন ইন</a>""")

TFA_FORM = _auth_tpl("""<p class="au-note">পাসওয়ার্ড সঠিক হয়েছে। চালিয়ে যেতে আলাদা অ্যাডমিন সিকিউরিটি কোডটি দিন।</p>
<form method="post" class="au-form" autocomplete="off"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<div class="au-fw"><label for="au-cd">অ্যাডমিন সিকিউরিটি কোড</label><div class="au-f">@@key@@<input id="au-cd" name="code" type="password" required autofocus maxlength="128" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="••••••••">@@eye@@</div></div>
<button class="au-btn">কোড যাচাই করুন @@arrow@@</button></form>""")

FORGOT_FORM = _auth_tpl("""<ol class="au-steps"><li><span>আপনার নাম, মোবাইল নম্বর ও মেম্বার আইডি সাপোর্টকে জানান।{% if tg %} <a href="{{tg}}">টেলিগ্রামে মেসেজ করুন</a>{% endif %}</span></li>
<li><span>স্টাফ একটি ৩০ মিনিটের এককালীন কোড দেবেন।</span></li><li><span>নিচে কোডটি দিয়ে নতুন পাসওয়ার্ড সেট করুন।</span></li></ol>
<form method="post" action="/reset" class="au-form"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<div class="au-fw"><label for="au-ph">মোবাইল নম্বর</label><div class="au-f">@@phone@@<input id="au-ph" name="phone" required inputmode="numeric" autocomplete="username" placeholder="01XXXXXXXXX"></div></div>
<div class="au-fw"><label for="au-cd">রিসেট কোড</label><div class="au-f">@@key@@<input id="au-cd" name="code" required autocomplete="one-time-code" autocapitalize="characters" placeholder="XXXXXXXX"></div></div>
<div class="au-fw"><label for="au-pw">নতুন পাসওয়ার্ড</label><div class="au-f">@@lock@@<input id="au-pw" name="pw" type="password" minlength="6" required autocomplete="new-password" placeholder="••••••••" data-pwmeter>@@eye@@</div>
<div class="au-meter" data-s="0"><b></b><b></b><b></b><b></b><em></em></div></div>
<button class="au-btn">পাসওয়ার্ড বদলান @@arrow@@</button></form>""")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if setting("signup_open", "1") == "0":
        err("বর্তমানে নতুন সাইন আপ বন্ধ আছে।"); return redirect("/login")
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
                alert_admins("নতুন ইউজার", "#%d %s (%s)" % (last + 1, n, p), "/admin/users/%d" % uid, "users_view")
                if referrer:
                    bonus = referral_reward_amount()
                    db().execute("INSERT INTO referrals(referrer_id,referred_id,code,amount,status,created) VALUES(?,?,?,?,?,?)",
                                 (referrer["id"], uid, code, bonus, "pending", now()))
                    notify(referrer["id"], "নতুন রেফারেল", "আপনার কোডে #%d সাইন আপ করেছেন। তার প্রথম ডিপোজিট অনুমোদিত হলে ৳%s বোনাস পাবেন।" % (last + 1, money(bonus)),
                           "/referral", "New referral", "User #%d signed up with your code. You will receive ৳%s after their first approved deposit." % (last + 1, money(bonus)))
                    db().execute("INSERT INTO audit(actor,action,detail,created,actor_id,ip) VALUES(?,?,?,?,?,?)",
                                 ("system", "referral_request", "referral for user#%d by user#%d" % (uid, referrer["id"]), now(), None, ip))
        except INTEGRITY:
            err("এই নম্বর দিয়ে আগেই অ্যাকাউন্ট আছে।"); return redirect(back)
        flash("অ্যাকাউন্ট তৈরি হয়েছে। সাইন ইন করুন।"); return redirect("/login")
    ref = re.sub(r"[^A-Z0-9]", "", request.args.get("ref", "").upper())[:12]
    return page(AUTH_TOP + SIGNUP_FORM + AUTH_BOTTOM, authpage=True, mode="up", ref=ref, disc=DISCLAIMER_EN if cur_lang() == "en" else DISCLAIMER)


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
        if ok and u["is_admin"]:
            # password verified -> NO session yet; only a short-lived pending marker until the security code is verified
            if not _tf_configured():
                err("অ্যাডমিন সিকিউরিটি কোড সার্ভারে সেট করা নেই। Render-এ ADMIN_SECURITY_CODE (বা ADMIN_2FA_CODE_HASH) সেট করে রিডেপ্লয় করুন।")
                return redirect("/login")
            session.clear()
            session["tf"] = {"uid": u["id"], "sv": u["session_ver"], "ts": int(time.time())}
            return redirect("/login/verify")
        if ok:
            session.clear(); session.permanent = True
            session["uid"], session["sv"] = u["id"], u["session_ver"]
            db().execute("UPDATE users SET last_login=? WHERE id=?", (now(), u["id"]))
            return redirect("/")
        err("নম্বর/পাসওয়ার্ড ভুল অথবা অ্যাকাউন্ট ব্লকড/নিষ্ক্রিয়।"); return redirect("/login")
    session.pop("tf", None)
    return page(AUTH_TOP + LOGIN_FORM + AUTH_BOTTOM, authpage=True, mode="in", ref="", disc=DISCLAIMER_EN if cur_lang() == "en" else DISCLAIMER)


@app.route("/login/verify", methods=["GET", "POST"])
def login_verify():
    t = session.get("tf")
    if not isinstance(t, dict) or time.time() - int(t.get("ts", 0)) > TF_TTL:
        if t:
            err("সময় শেষ হয়েছে। আবার সাইন ইন করুন।")
        session.pop("tf", None)
        return redirect("/login")
    u = q1("SELECT * FROM users WHERE id=?", (t.get("uid"),))
    if not u or not u["is_admin"] or u["blocked"] or u["session_ver"] != t.get("sv"):
        session.pop("tf", None)
        return redirect("/login")
    if request.method == "POST":
        ip, p = client_ip(), u["phone"]
        if _tf_locked(p, ip):
            session.pop("tf", None)
            err("অনেকবার ভুল কোড দেওয়া হয়েছে। ১৫ মিনিট পরে চেষ্টা করুন।"); return redirect("/login")
        ok = _tf_code_ok(request.form.get("code", "").strip()[:128])
        db().execute("INSERT INTO login_history(user_id,phone,ip,ok,created) VALUES(?,?,?,?,?)",
                     (u["id"], "2fa:" + p, ip, int(ok), now()))
        if not ok:
            audit("staff_2fa_failed", "role=%s" % u["role"], actor=u)
            if _tf_locked(p, ip):
                session.pop("tf", None)
                err("অনেকবার ভুল কোড দেওয়া হয়েছে। ১৫ মিনিট পরে চেষ্টা করুন।"); return redirect("/login")
            err("সিকিউরিটি কোড সঠিক নয়।"); return redirect("/login/verify")
        session.clear(); session.permanent = True          # session is created only now, after both factors passed
        session["uid"], session["sv"] = u["id"], u["session_ver"]
        db().execute("UPDATE users SET last_login=? WHERE id=?", (now(), u["id"]))
        audit("staff_login", "role=%s" % u["role"], actor=u)
        return redirect("/admin")
    return page(AUTH_TOP + TFA_FORM + AUTH_BOTTOM, authpage=True, mode="tf", ref="", disc=DISCLAIMER_EN if cur_lang() == "en" else DISCLAIMER)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear(); return redirect("/login")


@app.route("/forgot")
def forgot():
    return page(AUTH_TOP + FORGOT_FORM + AUTH_BOTTOM, authpage=True, mode=None, ref="", disc=DISCLAIMER_EN if cur_lang() == "en" else DISCLAIMER)


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
    s["deposit"] = one("SELECT (SELECT COALESCE(SUM(amount),0) FROM tx WHERE user_id=? AND kind='deposit' AND status='approved')"
                       "+(SELECT COALESCE(SUM(amount),0) FROM requests WHERE user_id=? AND kind='deposit' AND status='approved') s", (uid, uid))
    s["withdraw"] = one("SELECT (SELECT COALESCE(SUM(amount),0) FROM tx WHERE user_id=? AND kind='withdraw' AND status IN('approved','paid'))"
                        "+(SELECT COALESCE(SUM(amount),0) FROM requests WHERE user_id=? AND kind='withdraw' AND COALESCE(flow,'')<>'client_confirm' AND status='approved') s", (uid, uid))
    s["pending"] = one("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE user_id=? AND kind='withdraw' AND status IN('pending','processing')", (uid,))
    s["today"] = one("SELECT COALESCE(SUM(amount),0) s FROM ledger WHERE user_id=? AND kind IN('commission','referral_bonus') AND date(created)=date('now')", (uid,))
    return s


def ticker_info():
    """Active dashboard announcement (or None). Stored in settings: ticker_on / ticker_text_bn / ticker_text_en."""
    if setting("ticker_on", "0") != "1":
        return None
    t = (setting("ticker_text_" + cur_lang(), "") or setting("ticker_text_bn", "") or setting("ticker_text_en", "")).strip()
    if not t:
        return None
    return {"text": t, "dur": round(max(10.0, (len(t) * 8 + 360) / 55.0), 1)}  # ~55 px/second: comfortable reading speed


@app.route("/")
@login_required
def home():
    u = me()
    if u["is_admin"]:
        return redirect("/admin")
    expire_requests()
    req_open = q1("SELECT COUNT(*) c FROM requests WHERE user_id=? AND status='pending'", (u["id"],))["c"]
    return page("""{% if tk %}<div class="tkr" role="marquee"><span class="tkr-b">📢</span><div class="tkr-w"><div class="tkr-t" style="--d:{{tk.dur}}s">{{tk.text}}</div></div></div>{% endif %}<div class="card hero"><small>উপলব্ধ ব্যালেন্স</small><div class="bal">৳ {{money(u['balance'])}}</div>
<div class="qa"><a class="qb q1" href="/deposit"><span class="qi"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg></span><span class="ql">Add Money</span></a><a class="qb q2" href="/withdraw"><span class="qi"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 19V5M5.5 11.5 12 5l6.5 6.5"/></svg></span><span class="ql">উইথড্র</span></a><a class="qb q3" href="/requests"><span class="qi"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 13h5.2l1.3 2.5h5l1.3-2.5H21"/><path d="M5.6 5.6 3 13v5a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5l-2.6-7.4A2 2 0 0 0 16.5 4.3h-9a2 2 0 0 0-1.9 1.3z"/></svg></span><span class="ql">অনুরোধ</span>{% if req_open %}<span class="qn">{{req_open}}</span>{% endif %}</a><a class="qb q4" href="/payment-numbers"><span class="qi"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="2.5" y="5" width="19" height="14" rx="2.5"/><path d="M2.5 10h19M6.5 15h3"/></svg></span><span class="ql">Payment Methods</span></a></div></div>
<div class="g2"><div class="card"><div class="k">পেন্ডিং উইথড্র</div><div class="v">৳ {{money(s.pending)}}</div></div>
<div class="card"><div class="k">মোট ডিপোজিট</div><div class="v">৳ {{money(s.deposit)}}</div></div>
<div class="card"><div class="k">মোট উইথড্র</div><div class="v">৳ {{money(s.withdraw)}}</div></div>
<div class="card"><div class="k">মোট কমিশন</div><div class="v">৳ {{money(u['commission'])}}</div><div class="k">আপনার রেট: {{rate|pct}}%</div></div>
<div class="card"><div class="k">আজকের আয়</div><div class="v">৳ {{money(s.today)}}</div></div>
<div class="card"><div class="k">মেম্বার আইডি</div><div class="v">#{{u['member_id']}}</div></div></div>
{% if notices %}{% for n in notices %}<div class="card"><b>📢 {{n['title']}}</b><div class="k">{{n['body']}}</div></div>{% endfor %}{% endif %}
<div class="card welcome">{{welcome}}</div>""", active="/", s=stats(u["id"]), req_open=req_open, rate=effective_rate(u),
                notices=qa("SELECT * FROM notifications WHERE user_id IS NULL ORDER BY id DESC LIMIT 3"),
                welcome=setting("welcome", WELCOME_DEFAULT), tk=ticker_info())


def save_shot(f):
    if not f or not f.filename:
        return None, None
    data = f.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        return None, "স্ক্রিনশট ২ MB-এর বেশি হতে পারবে না।"
    data, ext = optimize_image(data)  # validates magic bytes + decodability, downsizes to <=1600px WebP, strips EXIF
    if not ext:
        return None, "শুধু JPG, PNG বা WEBP ছবি দিন (ছবিটি পড়া যায়নি)।"
    name = secrets.token_hex(16) + "." + ext
    try:
        store_put(name, data)
    except (StorageError, OSError):
        return None, "স্ক্রিনশট সংরক্ষণ করা যায়নি। একটু পরে আবার চেষ্টা করুন।"
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
            if q1("SELECT 1 FROM tx WHERE kind='deposit' AND norm_trx=?", (nt,)) or q1("SELECT 1 FROM requests WHERE norm_trx=?", (nt,)):
                store_delete(shot)  # don't leave an unreferenced file behind (storage is limited)
                err("এই TrxID আগেই ব্যবহার করা হয়েছে।"); return redirect("/deposit")
            db().execute("INSERT INTO tx(user_id,kind,method,amount,trx,norm_trx,screenshot,status,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (u["id"], "deposit", m, amt, trx, nt, shot, "pending", now(), now()))
            alert_admins("নতুন ডিপোজিট রিকোয়েস্ট", "#%s %s — ৳%s (%s)" % (u["member_id"], u["name"], money(amt), m), "/admin/deposits", "deposits")
            if shot:
                alert_admins("স্ক্রিনশট আপলোড", "#%s ডিপোজিটের স্ক্রিনশট দিয়েছেন" % u["member_id"], "/admin/deposits", "deposits")
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
        at = request.form.get("account_type", "").strip()
        if at not in ACCT_TYPES:
            err("পেমেন্ট অ্যাকাউন্ট টাইপ (Personal / Agent / Merchant) নির্বাচন করুন।"); return redirect("/withdraw")
        if m not in METHODS or amt < mn or not re.fullmatch(r"01\d{9}", num):
            err("মাধ্যম, ন্যূনতম ৳%s বা বেশি পরিমাণ ও সঠিক নম্বর দিন।" % int(mn)); return redirect("/withdraw")
        if rate_hit("wd:%d" % u["id"], 6, 3600):
            err("অনেক রিকোয়েস্ট হয়েছে।"); return redirect("/withdraw")
        try:
            with atomic():
                cur = db().execute("INSERT INTO tx(user_id,kind,method,amount,number,status,created,updated,account_type) VALUES(?,?,?,?,?,?,?,?,?)",
                                   (u["id"], "withdraw", m, amt, num, "pending", now(), now(), at))
                tid = cur.lastrowid
                post(u["id"], "withdraw_hold", -amt, "wd:%d:hold" % tid, "tx", tid, "Withdrawal reserved", u["member_id"])
                alert_admins("নতুন উইথড্র রিকোয়েস্ট", "#%s %s — ৳%s (%s, %s)" % (u["member_id"], u["name"], money(amt), m, at), "/admin/withdrawals", "withdrawals")
        except LedgerError:
            err("ব্যালেন্স অপর্যাপ্ত।"); return redirect("/withdraw")
        flash("উইথড্র রিকোয়েস্ট জমা হয়েছে, টাকা রিজার্ভ করা হয়েছে।"); return redirect("/history")
    return page("""<div class="card"><h2>উইথড্র</h2><p class="k">উপলব্ধ: ৳ {{money(u['balance'])}} · ন্যূনতম ৳{{mn|int}}</p>
<form method="post" data-confirm="উইথড্র রিকোয়েস্ট জমা দেবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>মাধ্যম</label><select name="method"><option>bKash</option><option>Nagad</option><option>Rocket</option></select>
<label>Payment Account Type</label><select name="account_type" required><option value="" disabled selected>নির্বাচন করুন</option><option value="Personal">Personal</option><option value="Agent">Agent</option><option value="Merchant">Merchant</option></select>
<label>পরিমাণ</label><input name="amount" type="number" step="0.01" required><label>আপনার নম্বর</label><input name="number" inputmode="numeric" maxlength="11" required>
<button style="width:100%">রিকোয়েস্ট করুন</button></form></div>""", active="/withdraw", mn=mn)


@app.route("/history")
@customer_required
def history():
    u = me()
    f = request.args.get("f", "all")
    if f not in ("all", "deposit", "withdraw"):
        f = "all"
    en = cur_lang() == "en"
    kw, ka = ("", ()) if f == "all" else (" AND kind=?", (f,))
    # real data only: tx = user-submitted deposits/withdrawals (no order id / commission stored),
    # requests = order-based requests (order_id, pay_number, commission stored)
    txs = qa("SELECT * FROM tx WHERE user_id=?" + kw + " ORDER BY id DESC LIMIT 100", (u["id"],) + ka)
    rkw = {"all": "",
           "deposit": " AND (flow='client_confirm' OR (COALESCE(flow,'')<>'admin_review' AND kind='deposit'))",
           "withdraw": " AND (flow='admin_review' OR (COALESCE(flow,'')<>'client_confirm' AND kind='withdraw'))"}[f]
    reqs = qa("SELECT * FROM requests WHERE user_id=?" + rkw + " ORDER BY id DESC LIMIT 100", (u["id"],))
    def _dk(r):  # type shown to the client follows the request type the admin chose (flow), not the wallet-direction kind
        return {"client_confirm": "deposit", "admin_review": "withdraw"}.get(r["flow"] or "", r["kind"])
    def _x(*pairs):  # extra details shown only when expanded; real stored values only
        return [(k, str(v)[:16] if k in ("sub", "upd") else str(v)) for k, v in pairs if v not in (None, "")]
    rows = [(t["created"], t["kind"], None, t["method"], t["number"], t["amount"], t["status"], None,
             _x(("trx", t["trx"])), t["kind"]) for t in txs] + \
           [(r["created"], r["kind"], r["order_id"], r["method"], r["pay_number"], r["amount"], r["status"], r["commission"],
             _x(("trx", r["trx"]),
                ("why", r["reject_reason"] if r["status"] == "rejected" else None), ("ins", r["instructions"])), _dk(r)) for r in reqs]
    rows.sort(key=lambda x: str(x[0] or ""), reverse=True)
    items = []
    for created, kind, order, method, number, amount, status, comm, extra, dkind in rows[:100]:
        amt = "৳ " + money(amount)
        tone = ""
        if kind == "withdraw" and status in ("pending", "submitted", "review", "processing", "approved"):
            amt, tone = "\u2212" + amt, "neg"
        elif kind == "deposit" and status == "approved":
            amt, tone = "+" + amt, "pos"
        if status == "processing":
            slabel = "Processing" if en else "প্রসেসিং"
        else:
            slabel = REQ_LABEL.get(status, status)
        items.append(dict(order=order or "", method=method or "", number=number or "", kind=REQ_KIND.get(dkind, dkind), dk=dkind,
                          amt=amt, tone=tone, status=slabel,
                          cls="pending" if status in ("submitted", "review") else status,
                          comm=("৳ " + money(comm)) if comm is not None else "", when=str(created or "")[:16], extra=extra))
    led = qa("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 100", (u["id"],))
    if f == "all":
        user_seen(lambda link, title, ts: _user_badge_key(link, title) == "/history")
    L = (dict(order="Order ID", method="Method", number="Number", kind="Type", amount="Amount", status="Status",
              comm="Commission", when="Date & Time", trx="TrxID", sub="Submitted", upd="Updated", why="Rejection reason", ins="Instructions", more="Details") if en else
         dict(order="অর্ডার আইডি", method="মাধ্যম", number="নম্বর", kind="ধরন", amount="পরিমাণ", status="অবস্থা",
              comm="কমিশন", when="তারিখ ও সময়", trx="ট্রানজেকশন আইডি", sub="জমার সময়", upd="আপডেট", why="রিজেক্টের কারণ", ins="নির্দেশনা", more="বিস্তারিত"))
    tabs = [("all", "All" if en else "সব"), ("deposit", "Deposit" if en else "ডিপোজিট"), ("withdraw", "Withdraw" if en else "উইথড্র")]
    return page("""<style>
.hxt{gap:8px;background:none;border:0;padding:0;margin-bottom:12px}
.hxt a{border:1.5px solid #CFEAE8;background:linear-gradient(180deg,#F4FCFB 0%,#DFF7F5 100%);border-radius:12px;padding:10px 4px;font-weight:700;font-size:14px;color:#4C6A82;text-decoration:none;touch-action:manipulation;-webkit-tap-highlight-color:transparent;box-shadow:0 1px 2px #1E90FF10,inset 0 1px 0 #ffffffcc;transition:background .25s ease,color .25s ease,border-color .25s ease,box-shadow .25s ease,transform .15s ease}
.hxt a:active{transform:scale(.97)}
.hxt a.on{background:linear-gradient(180deg,#2F9BFF 0%,#1668D0 100%);border-color:#1668D0;color:#fff;box-shadow:0 5px 14px -4px #1668D08c,inset 0 1px 0 #ffffff38}
:root[data-theme=dark] .hxt a{border-color:#1E4157;background:linear-gradient(180deg,#0F2A3D 0%,#0B2132 100%);color:#9FD6FF;box-shadow:0 1px 2px #0006,inset 0 1px 0 #ffffff0d}
:root[data-theme=dark] .hxt a.on{background:linear-gradient(180deg,#2F9BFF 0%,#1668D0 100%);border-color:#2F9BFF;color:#fff;box-shadow:0 5px 14px -4px #0009,inset 0 1px 0 #ffffff38}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]) .hxt a{border-color:#1E4157;background:linear-gradient(180deg,#0F2A3D 0%,#0B2132 100%);color:#9FD6FF;box-shadow:0 1px 2px #0006,inset 0 1px 0 #ffffff0d}:root:not([data-theme=light]) .hxt a.on{background:linear-gradient(180deg,#2F9BFF 0%,#1668D0 100%);border-color:#2F9BFF;color:#fff;box-shadow:0 5px 14px -4px #0009,inset 0 1px 0 #ffffff38}}
.hxc.hy{padding:11px 13px;margin-bottom:9px;border-radius:16px;box-shadow:0 1px 4px #0A3D660f;position:relative;overflow:hidden}
.hxc.hy.hy-pending::before{content:"";position:absolute;left:0;top:10px;bottom:10px;width:2px;border-radius:2px;background:#f59e0b;opacity:.55}
.hxc.hy.open{border-color:#1E90FF;box-shadow:0 3px 12px #0A3D6618}
.hxc.hy{background:#FFFFFF;background-image:linear-gradient(180deg,#FFFFFF 0%,#F6FDFC 100%);border-color:#D6EFEC;box-shadow:0 1px 3px #0a5a8c14,0 4px 12px -6px #0a5a8c24}
.hxc.hy.open{box-shadow:0 4px 16px -4px #1E90FF38}
.hxc.hy .hy-g,.hxc.hy .hy-g .hxr,.hy .hxd .hxr:first-child{border-color:#D6EFEC}
.hxc.hy .hy-tt .pill{box-shadow:inset 0 0 0 1px #0000000f}
.hxc.hy .hy-tt .pill.expired,.hxc.hy .hy-tt .pill.cancelled{background:#E3EEF0;color:#4C6573}
.hxc.hy .hy-cm{background:#1E90FF14;border-color:#1E90FF33}
:root[data-theme=dark] .hxc.hy{background:#0E1F31;background-image:linear-gradient(180deg,#10263B 0%,#0B1B2C 100%);border-color:#1E3A52;box-shadow:0 1px 3px #0006}
:root[data-theme=dark] .hxc.hy.open{border-color:#1E90FF;box-shadow:0 4px 16px -4px #0009}
:root[data-theme=dark] .hxc.hy .hy-g,:root[data-theme=dark] .hy .hxd .hxr:first-child{border-color:#1E3A52}
:root[data-theme=dark] .hxc.hy .hy-tt .pill{box-shadow:inset 0 0 0 1px #ffffff12}
:root[data-theme=dark] .hxc.hy .hy-tt .pill.expired,:root[data-theme=dark] .hxc.hy .hy-tt .pill.cancelled{background:#17303F;color:#9DB4C4}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]) .hxc.hy{background:#0E1F31;background-image:linear-gradient(180deg,#10263B 0%,#0B1B2C 100%);border-color:#1E3A52;box-shadow:0 1px 3px #0006}:root:not([data-theme=light]) .hxc.hy.open{border-color:#1E90FF;box-shadow:0 4px 16px -4px #0009}:root:not([data-theme=light]) .hxc.hy .hy-g,:root:not([data-theme=light]) .hy .hxd .hxr:first-child{border-color:#1E3A52}:root:not([data-theme=light]) .hxc.hy .hy-tt .pill{box-shadow:inset 0 0 0 1px #ffffff12}:root:not([data-theme=light]) .hxc.hy .hy-tt .pill.expired,:root:not([data-theme=light]) .hxc.hy .hy-tt .pill.cancelled{background:#17303F;color:#9DB4C4}}
.hy-top{display:flex;align-items:center;gap:10px}
.hy-ic{flex:none;width:36px;height:36px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:17px;font-weight:800;line-height:1;background:#1E90FF14;color:var(--bt)}
.hy-ic.deposit{background:#0EA37117;color:#0B7A50}
.hy-tt{flex:1;min-width:0;display:flex;flex-direction:column;gap:3px;align-items:flex-start}
.hy-tt b{font-size:15.5px;font-weight:800;line-height:1.25}
.hxc.hy .hy-tt .pill{padding:1px 9px;font-size:12px;font-weight:700;line-height:1.5;border-radius:99px;background:#E8F3F4;color:#456170;white-space:nowrap}
.hxc.hy .hy-tt .pill::before{content:"";display:inline-block;width:6px;height:6px;margin:0 5px 1px 0;border-radius:50%;background:currentColor}
.hxc.hy .hy-tt .pill::after{content:none}
.hxc.hy .hy-tt .pill.pending,.hxc.hy .hy-tt .pill.review,.hxc.hy .hy-tt .pill.processing,.hxc.hy .hy-tt .pill.submitted{background:#fef3c7;color:#b45309}
.hxc.hy .hy-tt .pill.approved,.hxc.hy .hy-tt .pill.paid{background:#DDF8EC;color:#0B7A50}
.hxc.hy .hy-tt .pill.rejected{background:#FFE4E6;color:#b91c1c}
.hxc.hy .hy-tt .pill.expired,.hxc.hy .hy-tt .pill.cancelled{background:#E8F3F4;color:#5A7587}
.hy-am{flex:none;font-size:17px;font-weight:800;line-height:1.2;white-space:nowrap;letter-spacing:-.2px}
.hy-am.neg{color:#dc2626}.hy-am.pos{color:var(--okt)}
.hy-g{display:grid;grid-template-columns:1fr 1fr;gap:8px 12px;margin-top:10px;padding-top:9px;border-top:1px solid var(--ln)}
.hy-g>div{min-width:0}
.hy-g span{display:block;font-size:12px;color:var(--mut);margin-bottom:1px;font-weight:500}
.hy-g b{display:block;font-size:14px;font-weight:650;line-height:1.3;overflow-wrap:anywhere}
.hy-g .na{color:var(--mut);font-weight:400}
.hy-cm{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:9px;padding:7px 11px;border-radius:11px;background:#1E90FF12;border:1px solid #1E90FF26}
.hy-cm>span{font-size:14px;font-weight:700;color:var(--bt);min-width:0}
.hy-cm>b{flex:none;font-size:16px;font-weight:800;color:#0B7A50;white-space:nowrap}
.hy-cm>b.na{font-size:15px;color:var(--mut);font-weight:500}
.hy-cm .gft{font-size:15px;margin-right:4px}
:root[data-theme=dark] .hy-cm>span{color:#9FD6FF}
:root[data-theme=dark] .hy-cm>b{color:#7FE3B8}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]) .hy-cm>span{color:#9FD6FF}:root:not([data-theme=light]) .hy-cm>b{color:#7FE3B8}}
.hy-more{display:flex;align-items:center;justify-content:center;gap:4px;margin-top:7px;font-size:12.5px;color:var(--mut);font-weight:500}
.hy-more i{font-style:normal;transition:transform .25s}.hxc.open .hy-more i{transform:rotate(180deg)}
.hy .hxd .hxr:first-child{margin-top:6px;padding-top:8px;border-top:1px solid var(--ln)}
.hy .hxd .hxr,.hxc.open.hy .hxd .hxr{font-size:13.5px;padding:5px 0}
@media(max-width:380px){.hxc.hy{padding:10px 11px}.hy-ic{width:32px;height:32px;font-size:16px}.hy-tt b{font-size:15px}.hy-am{font-size:16px}.hy-g{gap:8px 8px}.hy-g b{font-size:13.5px}.hy-cm>b{font-size:15.5px}}
</style>
<div class="hxt">{% for k,lb in tabs %}<a class="{{'on' if f==k}}" href="/history{{'' if k=='all' else '?f='+k}}">{{lb}}</a>{% endfor %}</div>
{% if not items %}<div class="card"><div class="empty">কোনো লেনদেন নেই</div></div>{% endif %}
{% for it in items %}<div class="hxc hy hy-{{it.cls}}" role="button" tabindex="0" aria-expanded="false">
<div class="hy-top"><span class="hy-ic {{it.dk}}">{{'↓' if it.dk=='deposit' else '↑'}}</span>
<div class="hy-tt"><b>{{it.kind}}</b><span class="pill {{it.cls}}">{{it.status}}</span></div>
<b class="hy-am {{it.tone}}">{{it.amt}}</b></div>
<div class="hy-g">
<div><span>{{L.order}}</span><b>{% if it.order %}{{it.order}}{% else %}<span class="na">—</span>{% endif %}</b></div>
<div><span>{{L.method}}</span><b>{{it.method or '—'}}</b></div>
<div><span>{{L.number}}</span><b>{{it.number or '—'}}</b></div>
<div><span>{{L.when}}</span><b>{{it.when or '—'}}</b></div></div>
<div class="hy-cm"><span><span class="gft">🎁</span>{{L.comm}}</span>{% if it.comm %}<b>{{it.comm}}</b>{% else %}<b class="na">—</b>{% endif %}</div>
{% if it.extra %}<div class="hy-more">{{L.more}} <i>▾</i></div>
<div class="hxd"><div>{% for k,v in it.extra %}<div class="hxr"><span>{{L[k]}}</span><b{% if k in ('why','ins') %} style="white-space:pre-line;font-weight:500"{% endif %}>{{v}}</b></div>{% endfor %}</div></div>{% endif %}</div>{% endfor %}
<script>(function(){if(window._hxInit)return;window._hxInit=1;function t(c){var o=!c.classList.contains('open');c.classList.toggle('open',o);c.setAttribute('aria-expanded',o?'true':'false');document.body.classList.toggle('hx1',o);if(o){window.scrollTo(0,0)}else{c.scrollIntoView({block:'center'})}}
document.addEventListener('click',function(e){var c=e.target.closest&&e.target.closest('.hxc');if(c)t(c)});
document.addEventListener('keydown',function(e){if((e.key==='Enter'||e.key===' ')&&e.target.classList&&e.target.classList.contains('hxc')){e.preventDefault();t(e.target)}})})();</script>
<div class="card hxl"><h2>ওয়ালেট লেজার</h2><div class="tw"><table><tr><th>ধরন</th><th>৳</th><th>নোট</th><th>সময়</th></tr>
{% for l in led %}<tr><td>{{l['kind']}}</td><td style="color:{{'var(--okt)' if l['amount']>=0 else '#dc2626'}}">{{money(l['amount'])}}</td><td>{{l['note'] or ''}}</td><td>{{l['created'][:16]}}</td></tr>{% endfor %}</table></div></div>""",
                active="/history", items=items, led=led, L=L, tabs=tabs, f=f)


@app.route("/shot/<name>")
@login_required
def shot(name):
    if not re.fullmatch(r"[0-9a-f]{32}\.(jpg|png|webp)", name):
        abort(404)
    u = me()
    t = q1("SELECT user_id FROM tx WHERE screenshot=?", (name,))
    if t:
        staff_ok = has_perm("deposits", u) or has_perm("withdrawals", u)
    else:  # screenshots of admin-sent manual requests
        t = q1("SELECT user_id FROM requests WHERE screenshot=?", (name,))
        staff_ok = has_perm("requests", u)
    if not t or (u["id"] != t["user_id"] and not staff_ok):
        abort(404)
    try:
        data = store_get(name)
    except StorageError:
        abort(503)
    if data is None:
        abort(404)
    resp = send_file(io.BytesIO(data), mimetype=MIME[name.rsplit(".", 1)[1]])
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/notifications")
@customer_required
def notifications():
    u = me()
    rows = qa("SELECT * FROM notifications WHERE user_id=? OR user_id IS NULL ORDER BY id DESC LIMIT 50", (u["id"],))
    return page("""<h2>নোটিফিকেশন</h2>{% if not rows %}<div class="card empty">কোনো নোটিফিকেশন নেই</div>{% endif %}
<div id="nlist" data-csrf="{{csrf_token}}">{% for n in rows %}<div class="card{{' new' if n['user_id'] and not n['is_read'] else ''}}"{% if n['user_id'] and not n['is_read'] %} data-nid="{{n['id']}}"{% endif %}><b>{{(n['title_en'] if lang=='en' and n['title_en'] else n['title'])}}</b><div>{{(n['body_en'] if lang=='en' and n['body_en'] else n['body'])}}</div><div class="k">{{n['created'][:16]}}</div>
{% if n['link'] %}<a class="btn sm" href="{{n['link']}}" style="margin-top:8px">খুলুন</a>{% endif %}</div>{% endfor %}</div>
<script>(function(){function go(){if(typeof autoRead==='function')autoRead();else setTimeout(go,50)}go()})()</script>""", rows=rows)


@app.route("/insight")
@customer_required
def insight():
    return page("""<div class="card"><h2>ইনসাইট</h2><div class="row"><a class="btn sm s" href="#" onclick="load(7);return false">৭ দিন</a>
<a class="btn sm s" href="#" onclick="load(30);return false">৩০ দিন</a><a class="btn sm s" href="#" onclick="load(90);return false">৯০ দিন</a></div>
<p class="k">🟦 ডিপোজিট &nbsp; 🟥 উইথড্র &nbsp; 🟩 কমিশন ও রেফারেল</p><canvas id="ch"></canvas><div id="sum" class="k"></div></div>
<script>function load(d){fetch('/insight/data?days='+d).then(r=>r.json()).then(j=>{bars('ch',j.labels,[j.deposit,j.withdraw,j.commission],['#1E90FF','#EF4444','#2BC4A8']);
document.getElementById('sum').textContent='মোট ডিপোজিট ৳'+j.t[0]+' · উইথড্র ৳'+j.t[1]+' · আয় ৳'+j.t[2]})}load(7)</script>""", active="/insight")


def series(uid, days):
    start = (datetime.utcnow() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    w, wa = (" AND user_id=?", (uid,)) if uid else ("", ())

    def grp(table, col, cond):  # {YYYY-MM-DD (UTC): sum} in one grouped query
        rows = qa("SELECT substr(%s,1,10) d, COALESCE(SUM(amount),0) s FROM %s WHERE %s%s AND substr(%s,1,10)>=? GROUP BY 1" % (col, table, cond, w, col),
                  wa + (start,))
        return {r["d"]: float(r["s"]) for r in rows}
    dep_t = grp("tx", "updated", "kind='deposit' AND status='approved'")
    dep_r = grp("requests", "decided_at", "kind='deposit' AND status='approved'")
    wd_t = grp("tx", "updated", "kind='withdraw' AND status IN('approved','paid')")
    wd_r = grp("requests", "decided_at", "kind='withdraw' AND COALESCE(flow,'')<>'client_confirm' AND status='approved'")
    com_l = grp("ledger", "created", "kind IN('commission','referral_bonus')")
    labels, dep, wd, com = [], [], [], []
    for i in range(days - 1, -1, -1):
        d = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        labels.append(d[5:])
        dep.append(round(round(dep_t.get(d, 0), 2) + round(dep_r.get(d, 0), 2), 2))
        wd.append(round(round(wd_t.get(d, 0), 2) + round(wd_r.get(d, 0), 2), 2))
        com.append(round(com_l.get(d, 0), 2))
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
    st = q1("""SELECT COUNT(*) total, COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0) pend,
               COALESCE(SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END),0) appr,
               COALESCE(SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END),0) rej,
               COALESCE(SUM(CASE WHEN status='approved' THEN amount END),0) earned FROM referrals WHERE referrer_id=?""", (u["id"],))
    rows = qa("""SELECT r.*, x.name x_name, x.member_id x_mid FROM referrals r JOIN users x ON x.id=r.referred_id
                 WHERE r.referrer_id=? ORDER BY r.id DESC LIMIT 100""", (u["id"],))
    by = q1("SELECT member_id,name FROM users WHERE id=?", (u["referred_by"],)) if u["referred_by"] else None
    link = ref_link(u["referral_code"])
    user_seen(lambda lk, title, ts: _user_badge_key(lk, title) == "/referral")
    bonus = referral_reward_amount()
    text = "%s-এ যোগ দিন! আমার রেফারেল কোড: %s" % (SITE, u["referral_code"])
    return page("""<div class="card hero"><small>আপনার রেফারেল কোড</small><div class="code">{{u['referral_code']}}</div>
<div class="copybox" style="color:var(--tx)">{{link}}</div>
<div class="row"><button class="btn w" data-copy="{{link}}">📋 লিংক কপি</button><button class="btn w" data-share="{{link}}" data-text="{{text}}">📤 শেয়ার</button></div>
<div class="row" style="margin-top:10px"><button class="btn w" data-copy="{{u['referral_code']}}">কোড কপি</button>
<a class="btn w" target="_blank" rel="noopener" href="https://wa.me/?text={{(text+' '+link)|urlencode}}">WhatsApp</a></div></div>
<div class="card"><b>🎁 বর্তমান রিওয়ার্ড: প্রতি সফল রেফারে ৳{{money(bonus)}}</b><div class="k">যত খুশি মানুষকে রেফার করতে পারেন। শুধু সাইন আপ করলে বোনাস হয় না — আপনার রেফার করা প্রত্যেক ব্যক্তির প্রথম ডিপোজিট অনুমোদিত হলে, সেই ব্যক্তির জন্য একবার ৳{{money(bonus)}} আপনার ওয়ালেটে যুক্ত হয়।</div>
{% if by %}<div class="k" style="margin-top:6px">আপনাকে রেফার করেছেন: #{{by['member_id']}} {{by['name']}}</div>{% endif %}</div>
<div class="g2"><div class="card"><div class="k">মোট রেফার</div><div class="v">{{st['total']}}</div></div>
<div class="card"><div class="k">প্রথম ডিপোজিট বাকি</div><div class="v">{{st['pend']}}</div></div>
<div class="card"><div class="k">রিওয়ার্ড পেইড</div><div class="v">{{st['appr']}}</div></div>
<div class="card"><div class="k">মোট রেফারেল আয়</div><div class="v">৳ {{money(st['earned'])}}</div></div></div>
<div class="card"><h3>রেফারেল ইতিহাস</h3>{% if not rows %}<div class="empty">এখনো কেউ আপনার কোডে যোগ দেয়নি</div>{% else %}<div class="tw"><table>
<tr><th>সদস্য</th><th>৳</th><th>অবস্থা</th><th>তারিখ</th></tr>{% for r in rows %}<tr><td>#{{r['x_mid']}} {{r['x_name']}}</td><td>{{money(r['amount'] if r['status']=='approved' else bonus) if r['status']!='rejected' else '-'}}</td>
<td><span class="pill {{r['status']}}">{{ {'pending':'ডিপোজিটের অপেক্ষায়','approved':'পেইড','rejected':'বাতিল'}[r['status']] }}</span></td><td>{{r['created']|bdd}}</td></tr>{% endfor %}</table></div>{% endif %}</div>""",
                active="/account", st=st, rows=rows, by=by, link=link, text=text, bonus=bonus)


@app.route("/support", methods=["GET", "POST"])
@customer_required
def support():
    u = me()
    if request.method == "POST":
        s, m = request.form.get("subject", "").strip()[:100], request.form.get("message", "").strip()[:1000]
        if not s or not m:
            err("বিষয় ও বার্তা দিন।"); return redirect("/support")
        db().execute("INSERT INTO tickets(user_id,subject,message,created) VALUES(?,?,?,?)", (u["id"], s, m, now()))
        alert_admins("নতুন সাপোর্ট বার্তা", "#%s %s: %s" % (u["member_id"], u["name"], s), "/admin/tickets", "tickets")
        flash("টিকিট জমা হয়েছে।"); return redirect("/support")
    rows = qa("SELECT * FROM tickets WHERE user_id=? ORDER BY id DESC LIMIT 30", (u["id"],))
    user_seen(lambda link, title, ts: _user_badge_key(link, title) == "/support")
    return page("""<div class="card"><h2>সাপোর্ট</h2>{% if tg %}<a class="btn g" href="{{tg}}" target="_blank" rel="noopener" style="width:100%;margin-bottom:12px">✈ {{tg_label}}</a>{% endif %}
<form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}"><label>বিষয়</label><input name="subject" required maxlength="100">
<label>বার্তা</label><textarea name="message" rows="3" required maxlength="1000"></textarea><button style="width:100%">টিকিট জমা দিন</button></form></div>
{% for t in rows %}<div class="card"><b>{{t['subject']}}</b> <span class="pill {{'approved' if t['status']=='closed' else 'pending'}}">{{t['status']}}</span>
<div>{{t['message']}}</div>{% if t['reply'] %}<div class="k" style="margin-top:8px">↳ সাপোর্ট: {{t['reply']}}</div>{% endif %}</div>{% endfor %}""", active="/account", rows=rows)


ACCOUNT_SOON = {"kyc": ("🪪", "KYC যাচাই"), "vip": ("👑", "VIP লেভেল"), "language": ("🌐", "ভাষা")}


def _change_password(u, back_to):
    if not check_password_hash(u["pw"], request.form.get("old", "")) or len(request.form.get("new", "")) < 6:
        err("পুরনো পাসওয়ার্ড ভুল অথবা নতুন পাসওয়ার্ড ৬ অক্ষরের কম।"); return redirect(back_to)
    db().execute("UPDATE users SET pw=?, session_ver=session_ver+1 WHERE id=?", (generate_password_hash(request.form["new"]), u["id"]))
    session.clear(); flash("পাসওয়ার্ড বদলেছে। আবার সাইন ইন করুন।"); return redirect("/login")


@app.route("/account", methods=["GET", "POST"])
@customer_required
def account():
    u = me()
    if request.method == "POST":
        return _change_password(u, "/account")
    return page("""<div class="hero2"><div style="font-size:21px;font-weight:700">{{u['name']}}</div>
<div style="opacity:.92;margin-top:4px">📱 {{u['phone']}} &nbsp;·&nbsp; 🆔 #{{u['member_id']}}</div>
<div style="opacity:.92;margin-top:8px">ব্যালেন্স: <b>৳ {{money(u['balance'])}}</b></div></div>
<div class="card menu">
<a class="li" href="/kyc"><span class="ic">🪪</span><span class="lt">KYC যাচাই</span><span class="ch">›</span></a>
<a class="li" href="/account/soon/vip"><span class="ic">👑</span><span class="lt">VIP লেভেল</span><span class="ch">›</span></a>
<a class="li" href="/referral"><span class="ic">🎁</span><span class="lt">ইনভাইট ও আর্ন</span><span class="bd" data-bd="/referral"{% if not nb('/referral') %} hidden{% endif %}>{{nb('/referral')}}</span><span class="ch">›</span></a>
<button type="button" class="li" onclick="toggleTheme()"><span class="ic">🌙</span><span class="lt">ডার্ক মোড</span><span class="k" id="thv"></span></button>
<a class="li" href="/notifications"><span class="ic">🔔</span><span class="lt">নোটিফিকেশন</span>{% if unread %}<span class="bd">{{unread}}</span>{% endif %}<span class="ch">›</span></a>
<button type="button" class="li" onclick="setSnd(!sndOn())"><span class="ic">🔊</span><span class="lt">নোটিফিকেশন সাউন্ড</span><span class="k" id="sndv"></span></button>
<button type="button" class="li" onclick="enableBrowserNotif()"><span class="ic">📲</span><span class="lt">ব্রাউজার নোটিফিকেশন</span><span class="k" id="bnv"></span></button>
<a class="li" href="/lang/{{'bn' if lang=='en' else 'en'}}?next=/account"><span class="ic">🌐</span><span class="lt">ভাষা</span><span class="k">{{'বাংলা (Bangla)' if lang=='en' else 'English'}}</span><span class="ch">›</span></a>
<a class="li" href="/account/settings"><span class="ic">⚙️</span><span class="lt">সেটিংস</span><span class="ch">›</span></a>
<a class="li" href="/payment-numbers"><span class="ic">💳</span><span class="lt">পেমেন্ট নম্বর ব্যবস্থাপনা</span><span class="bd" data-bd="/payment-numbers"{% if not nb('/payment-numbers') %} hidden{% endif %}>{{nb('/payment-numbers')}}</span><span class="ch">›</span></a>
<a class="li" href="/support"><span class="ic">💬</span><span class="lt">সাপোর্ট</span><span class="bd" data-bd="/support"{% if not nb('/support') %} hidden{% endif %}>{{nb('/support')}}</span><span class="ch">›</span></a>
<a class="li" href="/feedback"><span class="ic">📝</span><span class="lt">ফিডব্যাক</span><span class="ch">›</span></a>
<a class="li" href="/about"><span class="ic">ℹ️</span><span class="lt">আমাদের সম্পর্কে</span><span class="ch">›</span></a>
<form method="post" action="/logout"><input type="hidden" name="_csrf" value="{{csrf_token}}"><button class="li out"><span class="ic">🚪</span><span class="lt">লগআউট</span></button></form>
</div>""", active="/account")


@app.route("/account/settings", methods=["GET", "POST"])
@customer_required
def account_settings():
    u = me()
    if request.method == "POST":
        return _change_password(u, "/account/settings")
    hist = qa("SELECT * FROM login_history WHERE user_id=? ORDER BY id DESC LIMIT 8", (u["id"],))
    return page("""<div class="card"><h2>সেটিংস</h2><p>📱 {{u['phone']}}<br>🆔 #{{u['member_id']}}</p></div>
<div class="card"><h3>পাসওয়ার্ড বদলান</h3><form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>পুরনো পাসওয়ার্ড</label><input name="old" type="password" required><label>নতুন পাসওয়ার্ড</label><input name="new" type="password" minlength="6" required>
<button style="width:100%">বদলান</button></form></div>
<div class="card"><h3>সাম্প্রতিক লগইন</h3><div class="tw"><table>{% for h in hist %}<tr><td>{{h['created'][:16]}}</td><td>{{h['ip']}}</td><td>{{'✅' if h['ok'] else '❌'}}</td></tr>{% endfor %}</table></div></div>
<div class="card"><a href="/about">শর্তাবলি</a></div>""", active="/account", hist=hist)


@app.route("/account/soon/<name>")
@customer_required
def account_soon(name):
    if name not in ACCOUNT_SOON:
        abort(404)
    ic, t = ACCOUNT_SOON[name]
    return page("""<div class="card empty"><div style="font-size:44px">{{ic}}</div><h2>{{t}}</h2><p>এই ফিচারটি শীঘ্রই আসছে।</p>
<a class="btn" href="/account">← অ্যাকাউন্টে ফিরুন</a></div>""", active="/account", ic=ic, t=t)


@app.route("/feedback", methods=["GET", "POST"])
@customer_required
def feedback():
    u = me()
    if request.method == "POST":
        m = request.form.get("message", "").strip()[:1000]
        if len(m) < 3:
            err("আপনার মতামত লিখুন।"); return redirect("/feedback")
        if rate_hit("fb:%d" % u["id"], 5, 3600):
            err("অনেক রিকোয়েস্ট হয়েছে, পরে চেষ্টা করুন।"); return redirect("/feedback")
        db().execute("INSERT INTO tickets(user_id,subject,message,created) VALUES(?,?,?,?)", (u["id"], "ফিডব্যাক", m, now()))
        alert_admins("নতুন ফিডব্যাক", "#%s %s" % (u["member_id"], u["name"]), "/admin/tickets", "tickets")
        flash("ধন্যবাদ! আপনার ফিডব্যাক পাঠানো হয়েছে।"); return redirect("/account")
    return page("""<div class="card"><h2>ফিডব্যাক</h2><p class="k">আমাদের সেবা কেমন লাগছে বা কী উন্নতি করা যায়, জানান।</p>
<form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}"><label>আপনার মতামত</label>
<textarea name="message" rows="5" maxlength="1000" required></textarea><button style="width:100%">পাঠান</button></form></div>""", active="/account")


# ---------------------------------------------------------------- admin: shared pieces
REF_SQL = """SELECT r.*, rf.member_id rf_mid, rf.name rf_name, rf.phone rf_phone, x.member_id x_mid, x.name x_name, x.phone x_phone,
 (COALESCE(x.signup_ip,'')<>'' AND (x.signup_ip=rf.signup_ip OR EXISTS(SELECT 1 FROM login_history h WHERE h.user_id=rf.id AND h.ip=x.signup_ip))) same_ip,
 ((SELECT COUNT(*) FROM tx d WHERE d.user_id=r.referred_id AND d.kind='deposit' AND d.status='approved')
  +(SELECT COUNT(*) FROM requests q WHERE q.user_id=r.referred_id AND q.kind='deposit' AND COALESCE(q.flow,'')='' AND q.status='approved')) dep_n
 FROM referrals r JOIN users rf ON rf.id=r.referrer_id JOIN users x ON x.id=r.referred_id"""

REF_LIST = """{% if not rows %}<div class="card empty">কোনো রেফারেল রিকোয়েস্ট নেই</div>{% endif %}
{% for r in rows %}<div class="card"><div class="row" style="align-items:center"><b>৳ {{money(r['amount'] if r['status']=='approved' else ref_reward())}}</b><span class="pill {{r['status']}}" style="flex:0">{{r['status']}}</span></div>
<div class="k">রেফারার: <a href="/admin/referrals/user/{{r['referrer_id']}}"><b>#{{r['rf_mid']}} {{r['rf_name']}}</b></a> · {{r['rf_phone']}}</div>
<div class="k">নতুন ইউজার: <a href="/admin/referrals/user/{{r['referred_id']}}"><b>#{{r['x_mid']}} {{r['x_name']}}</b></a> · {{r['x_phone']}} · {{r['created'][:16]}}</div>
{% if r['same_ip'] and r['status']=='pending' %}<div class="msg error" style="margin:6px 0">⚠ একই আইপি থেকে সাইন আপ/লগইন — যাচাই করুন</div>{% endif %}
{% if r['status']!='pending' %}<div class="k">সিদ্ধান্ত: {{r['decided_by']}} · {{(r['decided_at'] or '')[:16]}}{% if r['note'] %} · {{r['note']}}{% endif %}</div>
{% elif can('referrals') %}{% if not r['dep_n'] %}<div class="k">⏳ রেফার করা ইউজারের প্রথম অনুমোদিত ডিপোজিটের অপেক্ষায় — ডিপোজিট অনুমোদিত হলে রিওয়ার্ড স্বয়ংক্রিয়ভাবে যুক্ত হবে।</div>{% endif %}<form method="post" action="/admin/referrals/{{r['id']}}" style="margin-top:8px" data-confirm="নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<input name="note" placeholder="নোট (ঐচ্ছিক)" maxlength="200"><div class="row">{% if r['dep_n'] %}<button name="act" value="approve" class="btn sm g">✅ রিওয়ার্ড দিন</button>{% endif %}<button name="act" value="reject" class="btn sm r">❌ বাতিল</button></div></form>{% endif %}</div>{% endfor %}"""


def back(default="/admin"):
    ref = request.referrer or ""
    return redirect(ref if ref.startswith(request.host_url) else default)


# ---------------------------------------------------------------- admin: dashboard
ACTIVITY_SQL = """SELECT created t, 'নতুন ইউজার: #'||COALESCE(member_id,'')||' '||COALESCE(name,'') d FROM users WHERE is_admin=0
UNION ALL SELECT l.created, 'লগইন: '||COALESCE(u.name,l.phone,'') FROM login_history l LEFT JOIN users u ON u.id=l.user_id
          WHERE l.ok=1 AND COALESCE(u.is_admin,0)=0
UNION ALL SELECT t.created, (CASE t.kind WHEN 'deposit' THEN 'ডিপোজিট' ELSE 'উইথড্র' END)||' ৳'||t.amount||' — '||u.name
          FROM tx t JOIN users u ON u.id=t.user_id
UNION ALL SELECT r.submitted_at, 'রিকোয়েস্ট জমা '||r.order_id||' — '||u.name FROM requests r JOIN users u ON u.id=r.user_id
          WHERE r.submitted_at IS NOT NULL
ORDER BY t DESC LIMIT 10"""


INTEG_TPL = """<div class="card"><b>লেজার রিকনসিলিয়েশন:</b>
{% if bad %}<span class="pill rejected">{{bad|length}}টি অমিল</span>{% for b in bad %}<div class="k">#{{b['member_id']}}: ব্যালেন্স {{b['balance']}} ≠ লেজার {{b['ledger_sum']}}</div>{% endfor %}
{% else %}<span class="pill approved">সব মিলেছে ✅</span>{% endif %}</div>
{% if rc %}<a class="card" href="/admin/reconcile" style="display:block"><b>🧮 পূর্ণ মিলানো (ওয়ালেট · পুল · কোম্পানি-লেজার):</b> <span class="pill {{'approved' if rc=='ok' else 'rejected'}}">{{'সব মিলেছে ✅' if rc=='ok' else ('দেখা দরকার ⚠' if rc=='warn' else 'গরমিল ❌')}}</span></a>{% endif %}"""


@app.route("/admin/dash/integrity")
@staff_required("dashboard_fin")
def admin_dash_integrity():
    """Heavy ledger reconciliation, computed after the dashboard is already on screen (same data and permissions as before)."""
    rc = recon_overall(recon_checks()) if has_perm("reports") else None
    return render_str(INTEG_TPL, bad=reconcile(), rc=rc)


@app.route("/admin")
@staff_required()
def admin_home():
    u = me()
    expire_requests()
    one = lambda sql: q1(sql)["s"]
    fin = has_perm("dashboard_fin", u)
    s = dict(open_tickets=one("SELECT COUNT(*) s FROM tickets WHERE status='open'"),
             total=one("SELECT COUNT(*) s FROM users WHERE is_admin=0"),
             active=one("SELECT COUNT(*) s FROM users WHERE is_admin=0 AND blocked=0"),
             blocked=one("SELECT COUNT(*) s FROM users WHERE is_admin=0 AND blocked=1"),
             active30=one("SELECT COUNT(*) s FROM users WHERE is_admin=0 AND blocked=0 AND last_login>=datetime('now','-30 days')"),
             pend_req=one("SELECT COUNT(*) s FROM requests WHERE status IN('submitted','review')"))
    bad, pend, acts, rc = [], [], [], None
    if fin:
        s.update(
            liability=one("SELECT COALESCE(SUM(balance),0) s FROM users WHERE is_admin=0"),
            pend_dep=one("SELECT COUNT(*) s FROM tx WHERE kind='deposit' AND status IN('pending','review')"),
            pend_wd=one("SELECT COUNT(*) s FROM tx WHERE kind='withdraw' AND status IN('pending','processing','approved')"),
            dep_vol=one("SELECT (SELECT COALESCE(SUM(amount),0) FROM tx WHERE kind='deposit' AND status='approved')"
                        "+(SELECT COALESCE(SUM(amount),0) FROM requests WHERE kind='deposit' AND status='approved') s"),
            wd_vol=one("SELECT (SELECT COALESCE(SUM(amount),0) FROM tx WHERE kind='withdraw' AND status IN('approved','paid'))"
                       "+(SELECT COALESCE(SUM(amount),0) FROM requests WHERE kind='withdraw' AND COALESCE(flow,'')<>'client_confirm' AND status='approved') s"),
            comm=one("SELECT COALESCE(SUM(amount),0) s FROM ledger WHERE kind='commission'"),
            comm_today=one("SELECT COALESCE(SUM(amount),0) s FROM ledger WHERE kind='commission' AND date(created)=date('now')"),
            ref_paid=one("SELECT COALESCE(SUM(amount),0) s FROM ledger WHERE kind='referral_bonus'"),
            ref_pend_n=one("SELECT COUNT(*) s FROM referrals WHERE status='pending'"),
            ref_pend_amt=one("SELECT COALESCE(SUM(amount),0) s FROM referrals WHERE status='pending'"),
            today_dep=one("SELECT (SELECT COALESCE(SUM(amount),0) FROM tx WHERE kind='deposit' AND status='approved' AND date(updated)=date('now'))"
                          "+(SELECT COALESCE(SUM(amount),0) FROM requests WHERE kind='deposit' AND status='approved' AND date(decided_at)=date('now')) s"))
        s.update(pool=pool_balance(), pool_res=pool_reserved())  # ledger reconciliation scans load separately (see /admin/dash/integrity)
    if has_perm("referrals", u):
        pend = qa(REF_SQL + " WHERE r.status='pending' ORDER BY r.id LIMIT 5")
    if has_perm("users_view", u):
        acts = qa(ACTIVITY_SQL)
    return page("""{% if fin %}<div class="g2"><div class="card"><div class="k">মোট ইউজার</div><div class="v">{{s.total}}</div></div>
<div class="card"><div class="k">সক্রিয় ইউজার <span class="k">(৩০ দিনে লগইন)</span></div><div class="v">{{s.active30}}</div></div>
<div class="card"><div class="k">ব্লক নয় / ব্লকড</div><div class="v">{{s.active}} / {{s.blocked}}</div></div>
<div class="card"><div class="k">পেন্ডিং রিকোয়েস্ট (ম্যানুয়াল)</div><div class="v">{{s.pend_req}}</div></div>
<div class="card"><div class="k">মোট ডিপোজিট</div><div class="v">৳ {{money(s.dep_vol)}}</div></div>
<div class="card"><div class="k">মোট উইথড্র</div><div class="v">৳ {{money(s.wd_vol)}}</div></div>
<div class="card"><div class="k">আজকের কমিশন</div><div class="v">৳ {{money(s.comm_today)}}</div></div>
<div class="card"><div class="k">মোট কমিশন</div><div class="v">৳ {{money(s.comm)}}</div></div>
<div class="card"><div class="k">মোট ওয়ালেট দায়</div><div class="v">৳ {{money(s.liability)}}</div></div>
<div class="card"><div class="k">আজকের ডিপোজিট</div><div class="v">৳ {{money(s.today_dep)}}</div></div>
<div class="card"><div class="k">পেন্ডিং ডিপোজিট</div><div class="v">{{s.pend_dep}}</div></div>
<div class="card"><div class="k">পেন্ডিং উইথড্র</div><div class="v">{{s.pend_wd}}</div></div>
<div class="card"><div class="k">রেফারেল বোনাস (প্রদত্ত)</div><div class="v">৳ {{money(s.ref_paid)}}</div></div>
<div class="card"><div class="k">পেন্ডিং রেফারেল</div><div class="v">{{s.ref_pend_n}} <span class="k">(৳{{money(s.ref_pend_amt)}})</span></div></div>
<div class="card"><div class="k">খোলা টিকিট</div><div class="v">{{s.open_tickets}}</div></div>
<div class="card"><div class="k">কমিশন পুল</div><div class="v">৳ {{money(s.pool)}}</div><div class="k">প্রতিশ্রুত ৳{{money(s.pool_res)}}</div></div></div>
{% else %}<div class="g2"><div class="card"><div class="k">খোলা টিকিট</div><div class="v">{{s.open_tickets}}</div></div>
<div class="card"><div class="k">মোট ইউজার</div><div class="v">{{s.total}}</div></div>
{% if can('requests') %}<div class="card"><div class="k">পেন্ডিং রিকোয়েস্ট (ম্যানুয়াল)</div><div class="v">{{s.pend_req}}</div></div>{% endif %}</div>{% endif %}
{% if acts %}<div class="card"><h3>সাম্প্রতিক ইউজার কার্যকলাপ</h3><div class="tw"><table>{% for a in acts %}<tr><td>{{(a['t'] or '')[:16]}}</td><td>{{a['d']}}</td></tr>{% endfor %}</table></div></div>{% endif %}
{% if can('referrals') %}<h3>⏳ পেন্ডিং রেফারেল রিকোয়েস্ট</h3>""" + REF_LIST + """{% if rows %}<a class="btn s" style="width:100%;margin-bottom:14px" href="/admin/referrals">সব রেফারেল দেখুন</a>{% endif %}{% endif %}
{% if fin %}<div id="integ"><div class="card k">⏳ লেজার যাচাই হচ্ছে…</div></div>
<div class="card"><h3>গত ১৪ দিন</h3><canvas id="ch"></canvas></div>
<script>fetch('/admin/dash/integrity',{credentials:'same-origin'}).then(function(r){return r.ok?r.text():''}).then(function(h){var e=document.getElementById('integ');if(e&&h)e.innerHTML=h});fetch('/insight/data?days=14').then(r=>r.json()).then(j=>bars('ch',j.labels,[j.deposit,j.withdraw,j.commission],['#1E90FF','#EF4444','#2BC4A8']))</script>{% endif %}""",
                active="/admin", s=s, bad=bad, rows=pend, fin=fin, acts=acts, rc=rc)


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
    t0 = now()
    pg = make_pg(q1("SELECT COUNT(*) n FROM tx t WHERE %s" % where, args)["n"], 30)
    rows = qa("SELECT t.*,u.name,u.phone,u.member_id FROM tx t JOIN users u ON u.id=t.user_id WHERE %s ORDER BY t.id DESC LIMIT ? OFFSET ?" % where, args + [30, pg["off"]])
    _seen_list(active, rows, 30, pg, t0)
    return page("""<h2>{{title}}</h2><div class="row" style="margin-bottom:10px"><a class="btn sm s" href="?status=open">খোলা</a><a class="btn sm s" href="?status=all">সব</a></div>
{% if not rows %}<div class="card empty">কিছু নেই</div>{% endif %}
{% for t in rows %}<div class="card"><b>৳ {{money(t['amount'])}}</b> · {{t['method']}} <span class="pill {{t['status']}}">{{t['status']}}</span>
<div class="k">#{{t['member_id']}} {{t['name']}} · {{t['phone']}} · {{t['created'][:16]}}</div>
<div>{{'TrxID' if t['kind']=='deposit' else 'নম্বর'}}: <b>{{t['trx'] or t['number']}}</b></div>
{% if t['kind']=='withdraw' %}<div>Payment Account Type: <b>{{t['account_type'] or '—'}}</b></div>{% endif %}
{% if t['screenshot'] %}<a href="/shot/{{t['screenshot']}}" target="_blank"><b>🖼 স্ক্রিনশট</b></a>{% endif %}
{% if t['note'] %}<div class="k">নোট: {{t['note']}}</div>{% endif %}
{% if t['status'] in statuses %}<form method="post" action="/admin/tx/{{t['id']}}" style="margin-top:8px" data-confirm="নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<input name="note" placeholder="নোট (ঐচ্ছিক)" maxlength="200"><div class="row">
{% for a,l,c in acts[t['kind']] %}{% if t['status'] in a %}<button name="act" value="{{l[0]}}" class="btn sm {{c}}">{{l[1]}}</button>{% endif %}{% endfor %}</div></form>{% endif %}</div>{% endfor %}""" + PAGER,
                active=active, rows=rows, title=title, statuses=statuses, acts=ACTIONS, pg=pg)


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
        if dep and act == "approve":  # same transaction: first approved Add Money -> one referral reward (never blocks the deposit itself)
            referral_reward_on_deposit(t["user_id"], a, "tx#%d" % i, tx_id=i)
        open_st = ("pending", "review") if dep else ("pending", "processing", "approved")
        if not q1("SELECT 1 FROM tx WHERE kind=? AND status IN (%s)" % ",".join("?" * len(open_st)), (t["kind"],) + open_st):
            alerts_done("/admin/deposits" if dep else "/admin/withdrawals")  # nothing left to handle in this queue
    flash("সম্পন্ন: %s" % new)
    return back()


# ---------------------------------------------------------------- admin: users
PER_PAGE = 25


def make_pg(total, per=PER_PAGE):
    """Pagination helper: ?p=N, always clamped to a valid page."""
    pages = max(1, (total + per - 1) // per)
    p = min(max(1, request.args.get("p", type=int) or 1), pages)

    def url(n):
        a = {k: v for k, v in request.args.items() if k != "p"}
        a["p"] = n
        return request.path + "?" + urlencode(a)
    return {"p": p, "pages": pages, "total": total, "per": per, "off": (p - 1) * per, "prev": url(p - 1), "next": url(p + 1)}


PAGER = """{% if pg and pg.pages>1 %}<div class="row" style="justify-content:space-between;align-items:center;margin:10px 0">
{% if pg.p>1 %}<a class="btn sm s" href="{{pg.prev}}">← আগের</a>{% else %}<span></span>{% endif %}<span class="k">পেজ {{pg.p}} / {{pg.pages}} · মোট {{pg.total}}</span>
{% if pg.p<pg.pages %}<a class="btn sm s" href="{{pg.next}}">পরের →</a>{% else %}<span></span>{% endif %}</div>{% endif %}"""


# ================================================================ Admin Desk: fast user search + user hub (no schema change)
METHOD_COLOR = {"bKash": "#E2136E", "Nagad": "#F6921E", "Rocket": "#8C3494"}
USER_FILTERS = (("all", "সব"), ("active", "সক্রিয়"), ("blocked", "ব্লকড"), ("funded", "ব্যালেন্স আছে"),
                ("new", "নতুন (৭ দিন)"), ("openreq", "খোলা রিকোয়েস্ট"), ("kyc", "KYC অপেক্ষমাণ"))
REQ_DEP_SQL = "(COALESCE(r.flow,'')='client_confirm' OR (COALESCE(r.flow,'')='' AND r.kind='deposit'))"   # alias r = requests
SEARCH_PER = 20

DESK_STYLE = """<style>
.chips{display:flex;gap:6px;overflow-x:auto;padding:2px 2px 10px;margin:0 -2px;-webkit-overflow-scrolling:touch}
.chips button{flex:none;padding:7px 12px;border-radius:99px;border:1.5px solid var(--ln);background:var(--card);background-image:none;box-shadow:none;color:var(--mut);font-weight:600;font-size:13px;touch-action:manipulation}
.chips button.on{background:var(--b);border-color:var(--b);color:#fff}
.sq input{margin:0 0 8px;font-size:16px}
.sq-st{min-height:18px;font-size:12.5px;color:var(--mut);margin:0 0 6px}
.uc{background:var(--card);border:1px solid var(--ln);border-left:4px solid var(--b);border-radius:14px;margin-bottom:10px;box-shadow:0 1px 3px #0A3D6614}
.uc.blocked{border-left-color:#ef4444}
.uc-main{display:block;padding:11px 12px;color:var(--tx)}
.uc-t{display:flex;justify-content:space-between;align-items:center;gap:8px}
.uc-t b{font-size:15.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.uc-t .pill{flex:none}
.uc-m{font-size:13px;color:var(--mut);margin:2px 0 4px}
.uc-b{display:flex;justify-content:space-between;gap:8px;font-size:13.5px}
.uc-o{color:#b45309;font-weight:700}
.uc-a{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:0 12px 11px}
.uc-a .btn{padding:8px 6px;font-size:13px}
.tabs{display:flex;gap:6px;overflow-x:auto;padding:2px 2px 10px;margin:0 -2px;-webkit-overflow-scrolling:touch}
.tabs button{flex:none;display:inline-flex;align-items:center;gap:5px;padding:8px 12px;border-radius:12px;border:1.5px solid var(--ln);background:var(--card);background-image:none;box-shadow:none;color:var(--mut);font-weight:700;font-size:13.5px;white-space:nowrap;touch-action:manipulation}
.tabs button.on{background:var(--b);border-color:var(--b);color:#fff}
.tabs button i{font-style:normal;font-size:11.5px;min-width:18px;padding:0 5px;border-radius:99px;background:#ef444422;color:#b91c1c;text-align:center}
.tabs button.on i{background:#ffffff33;color:#fff}
.js [data-tab]{display:none}.js [data-tab].on{display:block}
.qa{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px}
.qa .btn{min-height:68px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;padding:10px 8px;font-size:14px;line-height:1.3;border-radius:16px;width:100%}
.qa .dis{opacity:.5;pointer-events:none;filter:grayscale(.6)}
.pf-bal{font-size:30px;font-weight:800;margin:6px 0 2px;line-height:1.15}
.pm{background:var(--card);border:1px solid var(--ln);border-left:5px solid var(--mc,#1E90FF);border-radius:14px;padding:11px 12px;margin-bottom:10px;box-shadow:0 1px 3px #0A3D6614}
.pm.hl{outline:2px solid var(--mc,#1E90FF)}
.pm-h{display:flex;justify-content:space-between;align-items:center;gap:8px}
.pm-b{font-weight:800;font-size:15px;color:var(--mc,#1E90FF)}
.pm-n{font-size:20px;font-weight:700;letter-spacing:.5px;margin:4px 0;word-break:break-all}
.pm-r{display:flex;gap:8px;align-items:center;justify-content:space-between}
.pr{display:flex;gap:8px;align-items:center;justify-content:space-between;background:var(--card);border:1px solid var(--ln);border-radius:12px;padding:9px 11px;margin-bottom:8px}
.pr-m{flex:1;min-width:0;color:var(--tx)}
.pr-t{display:flex;gap:8px;align-items:center;justify-content:space-between}
.pr-t b{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pr-s{display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex:none}
.pf-act{display:flex;gap:8px;padding:6px 0;border-bottom:1px solid var(--ln);font-size:13px;line-height:1.4}
.pf-act span:first-child{flex:none;width:22px;text-align:center}
.pf-act .k{flex:none;white-space:nowrap}
details.dt{background:var(--card);border:1px solid var(--ln);border-radius:14px;margin-bottom:10px;padding:0 14px}
details.dt>summary{cursor:pointer;font-weight:700;padding:13px 0;list-style:none}
details.dt>summary::-webkit-details-marker{display:none}
details.dt[open]>summary{border-bottom:1px solid var(--ln);margin-bottom:10px}
details.dt .inn{padding-bottom:12px}
.dm{position:fixed;inset:0;background:#0A1B2B99;display:flex;align-items:flex-end;justify-content:center;z-index:60}
.dm-box{background:var(--card);width:100%;max-width:620px;border-radius:20px 20px 0 0;padding:16px 16px calc(16px + env(safe-area-inset-bottom,0px));max-height:88vh;overflow:auto;box-shadow:0 -12px 30px #0A1B2B55}
.dm-box h3{margin:0 0 8px}
.dm-dl{margin:0 0 10px}.dm-dl>div{display:flex;gap:10px;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--ln)}
.dm-dl dt{flex:0 0 36%;color:var(--mut);font-size:13px}.dm-dl dd{margin:0;flex:1;text-align:right;font-size:14px;word-break:break-word}
.dm-note{background:var(--aq);color:#0B4F6C;border-radius:12px;padding:9px 12px;font-size:13px;margin:8px 0}
.dm-warn{background:#FEF3C7;color:#92400E;border-radius:12px;padding:9px 12px;font-size:13px;margin:8px 0}
.dm-err{background:#FFE4E6;color:#991b1b;border-radius:12px;padding:9px 12px;font-size:13px;margin:8px 0}
.dm-btns{display:grid;grid-template-columns:1fr 1.4fr;gap:10px;margin-top:10px}
.pmc{display:flex;align-items:center;gap:10px;background:var(--fld);border:1.5px solid var(--ln);border-left:5px solid var(--mc,#1E90FF);border-radius:12px;padding:10px 12px;margin:0 0 8px;color:var(--tx);cursor:pointer}
.pmc input{width:auto;margin:0;flex:none}
.pmc.on{border-color:var(--mc,#1E90FF);background:var(--aqs)}
.pmc b{display:block;color:var(--mc,#1E90FF)}
.pmc span.n{font-size:16px;font-weight:700;letter-spacing:.4px}
.lock{opacity:.55}
</style>"""

USER_ROWS_TPL = """{% if not rows and p==1 %}<div class="card empty">কোনো ইউজার পাওয়া যায়নি</div>{% endif %}
{% for x in rows %}<div class="uc{{' blocked' if x['blocked']}}"><a class="uc-main" href="/admin/users/{{x['id']}}"><div class="uc-t"><b>{{x['name']}}</b><span class="pill {{'rejected' if x['blocked'] else 'approved'}}">{{'ব্লকড' if x['blocked'] else 'সক্রিয়'}}</span></div>
<div class="uc-m">#{{x['member_id']}} · 📱 {{x['phone']}}</div>
<div class="uc-b"><span>ব্যালেন্স <b>৳ {{money(x['balance'])}}</b></span>{% if can('requests') and x['open_req'] %}<span class="uc-o">⏳ {{x['open_req']}}টি খোলা রিকোয়েস্ট</span>{% endif %}</div></a>
</div>{% endfor %}
{% if more %}<button type="button" class="btn s uc-more" data-next="{{p+1}}" style="width:100%;margin-bottom:10px">আরও দেখান</button>{% endif %}"""


def _clean_q(s, n=40):
    """Search text: no leading '#', no LIKE wildcards (so '%' / '_' can never widen a query)."""
    return re.sub(r"[%_\\]", "", (s or "").strip().lstrip("#"))[:n].strip()


def _frag(src, _conv=True, **ctx):
    """Render an HTML fragment without the page shell / per-request context processors (cheap: used on every keystroke).
    _conv=False when the fragment is embedded in page(), which converts timestamps to Bangladesh time itself (never twice)."""
    ctx.update(money=money, can=has_perm, csrf_token=csrf(), acct_lbl=ACCT_LABEL, mcol=METHOD_COLOR, labels=REQ_LABEL)
    h = _tpl(src).render(ctx)
    return to_bdt(h) if _conv else h


def _user_filters():
    return [(k, l) for k, l in USER_FILTERS if (k != "openreq" or has_perm("requests")) and (k != "kyc" or has_perm("kyc"))]


def _user_search(q, f, p, per=SEARCH_PER):
    """One indexed-friendly query, LIMIT/OFFSET pagination (per+1 rows fetched to know if more exist; no COUNT(*) per keystroke).
    Matches name, phone, Member ID, referral code and - only for staff who may see them - registered payment numbers."""
    where, args = ["u.is_admin=0"], []
    if q:
        like = "%" + q + "%"
        cond = "u.name LIKE ? OR u.phone LIKE ? OR u.member_id LIKE ? OR u.referral_code LIKE ?"
        args += [like] * 4
        if has_perm("payment_numbers"):
            cond += " OR EXISTS(SELECT 1 FROM payment_numbers pn WHERE pn.user_id=u.id AND pn.number LIKE ?)"
            args.append(like)
        where.append("(" + cond + ")")
    if f == "active":
        where.append("COALESCE(u.blocked,0)=0")
    elif f == "blocked":
        where.append("COALESCE(u.blocked,0)=1")
    elif f == "funded":
        where.append("u.balance>0")
    elif f == "new":
        where.append("u.created>=datetime('now','-7 days')")
    elif f == "openreq" and has_perm("requests"):
        where.append("EXISTS(SELECT 1 FROM requests r WHERE r.user_id=u.id AND r.status IN ('pending','submitted','review'))")
    elif f == "kyc" and has_perm("kyc"):
        where.append("EXISTS(SELECT 1 FROM meta m WHERE m.k='kyc:'||u.id AND (m.v LIKE ? OR m.v LIKE ?))")
        args += ['%"status": "pending"%', '%"status":"pending"%']
    order, oargs = "u.id DESC", []
    if q:
        order, oargs = "(CASE WHEN u.member_id=? OR u.phone=? OR u.referral_code=? THEN 0 ELSE 1 END), u.id DESC", [q, q, q.upper()]
    p = min(max(p, 1), 500)
    rows = qa("SELECT u.id,u.name,u.phone,u.member_id,u.balance,u.commission,u.blocked,u.created,"
              "(SELECT COUNT(*) FROM requests r WHERE r.user_id=u.id AND r.status IN ('pending','submitted','review')) open_req "
              "FROM users u WHERE " + " AND ".join(where) + " ORDER BY " + order + " LIMIT ? OFFSET ?",
              args + oargs + [per + 1, (p - 1) * per])
    return rows[:per], len(rows) > per


@app.route("/admin/users")
@staff_required("users_view")
def admin_users():
    q, f = _clean_q(request.args.get("q", "")), request.args.get("f", "all")
    flt = _user_filters()
    if f not in {k for k, _ in flt}:
        f = "all"
    p = min(max(request.args.get("p", type=int) or 1, 1), 500)
    rows, more = _user_search(q, f, p)
    shown = {"/admin/users/%d" % x["id"] for x in rows}
    alerts_seen(lambda link, ts: link in shown)
    return page(DESK_STYLE + """<div class="card" style="padding:12px 14px"><div class="sq"><input id="uq" type="search" inputmode="search" enterkeyhint="search" autocomplete="off" value="{{q}}"
placeholder="নাম / ফোন / মেম্বার আইডি / রেফারেল কোড{% if can('payment_numbers') %} / পেমেন্ট নম্বর{% endif %}"></div>
<div class="chips" id="uf">{% for k,l in flt %}<button type="button" data-f="{{k}}" class="{{'on' if k==f}}">{{l}}</button>{% endfor %}</div><div class="sq-st" id="ust"></div></div>
<div id="ures">""" + USER_ROWS_TPL + """</div>
<script>(function(){var box=document.getElementById('ures'),inp=document.getElementById('uq'),chips=document.getElementById('uf'),st=document.getElementById('ust');
if(!box||!inp)return;var f=(chips.querySelector('button.on')||{dataset:{f:'all'}}).dataset.f,tm=null,seq=0;
function url(p){return '/admin/users/search?q='+encodeURIComponent(inp.value.trim())+'&f='+encodeURIComponent(f)+'&p='+p}
function sync(){var u=new URL(location.href),v=inp.value.trim();u.searchParams.delete('p');v?u.searchParams.set('q',v):u.searchParams.delete('q');f==='all'?u.searchParams.delete('f'):u.searchParams.set('f',f);history.replaceState(null,'',u)}
function load(p,append,btn){var my=++seq;st.textContent='খুঁজছে…';fetch(url(p),{credentials:'same-origin'}).then(function(r){if(!r.ok)throw 0;return r.text()}).then(function(h){if(my!==seq)return;
 if(append){if(btn)btn.remove();box.insertAdjacentHTML('beforeend',h)}else box.innerHTML=h;st.textContent=''}).catch(function(){if(my===seq){st.textContent='লোড করা যায়নি — আবার চেষ্টা করুন';if(btn)btn.disabled=false}})}
inp.addEventListener('input',function(){clearTimeout(tm);tm=setTimeout(function(){sync();load(1,false)},250)});
inp.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();clearTimeout(tm);sync();load(1,false);inp.blur()}});
chips.addEventListener('click',function(e){var b=e.target.closest('button[data-f]');if(!b)return;chips.querySelectorAll('button').forEach(function(x){x.classList.toggle('on',x===b)});f=b.dataset.f;sync();load(1,false)});
box.addEventListener('click',function(e){var b=e.target.closest('.uc-more');if(!b)return;b.disabled=true;load(+b.dataset.next,true,b)})})()</script>""",
                active="/admin/users", rows=rows, more=more, p=p, q=q, f=f, flt=flt)


@app.route("/admin/users/search")
@staff_required("users_view")
def admin_users_search():
    """HTML fragment of user cards for the live search (same permission as the user list)."""
    q, f = _clean_q(request.args.get("q", "")), request.args.get("f", "all")
    if f not in {k for k, _ in _user_filters()}:
        f = "all"
    p = min(max(request.args.get("p", type=int) or 1, 1), 500)
    rows, more = _user_search(q, f, p)
    r = Response(_frag(USER_ROWS_TPL, rows=rows, more=more, p=p), mimetype="text/html")
    r.headers["Cache-Control"] = "no-store"
    return r


def user_summary(i):
    r = q1("""SELECT
      COALESCE(SUM(CASE WHEN kind IN ('deposit','request_deposit') AND amount>0 THEN amount END),0) dep,
      COALESCE(SUM(CASE WHEN kind IN ('commission','commission_reversal') THEN amount END),0) com,
      COALESCE(SUM(CASE WHEN kind='referral_bonus' THEN amount END),0) refb,
      COALESCE(SUM(CASE WHEN kind='admin_adjust' THEN amount END),0) adj FROM ledger WHERE user_id=?""", (i,))
    s = stats(i)
    return {"dep": s["deposit"], "wd": s["withdraw"], "pending": s["pending"], "com": r["com"], "refb": r["refb"], "adj": r["adj"]}


def _user_activity(uid, limit=40):
    """One merged, newest-first timeline built only from sources the signed-in staff member may already see."""
    ev = []
    if has_perm("requests"):
        for l in qa("SELECT l.created,l.action,l.from_status,l.to_status,l.actor,l.note,r.order_id FROM request_log l JOIN requests r ON r.id=l.request_id "
                    "WHERE r.user_id=? ORDER BY l.id DESC LIMIT 25", (uid,)):
            ev.append((l["created"], "📨", "অনুরোধ %s — %s%s · %s%s" % (l["order_id"], l["action"], (" (%s → %s)" % (l["from_status"] or "-", l["to_status"])) if l["to_status"] else "",
                                                                  l["actor"] or "system", (" · " + l["note"]) if l["note"] else "")))
    if has_perm("payment_numbers"):
        for l in qa("SELECT created,action,method,account_type,number,old FROM payment_number_log WHERE user_id=? ORDER BY id DESC LIMIT 15", (uid,)):
            ev.append((l["created"], "💳", "পেমেন্ট নম্বর %s: %s/%s/%s%s" % (l["action"], l["method"], l["account_type"], l["number"], (" ← " + l["old"]) if l["old"] else "")))
    if has_perm("users_manage"):
        for l in qa("SELECT created,ip,ok FROM login_history WHERE user_id=? ORDER BY id DESC LIMIT 10", (uid,)):
            ev.append((l["created"], "✅" if l["ok"] else "❌", "লগইন %s · IP %s" % ("সফল" if l["ok"] else "ব্যর্থ", l["ip"] or "-")))
    if has_perm("audit"):
        for l in qa("SELECT created,actor,action,detail FROM audit WHERE detail LIKE ? OR detail LIKE ? ORDER BY id DESC LIMIT 20",
                    ("%%user#%d %%" % uid, "%%user#%d" % uid)):
            ev.append((l["created"], "📜", "অডিট %s · %s · %s" % (l["action"], l["actor"], (l["detail"] or "")[:140])))
    ev.sort(key=lambda e: e[0] or "", reverse=True)
    return ev[:limit]


REQ_BTNS = """{% for a in ra(r) %}{% if a=='edit' %}<a class="btn sm s" href="/admin/requests/{{r['id']}}/edit">✏️ সম্পাদনা</a>
{% else %}<button type="button" class="btn sm {{rbtn[a][1]}}" data-do="{{a}}" data-u="/admin/requests/{{r['id']}}/act" data-c="{{rbtn[a][1]}}" data-t="{{rbtn[a][0]}}" data-need="{{1 if a in ('reject','cancel') else 0}}" data-m="{{rnote(r,a)}}"{% if a=='approve' and xc_ok(r) %} data-extra="1"{% endif %}>{{rbtn[a][0]}}</button>{% endif %}{% endfor %}"""

REQ_ROWS_TPL = """{% for r in lst %}<div class="pr" style="flex-wrap:wrap"><a class="pr-m" href="/admin/requests/{{r['id']}}"><div class="pr-t"><b>{{r['order_id']}}</b><span class="pill {{r['status']}}">{{labels[r['status']]}}</span></div>
<div class="k">{{rk(r)}} · {{r['method']}} · {{r['created'][:16]}}{% if r['created_by'] %} · {{r['created_by']}}{% endif %}</div></a>
<div class="pr-s"><b>৳ {{money(r['amount'])}}</b>{% if r['commission'] %}<span class="k">+ কমিশন ৳{{money(r['commission'])}}</span>{% endif %}</div>
<div class="rq-acts" style="width:100%;margin:0"><a class="btn sm" href="/admin/requests/{{r['id']}}">⚙ দেখুন / ম্যানেজ</a>""" + REQ_BTNS + """</div></div>{% endfor %}"""

TX_ROWS_TPL = """{% for r in lst %}<div class="pr" style="flex-wrap:wrap"><a class="pr-m" href="/admin/requests/user/{{r['id']}}"><div class="pr-t"><b>{{'DEP' if r['kind']=='deposit' else 'WD'}}-{{'%05d'|format(r['id'])}}</b><span class="pill {{r['status']}}">{{txl.get(r['status'], r['status'])}}</span></div>
<div class="k">{{kinds[r['kind']]}} · 💳 {{r['method']}}{% if r['number'] %} {{r['number']}}{% endif %}{% if r['trx'] %} · TrxID {{r['trx']}}{% endif %} · {{r['created'][:16]}}</div></a>
<div class="pr-s"><b>৳ {{money(r['amount'])}}</b></div>
<div class="rq-acts" style="width:100%;margin:0"><a class="btn sm" href="/admin/requests/user/{{r['id']}}">⚙ দেখুন / ম্যানেজ</a>{% for a,l,c in txacts[r['kind']] %}{% if r['status'] in a %}<button type="button" class="btn sm {{c}}" data-do="{{l[0]}}" data-u="/admin/tx/{{r['id']}}" data-c="{{c}}" data-t="{{l[1]}}" data-need="0" data-m="{{tnote(r,l[0])}}">{{l[1]}}</button>{% endif %}{% endfor %}</div></div>{% endfor %}"""

PM_CARDS_TPL = """{% for p in pns %}<div class="pm{{' hl' if hl and p['number']==hl and (not hm or p['method']==hm)}}" style="--mc:{{mcol.get(p['method'],'#1E90FF')}}"><div class="pm-h"><span class="pm-b">{{p['method']}}</span><span class="pill">{{acct_lbl.get(p['account_type'],p['account_type'])}}</span></div>
<div class="pm-r"><div class="pm-n">{{p['number']}}</div><button type="button" class="btn sm s" data-copy="{{p['number']}}">📋 কপি</button></div>
<div class="k">যোগ: {{(p['created'] or '')[:16]}}{% if p['updated']!=p['created'] %} · আপডেট: {{(p['updated'] or '')[:16]}}{% endif %}{% if hl and p['number']==hl and (not hm or p['method']==hm) %} · <b>✔ এই অনুরোধে ব্যবহৃত</b>{% endif %}</div>
{% if send_uid and can('requests') %}<div class="uc-a" style="padding:8px 0 0"><a class="btn sm s" href="/admin/requests/new?uid={{send_uid}}&type=client_confirm&pn={{p['id']}}">📨 ডিপোজিট রিকোয়েস্ট</a><a class="btn sm s" href="/admin/requests/new?uid={{send_uid}}&type=admin_review&pn={{p['id']}}">🏧 উইথড্র রিকোয়েস্ট</a></div>{% endif %}</div>{% endfor %}"""


@app.route("/admin/users/<int:i>")
@staff_required("users_view")
def admin_user(i):
    x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (i,))
    if not x:
        abort(404)
    alerts_seen(lambda link, ts: link == "/admin/users/%d" % i)
    can_req, can_pn, can_ref = has_perm("requests"), has_perm("payment_numbers"), has_perm("referrals")
    full = has_perm("dashboard_fin") or has_perm("users_manage")
    if can_req:
        expire_requests()
    pg = make_pg(q1("SELECT COUNT(*) n FROM ledger WHERE user_id=?", (i,))["n"], 30) if full else None
    if pg:
        pg["prev"] += "#tx"
        pg["next"] += "#tx"
    led = qa("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT ? OFFSET ?", (i, 30, pg["off"])) if full else []
    comm = qa("SELECT * FROM ledger WHERE user_id=? AND kind IN ('commission','commission_reversal','referral_bonus') ORDER BY id DESC LIMIT 30", (i,)) if full else []
    adjs = qa("SELECT * FROM balance_adjustments WHERE user_id=? ORDER BY id DESC LIMIT 15", (i,)) if full else []
    txs = qa("SELECT * FROM tx WHERE user_id=? ORDER BY id DESC LIMIT 30", (i,))
    sel = "SELECT r.id,r.order_id,r.kind,r.flow,r.amount,r.commission,r.method,r.status,r.created,r.created_by FROM requests r WHERE r.user_id=?"
    open_reqs = qa(sel + " AND r.status IN ('pending','submitted','review') ORDER BY r.id DESC LIMIT 20", (i,)) if can_req else []
    a2u_reqs = qa(sel + " ORDER BY r.id DESC LIMIT 30", (i,)) if can_req else []      # sent BY admin TO this user
    ks = _rq_kinds()
    u2a_reqs = qa("SELECT * FROM tx WHERE user_id=? AND kind IN (%s) ORDER BY id DESC LIMIT 30" % ",".join("?" * len(ks)), [i] + ks) if (can_req and ks) else []   # submitted BY this user TO admin
    pns = qa("SELECT * FROM payment_numbers WHERE user_id=? ORDER BY id", (i,)) if can_pn else []
    pn_logs = qa("SELECT * FROM payment_number_log WHERE user_id=? ORDER BY id DESC LIMIT 6", (i,)) if can_pn else []
    reffed = qa("SELECT r.*, x.member_id mid, x.name nm FROM referrals r JOIN users x ON x.id=r.referred_id WHERE r.referrer_id=? ORDER BY r.id DESC LIMIT 50", (i,)) if can_ref else []
    refs = q1("SELECT COUNT(*) n, COALESCE(SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END),0) a FROM referrals WHERE referrer_id=?", (i,)) if can_ref else None
    by = q1("SELECT member_id,name FROM users WHERE id=?", (x["referred_by"],)) if (x["referred_by"] and can_ref) else None
    byrow = q1("SELECT created,status FROM referrals WHERE referred_id=?", (i,)) if (x["referred_by"] and can_ref) else None
    return page(DESK_STYLE + """<div id="uprof">
<div class="card" style="margin-bottom:10px"><div class="row" style="align-items:center;gap:8px"><h2 style="margin:0;min-width:0;overflow-wrap:anywhere">{{x['name']}}</h2>
<span class="pill {{'rejected' if x['blocked'] else 'approved'}}" style="flex:0;white-space:nowrap">{{'ব্লকড' if x['blocked'] else 'সক্রিয়'}}</span></div>
<div class="k" style="margin-top:4px">Member ID <b>#{{x['member_id']}}</b> · <a href="tel:{{x['phone']}}"><b>📱 {{x['phone']}}</b></a></div>
<div class="k">ওয়ালেট ব্যালেন্স</div><div class="pf-bal">৳ {{money(x['balance'])}}</div>
<div class="k">যোগদান: {{(x['created'] or '-')[:16]}} · সর্বশেষ লগইন: {{x['last_login'] or '-'}} · রেফারেল কোড: {{x['referral_code']}}</div>
{% if x['blocked'] and x['blocked_reason'] %}<div class="msg error" style="margin:8px 0 0">ব্লকের কারণ: {{x['blocked_reason']}} ({{(x['blocked_at'] or '')[:16]}})</div>{% endif %}
<div class="k" style="margin-top:8px">🪪 KYC: {% set ks=kycs(x['id']) %}<span class="pill {{ks if ks in ('pending','approved','rejected') else ''}}">{{kycl[ks]}}</span>{% if can('kyc') and ks!='none' %} <a href="/admin/kyc/{{x['id']}}"><b>দেখুন</b></a>{% endif %}</div></div>
<div class="qa">
{% if can('requests') %}{% if x['blocked'] %}<span class="btn dis">📨<br>ডিপোজিট রিকোয়েস্ট পাঠান</span><span class="btn dis">🏧<br>উইথড্র রিকোয়েস্ট পাঠান</span>
{% else %}<a class="btn" href="/admin/requests/new?uid={{x['id']}}&type=client_confirm">📨<span>ডিপোজিট রিকোয়েস্ট পাঠান</span></a><a class="btn" href="/admin/requests/new?uid={{x['id']}}&type=admin_review">🏧<span>উইথড্র রিকোয়েস্ট পাঠান</span></a>{% endif %}{% endif %}
{% if can('payment_numbers') %}<button type="button" class="btn s" data-go="pay">💳<span>পেমেন্ট মেথড দেখুন</span></button>{% endif %}
<button type="button" class="btn s" data-go="tx">📜<span>লেনদেনের ইতিহাস</span></button></div>
{% if x['blocked'] and can('requests') %}<div class="k" style="margin:-4px 0 10px">🔒 ব্লকড ইউজারকে রিকোয়েস্ট পাঠানো যায় না — আগে আনব্লক করুন।</div>{% endif %}
<div class="tabs" id="utabs"><button type="button" data-t="ov" class="on">👤 প্রোফাইল</button>
{% if can('payment_numbers') %}<button type="button" data-t="pay">💳 পেমেন্ট{% if pns %}<i>{{pns|length}}</i>{% endif %}</button>{% endif %}
<button type="button" data-t="tx">📜 লেনদেন</button>
{% if can('requests') %}<button type="button" data-t="a2u">📤 অ্যাডমিন → ইউজার{% if a2u_reqs %}<i>{{a2u_reqs|length}}</i>{% endif %}</button><button type="button" data-t="u2a">📥 ইউজার → অ্যাডমিন{% if u2a_reqs %}<i>{{u2a_reqs|length}}</i>{% endif %}</button>{% endif %}
<button type="button" data-t="act">🕘 অ্যাকটিভিটি</button></div>

<section data-tab="ov" class="on">
<div class="g2"><div class="card"><div class="k">মোট ডিপোজিট</div><div class="v">৳ {{money(sm.dep)}}</div></div><div class="card"><div class="k">মোট উইথড্র</div><div class="v">৳ {{money(sm.wd)}}</div></div>
<div class="card"><div class="k">মোট কমিশন (লেজার)</div><div class="v">৳ {{money(sm.com)}}</div></div><div class="card"><div class="k">পেন্ডিং উইথড্র</div><div class="v">৳ {{money(sm.pending)}}</div></div></div>
{% if can('requests') %}<div class="card"><h3 style="margin-top:0">⏳ খোলা রিকোয়েস্ট{% if open_reqs %} ({{open_reqs|length}}){% endif %}</h3>
{% if open_reqs %}{% set lst=open_reqs %}""" + REQ_ROWS_TPL + """{% else %}<div class="k">এই ইউজারের কোনো খোলা (pending / submitted / review) রিকোয়েস্ট নেই।</div>{% endif %}</div>{% endif %}
{% if can('users_manage') %}<details class="dt"><summary>🔒 ব্লক / পাসওয়ার্ড রিসেট কোড</summary><div class="inn"><form method="post" action="/admin/users/{{x['id']}}/block" data-confirm="নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<input type="hidden" name="act" value="{{'unblock' if x['blocked'] else 'block'}}"><label>{{'আনব্লকের নোট (ঐচ্ছিক)' if x['blocked'] else 'ব্লকের কারণ (আবশ্যক)'}}</label><input name="reason" maxlength="200" {{'' if x['blocked'] else 'required'}}>
<button class="btn {{'g' if x['blocked'] else 'r'}}" style="width:100%">{{'🔓 আনব্লক' if x['blocked'] else '🔒 ব্লক'}}</button></form>
<form method="post" action="/admin/users/{{x['id']}}/resetcode" data-confirm="নতুন রিসেট কোড তৈরি করবেন?" style="margin-top:8px"><input type="hidden" name="_csrf" value="{{csrf_token}}"><button class="btn s" style="width:100%">পাসওয়ার্ড রিসেট কোড</button></form></div></details>{% endif %}
{% if can('rates') %}<details class="dt"><summary>💸 কমিশন রেট — কার্যকর {{eff|pct}}%</summary><div class="inn"><form method="post" action="/admin/commission/rate" data-confirm="কমিশন রেট বদলাবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="idem" value="{{ridem}}"><input type="hidden" name="scope" value="user"><input type="hidden" name="uid" value="{{x['id']}}">
<div class="k">কার্যকর রেট: <b>{{eff|pct}}%</b> {% if x['comm_rate'] is not none %}(ইউজার-নির্দিষ্ট){% else %}(গ্লোবাল){% endif %} · সর্বোচ্চ {{rmax}}%</div>
<select name="op"><option value="set">সেট করুন</option><option value="inc">বাড়ান (+)</option><option value="dec">কমান (−)</option><option value="reset">গ্লোবালে ফিরুন</option></select>
<input name="value" type="number" step="0.01" min="0" max="10" placeholder="% মান" value="0"><input name="reason" placeholder="কারণ" required minlength="3" maxlength="200"><button class="s" style="width:100%">রেট আপডেট</button></form></div></details>{% endif %}
{% if can('adjust') %}<details class="dt"><summary>⚖️ ব্যালেন্স সমন্বয় (কারণ আবশ্যক)</summary><div class="inn"><p class="k">যোগ করতে বৈধ রেফারেন্স (TrxID / অনুরোধ নম্বর / রসিদ নম্বর) লাগবে এবং একই রেফারেন্স দুবার ব্যবহার করা যায় না। সীমা: ৳{{money(adj_cap)}}।</p>
<form method="post" action="/admin/users/{{x['id']}}/adjust" data-confirm="লেজারে স্থায়ীভাবে রেকর্ড হবে। নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="idem" value="{{idem}}">
<label>ধরন</label><select name="direction"><option value="credit">➕ ব্যালেন্স যোগ</option><option value="debit">➖ ব্যালেন্স বিয়োগ</option></select>
<label>পরিমাণ (৳)</label><input name="amount" type="number" step="0.01" min="0.01" required><label>রেফারেন্স (যোগের জন্য আবশ্যক)</label><input name="reference" maxlength="40">
<label>কারণ (কমপক্ষে ৫ অক্ষর)</label><input name="reason" required minlength="5" maxlength="200"><button style="width:100%">সমন্বয় করুন</button></form></div></details>{% endif %}
{% if can('notices') %}<details class="dt"><summary>📌 ব্যক্তিগত নোটিশ / নির্দেশনা</summary><div class="inn"><form method="post" action="/admin/users/{{x['id']}}/notice" data-confirm="ইউজারকে পাঠাবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<select name="kind"><option value="notice">📌 নোটিশ</option><option value="instruction">📋 নির্দেশনা</option></select>
<label>শিরোনাম (বাংলা)</label><input name="title_bn" required maxlength="80"><label>বার্তা (বাংলা)</label><textarea name="body_bn" required rows="3" maxlength="1000"></textarea>
<label>Title (English, optional)</label><input name="title_en" maxlength="80"><label>Message (English, optional)</label><textarea name="body_en" rows="3" maxlength="1000"></textarea>
<button style="width:100%">পাঠান</button></form></div></details>{% endif %}
{% if can('notices') or can('requests') %}<details class="dt"><summary>⚠ সতর্কবার্তা (Warning)</summary><div class="inn"><form method="post" action="/admin/warnings/new" data-confirm="সতর্কবার্তা ইউজারকে পাঠাবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="uid" value="{{x['id']}}"><input type="hidden" name="next" value="/admin/users/{{x['id']}}">
<textarea name="message" rows="3" required minlength="5" maxlength="500" placeholder="যেমন: Repeated cancellation of requests may result in temporary transaction restrictions."></textarea>
<div class="k" style="margin-bottom:6px">ইউজার নোটিফিকেশন ও অনুরোধ পেজে দেখবেন। শুধু সতর্কবার্তায় কোনো লেনদেন সীমাবদ্ধ হয় না — ব্লক করতে আলাদা অ্যাকশন লাগে।</div><button style="width:100%">⚠ সতর্কবার্তা পাঠান</button></form></div></details>{% endif %}
{% if can('reports') %}<a class="btn s" style="width:100%;margin-bottom:10px" href="/admin/reports/user/{{x['id']}}">📊 ইউজার রিপোর্ট</a>{% endif %}
{% if can('referrals') %}<div class="card"><h3 style="margin-top:0">রেফারেল তথ্য {% if can('referrals') %}<a class="k" href="/admin/referrals/user/{{x['id']}}">বিস্তারিত →</a>{% endif %}</h3><p class="k">রেফার করেছেন: {{refs['n']}} (অনুমোদিত {{refs['a']}}){% if by %} · রেফারার: <a href="/admin/users/{{x['referred_by']}}">#{{by['member_id']}} {{by['name']}}</a> ({{(byrow['created'] or '')|bdd}}, {{byrow['status']}}){% else %} · কারও রেফারে আসেননি{% endif %}</p>
{% if reffed %}<div class="tw"><table><tr><th>সদস্য</th><th>তারিখ</th><th>বোনাস</th><th>অবস্থা</th></tr>{% for r in reffed %}<tr><td><a href="/admin/users/{{r['referred_id']}}">#{{r['mid']}} {{r['nm']}}</a></td><td>{{r['created']|bdd}}</td><td>{{money(r['amount'])}}</td><td>{{r['status']}}</td></tr>{% endfor %}</table></div>{% endif %}</div>{% endif %}
</section>

{% if can('payment_numbers') %}<section data-tab="pay"><div class="card"><h3 style="margin-top:0">💳 {{x['name']}} এর নিবন্ধিত পেমেন্ট নম্বর</h3>
<p class="k">শুধু এই ইউজারের নিজের যোগ করা নম্বর। এখান থেকেই নম্বর বেছে রিকোয়েস্ট পাঠানো যায়।</p></div>
{% if not pns %}<div class="card empty">ইউজার এখনো কোনো পেমেন্ট নম্বর যোগ করেননি</div>{% endif %}
{% set send_uid = (x['id'] if not x['blocked'] else none) %}{% set hl = none %}{% set hm = none %}""" + PM_CARDS_TPL + """
{% if pn_logs %}<div class="card"><h3 style="margin-top:0">সাম্প্রতিক পরিবর্তন</h3><div class="tw"><table>{% for l in pn_logs %}<tr><td>{{(l['created'] or '')[:16]}}</td><td>{{l['action']}}</td><td>{{l['method']}}/{{l['account_type']}}/{{l['number']}}{% if l['old'] %} ← {{l['old']}}{% endif %}</td></tr>{% endfor %}</table></div></div>{% endif %}
</section>{% endif %}

<section data-tab="tx">
<div class="card"><h3 style="margin-top:0">লেনদেন</h3>{% if txs %}<div class="tw"><table>{% for t in txs %}<tr><td>{{t['kind']}}</td><td>{{money(t['amount'])}}</td><td>{{t['status']}}</td><td>{{(t['trx'] or t['number'] or '')}}</td><td>{{(t['created'] or '')[:16]}}</td></tr>{% endfor %}</table></div>{% else %}<div class="k">কোনো লেনদেন নেই</div>{% endif %}</div>
{% if comm %}<div class="card"><h3 style="margin-top:0">কমিশন / বোনাস ইতিহাস</h3><div class="tw"><table><tr><th>ধরন</th><th>৳</th><th>নোট</th><th>সময়</th></tr>
{% for l in comm %}<tr><td>{{l['kind']}}</td><td>{{money(l['amount'])}}</td><td>{{l['note'] or ''}}</td><td>{{l['created'][:16]}}</td></tr>{% endfor %}</table></div></div>{% endif %}
{% if adjs %}<div class="card"><h3 style="margin-top:0">ব্যালেন্স সমন্বয়ের ইতিহাস</h3><div class="tw"><table><tr><th>ধরন</th><th>৳</th><th>রেফারেন্স</th><th>কারণ</th><th>কে</th><th>সময়</th></tr>
{% for a in adjs %}<tr><td>{{a['direction']}}</td><td>{{money(a['amount'])}}</td><td>{{a['reference'] or '-'}} {{'✔' if a['verified']}}</td><td>{{a['reason']}}</td><td>{{a['actor']}}</td><td>{{a['created'][:16]}}</td></tr>{% endfor %}</table></div></div>{% endif %}
{% if led %}<div class="card"><h3 style="margin-top:0">ওয়ালেট লেজার</h3><div class="tw"><table><tr><th>ধরন</th><th>৳</th><th>নোট</th><th>কে</th><th>সময়</th></tr>
{% for l in led %}<tr><td>{{l['kind']}}</td><td>{{money(l['amount'])}}</td><td>{{l['note'] or ''}}</td><td>{{l['actor']}}</td><td>{{l['created'][:16]}}</td></tr>{% endfor %}</table></div>""" + PAGER + """</div>{% endif %}
</section>

{% if can('requests') %}<section data-tab="a2u"><div class="card"><h3 style="margin-top:0">📤 অ্যাডমিন → ইউজার রিকোয়েস্ট</h3><p class="k">এই ইউজারকে অ্যাডমিনের পাঠানো সব রিকোয়েস্ট (সর্বশেষ ৩০টি)।</p>
{% if not x['blocked'] %}<div class="uc-a" style="padding:0"><a class="btn sm" href="/admin/requests/new?uid={{x['id']}}&type=client_confirm">➕ ডিপোজিট রিকোয়েস্ট</a><a class="btn sm" href="/admin/requests/new?uid={{x['id']}}&type=admin_review">➕ উইথড্র রিকোয়েস্ট</a></div>{% endif %}</div>
{% if a2u_reqs %}{% set lst=a2u_reqs %}""" + REQ_ROWS_TPL + """{% else %}<div class="card empty">এই ইউজারকে কোনো রিকোয়েস্ট পাঠানো হয়নি</div>{% endif %}
<a class="btn s" style="width:100%" href="/admin/requests?tab=admin&q={{x['member_id']}}&status=all">সব দেখুন →</a></section>
<section data-tab="u2a"><div class="card"><h3 style="margin-top:0">📥 ইউজার → অ্যাডমিন রিকোয়েস্ট</h3><p class="k">এই ইউজারের জমা দেওয়া ডিপোজিট/উইথড্র রিকোয়েস্ট (সর্বশেষ ৩০টি)।</p></div>
{% if u2a_reqs %}{% set lst=u2a_reqs %}""" + TX_ROWS_TPL + """{% else %}<div class="card empty">এই ইউজারের কোনো রিকোয়েস্ট নেই (অথবা আপনার অনুমতির মধ্যে নেই)</div>{% endif %}
<a class="btn s" style="width:100%" href="/admin/requests?tab=user&q={{x['member_id']}}&status=all">সব দেখুন →</a></section>{% endif %}

<section data-tab="act"><div class="card"><h3 style="margin-top:0">🕘 ইউজার অ্যাকটিভিটি</h3>
{% if acts %}{% for e in acts %}<div class="pf-act"><span>{{e[1]}}</span><span style="flex:1;min-width:0;overflow-wrap:anywhere">{{e[2]}}</span><span class="k">{{(e[0] or '')[:16]}}</span></div>{% endfor %}
{% else %}<div class="k">দেখানোর মতো অ্যাকটিভিটি নেই (অথবা আপনার অনুমতির মধ্যে নেই)।</div>{% endif %}</div></section>
</div>
<script>(function(){var w=document.getElementById('uprof');if(!w)return;var tabs=document.getElementById('utabs'),names=[];
tabs.querySelectorAll('button[data-t]').forEach(function(b){names.push(b.dataset.t)});w.classList.add('js');
function show(t,scroll){if(names.indexOf(t)<0)t='ov';tabs.querySelectorAll('button').forEach(function(b){b.classList.toggle('on',b.dataset.t===t)});
 w.querySelectorAll('[data-tab]').forEach(function(s){s.classList.toggle('on',s.dataset.tab===t)});
 try{history.replaceState(null,'',location.pathname+location.search+(t==='ov'?'':'#'+t))}catch(e){}
 if(scroll)tabs.scrollIntoView({block:'start',behavior:'smooth'})}
tabs.addEventListener('click',function(e){var b=e.target.closest('button[data-t]');if(b)show(b.dataset.t,false)});
w.addEventListener('click',function(e){var b=e.target.closest('[data-go]');if(b)show(b.dataset.go,true)});
show(location.hash.slice(1),false)})()</script>""" + ACT_MODAL,
                active="/admin/users", x=x, led=led, txs=txs, refs=refs, by=by, byrow=byrow, reffed=reffed, comm=comm, adjs=adjs, pg=pg,
                sm=user_summary(i), idem=secrets.token_hex(8), adj_cap=adjust_cap(me()), pns=pns, pn_logs=pn_logs,
                open_reqs=open_reqs, a2u_reqs=a2u_reqs, u2a_reqs=u2a_reqs, acts=_user_activity(i), labels=REQ_LABEL,
                ra=req_actions, rbtn=RQ_BTN, rnote=req_note, tnote=tx_note, txl=TX_LABEL, kinds=REQ_KIND, txacts=ACTIONS,
                eff=effective_rate(x), rmax=rate_cfg()[1], ridem=secrets.token_hex(8))


@app.route("/admin/users/<int:i>/block", methods=["POST"])
@staff_required("users_manage")
def admin_block(i):
    x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (i,))
    if not x:
        abort(404)
    act = request.form.get("act", "")
    reason = request.form.get("reason", "").strip()[:200]
    if act not in ("block", "unblock"):
        act = "unblock" if x["blocked"] else "block"
    want = 1 if act == "block" else 0
    if want and len(reason) < 3:
        err("ব্লকের কারণ লিখুন (কমপক্ষে ৩ অক্ষর)।"); return redirect("/admin/users/%d" % i)
    with atomic():  # idempotent: only flips when the state really is the opposite (double-click safe)
        cur = db().execute("UPDATE users SET blocked=?, blocked_reason=?, blocked_at=?, session_ver=session_ver+1 WHERE id=? AND is_admin=0 AND COALESCE(blocked,0)=?",
                           (want, reason if want else None, now() if want else None, i, 1 - want))
        if cur.rowcount == 1:
            audit("block" if want else "unblock", "user#%d %s" % (i, reason))
            if not want:
                notify(i, "অ্যাকাউন্ট চালু হয়েছে", "আপনার অ্যাকাউন্ট আবার চালু করা হয়েছে।", None, "Account reactivated", "Your account has been reactivated.")
            flash("ইউজার ব্লক করা হয়েছে।" if want else "ইউজার আনব্লক করা হয়েছে।")
        else:
            flash("অবস্থা আগেই বদলে গেছে — কিছু পরিবর্তন হয়নি।")
    return redirect("/admin/users/%d" % i)


@app.route("/admin/users/<int:i>/notice", methods=["POST"])
@staff_required("notices")
def admin_user_notice(i):
    f = request.form
    kind = "instruction" if f.get("kind") == "instruction" else "notice"
    tb, bb = f.get("title_bn", "").strip()[:80], f.get("body_bn", "").strip()[:1000]
    te, be = f.get("title_en", "").strip()[:80], f.get("body_en", "").strip()[:1000]
    if not q1("SELECT 1 FROM users WHERE id=? AND is_admin=0", (i,)):
        abort(404)
    if not tb or not bb:
        err("বাংলা শিরোনাম ও বার্তা দিন।"); return redirect("/admin/users/%d" % i)
    pre = "📋 " if kind == "instruction" else "📌 "
    with atomic():
        notify(i, pre + tb, bb, None, (pre + te) if te else None, be or None)
        audit("personal_notice", "user#%d %s %s" % (i, kind, tb))
    flash("ব্যক্তিগত %s পাঠানো হয়েছে।" % ("নির্দেশনা" if kind == "instruction" else "নোটিশ"))
    return redirect("/admin/users/%d" % i)


ADJ_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _\-/#.:]{3,39}")
ADJ_HARD = 1_000_000


def adjust_cap(u):
    if u and u["role"] == "super_admin":
        return float(ADJ_HARD)
    return min(float(ADJ_HARD), parse_amount(setting("adjust_limit", "50000")) or 50000.0)


@app.route("/admin/users/<int:i>/adjust", methods=["POST"])
@staff_required("adjust")
def admin_adjust(i):
    a, f = me(), request.form
    back_u = "/admin/users/%d" % i
    amt, direction = parse_amount(f.get("amount")), f.get("direction", "")
    reason, ref = f.get("reason", "").strip()[:200], f.get("reference", "").strip()[:40]
    token = re.sub(r"\W", "", f.get("idem", ""))[:32]
    if direction not in ("credit", "debit") or amt <= 0 or len(reason) < 5 or len(token) < 6:
        err("ধরন, সঠিক পরিমাণ ও কারণ (কমপক্ষে ৫ অক্ষর) দিন।"); return redirect(back_u)
    if (direction == "credit" or ref) and not ADJ_REF_RE.fullmatch(ref):
        err("বৈধ রেফারেন্স দিন (৪–৪০ অক্ষর: TrxID / অনুরোধ নম্বর / রসিদ নম্বর)। ব্যালেন্স যোগ করতে এটা আবশ্যক।"); return redirect(back_u)
    cap = adjust_cap(a)
    if amt > cap:
        err("আপনার সমন্বয় সীমা ৳%s। এর বেশি হলে সুপার অ্যাডমিনকে জানান।" % money(cap)); return redirect(back_u)
    if not q1("SELECT 1 FROM users WHERE id=? AND is_admin=0", (i,)):
        abort(404)
    nref = norm_trx(ref)
    verified = 1 if nref and (q1("SELECT 1 FROM tx WHERE norm_trx=?", (nref,)) or q1("SELECT 1 FROM requests WHERE norm_trx=? OR order_id=?", (nref, ref.upper()))) else 0
    if direction == "credit" and not verified and a["role"] != "super_admin":
        err("এই রেফারেন্স সিস্টেমের কোনো লেনদেন/অনুরোধে পাওয়া যায়নি। এমন রেফারেন্সে যোগ করতে সুপার অ্যাডমিন লাগবে।"); return redirect(back_u)
    signed = amt if direction == "credit" else -amt
    idem = "adj:" + token
    note = ("ref:%s | %s" % (ref, reason) if ref else reason)[:300]
    try:
        with atomic():
            if post(i, "admin_adjust", signed, idem, "admin", None, note, a["member_id"]):
                db().execute("INSERT INTO balance_adjustments(user_id,direction,amount,reason,reference,norm_ref,verified,ledger_idem,actor,actor_id,created) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                             (i, direction, amt, reason, ref or None, nref or None, verified, idem, a["member_id"], a["id"], now()))
                audit("adjust", "user#%d %s ৳%s ref=%s verified=%d %s" % (i, direction, money(amt), ref or "-", verified, reason))
                if direction == "credit":
                    notify(i, "ব্যালেন্স সমন্বয়", "৳%s যোগ হয়েছে — %s" % (money(amt), reason), None, "Balance adjustment", "৳%s was added — %s" % (money(amt), reason))
                else:
                    notify(i, "ব্যালেন্স সমন্বয়", "৳%s কাটা হয়েছে — %s" % (money(amt), reason), None, "Balance adjustment", "৳%s was deducted — %s" % (money(amt), reason))
                flash("সমন্বয় হয়েছে।")
            else:
                flash("এই অপারেশন আগেই হয়েছে (ডুপ্লিকেট সাবমিট)।")
    except INTEGRITY:
        err("এই রেফারেন্স দিয়ে আগেই ব্যালেন্স যোগ করা হয়েছে — একই রেফারেন্স দুবার ব্যবহার করা যায় না।")
    except LedgerError as e:
        err("ব্যর্থ (কিছুই বদলায়নি): " + str(e))
    return redirect(back_u)


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
    return page("""<div class="row" style="margin-bottom:10px;align-items:center"><a class="btn sm" href="/admin/referrals">📋 তালিকা</a><a class="btn sm s" href="/admin/referrals/network">🌐 নেটওয়ার্ক</a><a class="btn sm s" href="/admin/referral-rewards">⚙️ রিওয়ার্ড সেটিংস</a>{% if can('pool_view') %}<span class="k">পুলে উপলব্ধ: ৳{{money(pool_av)}}</span>{% endif %}</div>
<div class="g2"><div class="card"><div class="k">পেন্ডিং</div><div class="v">{{sm['p']}} <span class="k">(৳{{money(sm['pa'])}})</span></div></div>
<div class="card"><div class="k">অনুমোদিত (প্রদত্ত)</div><div class="v">{{sm['a']}} <span class="k">(৳{{money(sm['aa'])}})</span></div></div>
<div class="card"><div class="k">বাতিল</div><div class="v">{{sm['r']}}</div></div></div>
<div class="row" style="margin-bottom:10px">{% for k,l in [('pending','পেন্ডিং'),('approved','অনুমোদিত'),('rejected','বাতিল'),('all','সব')] %}<a class="btn sm {{'' if k==st else 's'}}" href="?status={{k}}">{{l}}</a>{% endfor %}</div>"""
                + REF_LIST, active="/admin/referrals", rows=rows, sm=sm, st=st, pool_av=pool_available())


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
            if act == "approve":
                # Registration alone never pays: the referred user must already have an approved Add Money transaction.
                res = referral_reward_pay(r, rf, x, a, "manual by %s" % a["member_id"], need_deposit=True, admin_note=note)
                if res != "paid":
                    err({"no_deposit": "রেফার করা ইউজারের এখনো কোনো অনুমোদিত ডিপোজিট নেই — রিওয়ার্ড দেওয়া যাবে না।",
                         "no_funds": "কমিশন পুলে পর্যাপ্ত ফান্ড নেই — আগে পুলে ফান্ড যোগ করুন।",
                         "blocked": "রেফারার ব্লকড। আনব্লক করুন অথবা বাতিল করুন।"}.get(res, "এই রেফারেল আগেই প্রক্রিয়া করা হয়েছে।"))
                    return back("/admin/referrals")
            else:
                cur = db().execute("UPDATE referrals SET status='rejected', decided_by=?, decided_by_id=?, decided_at=?, note=? WHERE id=? AND status='pending'",
                                   (who, a["id"], now(), note, i))
                if cur.rowcount != 1:
                    raise LedgerError("duplicate decision")
                notify(rf["id"], "রেফারেল বাতিল", "#%s-এর রেফারেল বোনাস অনুমোদিত হয়নি।%s" % (x["member_id"], (" কারণ: " + note) if note else ""))
                audit("referral_reject", "ref#%d referrer#%s referred#%s" % (i, rf["member_id"], x["member_id"]))
    except (LedgerError, PoolError) as e:
        err("ব্যর্থ (কিছুই পরিবর্তন হয়নি): " + str(e)); return back("/admin/referrals")
    flash("রেফারেল %s।" % ("রিওয়ার্ড দেওয়া হয়েছে" if act == "approve" else "বাতিল হয়েছে"))
    return back("/admin/referrals")


# ---------------------------------------------------------------- admin: commission (rates, pool-backed manual commission, history)
def _tok(name="idem", n=32):
    return re.sub(r"\W", "", request.form.get(name, ""))[:n]


@app.route("/admin/commission/rate", methods=["POST"])
@staff_required("rates")
def admin_comm_rate():
    a = me()
    scope = request.form.get("scope", "user")
    op = request.form.get("op", "set")
    reason = request.form.get("reason", "").strip()[:200]
    tok = _tok()
    back_to = request.form.get("back") if request.form.get("back", "").startswith("/admin/") else "/admin/commission"
    try:
        val = round(float(request.form.get("value", "") or 0), 3)
    except ValueError:
        val = -1
    if scope not in ("user", "global", "max") or op not in ("set", "inc", "dec", "reset") or len(reason) < 3 or len(tok) < 6 or val != val or val < 0:
        err("সঠিক মান, কারণ (কমপক্ষে ৩ অক্ষর) দিন।"); return redirect(back_to)
    if scope in ("global", "max") and not has_perm("rates_global", a):
        abort(403)
    d, m = rate_cfg()
    uid = request.form.get("uid", type=int)
    x = None
    if scope == "user":
        x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (uid,)) if uid else None
        if not x:
            abort(404)
        back_to = "/admin/users/%d" % x["id"] if back_to == "/admin/commission" else back_to
        old = None if x["comm_rate"] is None else float(x["comm_rate"])
        base = effective_rate({"comm_rate": x["comm_rate"]})  # manual-rate maths ignores VIP
    elif scope == "global":
        old, base = d, d
    else:
        old, base = m, m
    if op == "reset":
        if scope != "user":
            err("রিসেট শুধু ইউজার-নির্দিষ্ট রেটের জন্য।"); return redirect(back_to)
        new = None
    else:
        new = round({"set": val, "inc": base + val, "dec": base - val}[op], 3)
        top = m if scope != "max" else COMM_RATE_CEILING
        if new < 0 or new > top + 1e-9:
            err("রেট ০%% থেকে %s%% এর মধ্যে হতে হবে (সর্বোচ্চ সীমা ১০%%)।" % ("%g" % top)); return redirect(back_to)
        if scope == "global" and new > m:
            err("গ্লোবাল রেট সর্বোচ্চ রেটের (%g%%) বেশি হতে পারে না।" % m); return redirect(back_to)
        if scope == "max" and new < d:
            err("সর্বোচ্চ রেট ডিফল্ট রেটের (%g%%) কম হতে পারে না — আগে ডিফল্ট কমান।" % d); return redirect(back_to)
    try:
        with atomic():
            db().execute("INSERT INTO commission_rate_log(scope,user_id,old_rate,new_rate,reason,idem,actor,actor_id,created) VALUES(?,?,?,?,?,?,?,?,?)",
                         (scope, x["id"] if x else None, old, new, reason, "rate:" + tok, a["member_id"], a["id"], now()))
            if scope == "user":
                db().execute("UPDATE users SET comm_rate=? WHERE id=?", (new, x["id"]))
                shown = effective_rate({"comm_rate": new, "vip_rate": x["vip_rate"]})
                notify(x["id"], "কমিশন রেট আপডেট", "আপনার কমিশন রেট এখন %g%%।" % shown, None,
                       "Commission rate updated", "Your commission rate is now %g%%." % shown)
            else:
                db().execute("INSERT OR REPLACE INTO settings VALUES(?,?)", ("comm_rate_default" if scope == "global" else "comm_rate_max", "%g" % new))
            audit("comm_rate", "scope=%s user=%s %s -> %s reason=%s" % (scope, x["id"] if x else "-", old, new, reason))
    except INTEGRITY:
        flash("এই পরিবর্তন আগেই হয়েছে (ডুপ্লিকেট সাবমিট)।"); return redirect(back_to)
    flash("রেট আপডেট হয়েছে।")
    return redirect(back_to)


@app.route("/admin/commission", methods=["GET", "POST"])
@staff_required("commissions", "rates")
def admin_commission():
    a = me()
    if request.method == "POST":
        if not has_perm("commissions", a):
            abort(403)
        op = request.form.get("op", "give")
        uid = request.form.get("uid", type=int)
        amt = parse_amount(request.form.get("amount"))
        reason = request.form.get("reason", "").strip()[:200]
        token = _tok()
        x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (uid,)) if uid else None
        back_to = "/admin/commission" + ("?uid=%d" % uid if uid else "")
        if op not in ("give", "reverse") or not x or (x["blocked"] and op == "give") or amt <= 0 or len(reason) < 3 or len(token) < 6:
            err("ইউজার নির্বাচন করুন এবং সঠিক পরিমাণ ও কারণ (কমপক্ষে ৩ অক্ষর) দিন।"); return redirect(back_to)
        try:
            with atomic():
                if op == "give":
                    idem = "com:" + token
                    cur = db().execute("INSERT OR IGNORE INTO commissions(user_id,amount,reason,given_by_id,given_by,idem,created) VALUES(?,?,?,?,?,?,?)",
                                       (x["id"], amt, reason, a["id"], "%s (%s)" % (a["name"], a["member_id"]), idem, now()))
                    if cur.rowcount == 0:
                        flash("এই কমিশন আগেই দেওয়া হয়েছে (ডুপ্লিকেট সাবমিট)।")
                    else:
                        pool_pay(x["id"], "commission", amt, idem, "commission", cur.lastrowid, reason, a["member_id"])
                        notify(x["id"], "কমিশন", "৳%s কমিশন যুক্ত হয়েছে — %s" % (money(amt), reason), None,
                               "Commission", "৳%s commission added — %s" % (money(amt), reason))
                        audit("commission", "#%s ৳%s (from pool) %s" % (x["member_id"], money(amt), reason))
                        flash("৳%s কমিশন #%s-কে দেওয়া হয়েছে (পুল থেকে)।" % (money(amt), x["member_id"]))
                else:
                    if amt > float(x["commission"] or 0) + 0.004:
                        raise PoolError("কাটার পরিমাণ ইউজারের মোট কমিশনের (৳%s) বেশি হতে পারে না।" % money(x["commission"]))
                    idem = "comrev:" + token
                    if pool_return(x["id"], amt, idem, "commission", None, reason, a["member_id"]):
                        notify(x["id"], "কমিশন সমন্বয়", "৳%s কমিশন কাটা হয়েছে — %s" % (money(amt), reason), None,
                               "Commission adjustment", "৳%s commission deducted — %s" % (money(amt), reason))
                        audit("commission_reverse", "#%s ৳%s (back to pool) %s" % (x["member_id"], money(amt), reason))
                        flash("৳%s কমিশন কাটা হয়েছে এবং পুলে ফেরত গেছে।" % money(amt))
                    else:
                        flash("এই অপারেশন আগেই হয়েছে।")
        except PoolError as e:
            err("ব্যর্থ, কিছুই পরিবর্তন হয়নি: " + str(e))
        except LedgerError as e:
            err("ব্যর্থ, কিছুই পরিবর্তন হয়নি: " + str(e))
        return redirect(back_to)
    s = request.args.get("q", "").strip().lstrip("#")[:40]
    like = "%" + s + "%"
    found = qa("SELECT * FROM users WHERE is_admin=0 AND (member_id=? OR name LIKE ? OR phone LIKE ?) ORDER BY id LIMIT 10", (s, like, like)) if s else []
    uid = request.args.get("uid", type=int)
    sel = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (uid,)) if uid else None
    where, args = "l.kind IN ('commission','commission_reversal')", []
    if sel:
        where += " AND l.user_id=?"; args.append(sel["id"])
    pg = make_pg(q1("SELECT COUNT(*) n FROM ledger l WHERE " + where, args)["n"], 30)
    hist = qa("SELECT l.*,u.member_id m,u.name n,(SELECT 1 FROM pool_ledger p WHERE p.ledger_idem=l.idem) pooled FROM ledger l JOIN users u ON u.id=l.user_id "
              "WHERE " + where + " ORDER BY l.id DESC LIMIT ? OFFSET ?", args + [30, pg["off"]])
    d, m = rate_cfg()
    custom = qa("SELECT id,member_id,name,comm_rate FROM users WHERE is_admin=0 AND comm_rate IS NOT NULL ORDER BY id LIMIT 30")
    rlog = qa("SELECT * FROM commission_rate_log ORDER BY id DESC LIMIT 10")
    bal, res = pool_balance(), pool_reserved()
    return page("""<div class="g2"><div class="card"><div class="k">পুল ব্যালেন্স</div><div class="v">৳ {{money(bal)}}</div></div>
<div class="card"><div class="k">কমিশন দেওয়ার জন্য উপলব্ধ</div><div class="v">৳ {{money(bal-res)}}</div><div class="k">(প্রতিশ্রুত ৳{{money(res)}} বাদে)</div></div></div>
{% if can('pool_view') %}<a class="btn s" href="/admin/pool" style="width:100%;margin-bottom:10px">🏦 কমিশন পুল দেখুন / ফান্ড ইতিহাস</a>{% endif %}
<div class="card"><h3>কমিশন রেট</h3><p class="k">গ্লোবাল (ডিফল্ট): <b>{{d}}%</b> · সর্বোচ্চ: <b>{{m}}%</b> (কোনোভাবেই ১০%-এর বেশি নয়)। ইউজারের নিজস্ব রেট থাকলে সেটাই প্রযোজ্য।</p>
{% if can('rates_global') %}<form method="post" action="/admin/commission/rate" data-confirm="গ্লোবাল রেট বদলাবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="idem" value="{{idem}}1"><input type="hidden" name="scope" value="global">
<select name="op"><option value="set">সেট করুন</option><option value="inc">বাড়ান (+)</option><option value="dec">কমান (−)</option></select>
<input name="value" type="number" step="0.01" min="0" max="10" placeholder="% মান" required><input name="reason" placeholder="কারণ" required minlength="3" maxlength="200"><button style="width:100%">গ্লোবাল রেট আপডেট</button></form>
<form method="post" action="/admin/commission/rate" data-confirm="সর্বোচ্চ রেট বদলাবেন?" style="margin-top:8px"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="idem" value="{{idem}}2"><input type="hidden" name="scope" value="max"><input type="hidden" name="op" value="set">
<input name="value" type="number" step="0.01" min="0" max="10" placeholder="সর্বোচ্চ রেট %" required><input name="reason" placeholder="কারণ" required minlength="3" maxlength="200"><button class="s" style="width:100%">সর্বোচ্চ রেট আপডেট</button></form>{% endif %}
{% if custom %}<h4>ইউজার-নির্দিষ্ট রেট</h4><div class="tw"><table>{% for c in custom %}<tr><td><a href="/admin/users/{{c['id']}}">#{{c['member_id']}} {{c['name']}}</a></td><td>{{'%g'|format(c['comm_rate'])}}%</td></tr>{% endfor %}</table></div>{% endif %}
{% if rlog %}<h4>রেট পরিবর্তনের ইতিহাস</h4><div class="tw"><table><tr><th>স্কোপ</th><th>পুরনো</th><th>নতুন</th><th>কারণ</th><th>কে</th><th>সময়</th></tr>{% for r in rlog %}<tr><td>{{r['scope']}}{% if r['user_id'] %} #{{r['user_id']}}{% endif %}</td><td>{{r['old_rate'] if r['old_rate'] is not none else '-'}}</td><td>{{r['new_rate'] if r['new_rate'] is not none else 'গ্লোবাল'}}</td><td>{{r['reason']}}</td><td>{{r['actor']}}</td><td>{{r['created'][:16]}}</td></tr>{% endfor %}</table></div>{% endif %}</div>
{% if can('commissions') %}<div class="card"><h2>ম্যানুয়াল কমিশন (পুল থেকে)</h2><p class="k">কমিশন সবসময় কমিশন পুল থেকে যায়; পুলে ফান্ড না থাকলে দেওয়া যায় না। কারণ বাধ্যতামূলক এবং ইউজার নোটিফিকেশন পাবেন।</p>
<form><label>ইউজার খুঁজুন (মেম্বার আইডি / নাম / ফোন)</label><input name="q" value="{{s}}" required><button style="width:100%">খুঁজুন</button></form>
{% for f in found %}<a href="?uid={{f['id']}}&q={{s|urlencode}}"><div class="card" style="margin:10px 0 0"><b>#{{f['member_id']}} {{f['name']}}</b> {% if f['blocked'] %}<span class="pill rejected">blocked</span>{% endif %}
<div class="k">{{f['phone']}} · ৳ {{money(f['balance'])}} · কমিশন ৳{{money(f['commission'])}}</div></div></a>{% endfor %}
{% if s and not found %}<div class="empty">কোনো ইউজার পাওয়া যায়নি</div>{% endif %}</div>
{% if sel %}<div class="card"><h3>প্রাপক: #{{sel['member_id']}} {{sel['name']}} <span class="k">(কমিশন মোট ৳{{money(sel['commission'])}})</span></h3>
<form method="post" data-confirm="লেজারে স্থায়ীভাবে রেকর্ড হবে। নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="idem" value="{{idem}}3"><input type="hidden" name="uid" value="{{sel['id']}}">
<label>ধরন</label><select name="op"><option value="give">➕ কমিশন দিন (পুল থেকে)</option><option value="reverse">➖ কমিশন কাটুন (পুলে ফেরত)</option></select>
<label>পরিমাণ (৳)</label><input name="amount" type="number" step="0.01" min="0.01" required><label>কারণ (আবশ্যক)</label><input name="reason" required minlength="3" maxlength="200">
<button style="width:100%" class="g">সম্পন্ন করুন</button></form></div>{% endif %}{% endif %}
<div class="card"><h3>কমিশন ইতিহাস{% if sel %} — #{{sel['member_id']}}{% endif %}</h3><div class="tw"><table><tr><th>ইউজার</th><th>৳</th><th>উৎস</th><th>কারণ</th><th>সময়</th></tr>
{% for h in hist %}<tr><td>#{{h['m']}} {{h['n']}}</td><td>{{money(h['amount'])}}</td><td>{{'পুল' if h['pooled'] else 'পুল-পূর্ব'}}</td><td>{{h['note'] or ''}}</td><td>{{h['created'][:16]}}</td></tr>{% endfor %}</table></div></div>""" + PAGER,
                active="/admin/commission", s=s, found=found, sel=sel, hist=hist, pg=pg, d=d, m=m, custom=custom, rlog=rlog,
                bal=bal, res=res, idem=secrets.token_hex(8))


# ---------------------------------------------------------------- admin: Commission Pool
@app.route("/admin/pool")
@staff_required("pool_view")
def admin_pool():
    t0 = now()
    kd = request.args.get("kind", "")
    where, args = "1=1", []
    if kd in ("fund", "payout", "reversal", "withdraw"):
        where, args = "kind=?", [kd]
    pg = make_pg(q1("SELECT COUNT(*) n FROM pool_ledger WHERE " + where, args)["n"], 30)
    rows = qa("SELECT * FROM pool_ledger WHERE " + where + " ORDER BY id DESC LIMIT ? OFFSET ?", args + [30, pg["off"]])
    t = q1("SELECT COALESCE(SUM(CASE WHEN kind='fund' THEN amount END),0) f, COALESCE(SUM(CASE WHEN kind='payout' THEN -amount END),0) p, "
           "COALESCE(SUM(CASE WHEN kind='reversal' THEN amount END),0) r, COALESCE(SUM(CASE WHEN kind='withdraw' THEN -amount END),0) w FROM pool_ledger")
    bal, res = pool_balance(), pool_reserved()
    if pg["p"] == 1:
        alerts_seen(lambda link, ts: _admin_badge_key(link) == "/admin/pool" and ts < t0)
    att = q1("SELECT * FROM pool_attestations ORDER BY id DESC LIMIT 1")
    atts = qa("SELECT * FROM pool_attestations ORDER BY id DESC LIMIT 5")
    ledger_sum = round(float(q1("SELECT COALESCE(SUM(amount),0) s FROM pool_ledger")["s"]), 2)
    by_src = qa("SELECT source_type k, COALESCE(SUM(amount),0) s, COUNT(*) n FROM pool_ledger WHERE kind='fund' GROUP BY source_type ORDER BY s DESC")
    by_use = qa("SELECT COALESCE(ref_type,'-') k, COALESCE(SUM(-amount),0) s, COUNT(*) n FROM pool_ledger WHERE kind='payout' GROUP BY ref_type ORDER BY s DESC")
    return page("""<div class="g2"><div class="card"><div class="k">পুল ব্যালেন্স</div><div class="v">৳ {{money(bal)}}</div></div>
<div class="card"><div class="k">উপলব্ধ (প্রতিশ্রুত বাদে)</div><div class="v">৳ {{money(bal-res)}}</div><div class="k">প্রতিশ্রুত: ৳{{money(res)}}</div></div>
<div class="card"><div class="k">মোট যোগ হয়েছে</div><div class="v">৳ {{money(t['f'])}}</div></div>
<div class="card"><div class="k">কমিশন/বোনাস দেওয়া হয়েছে</div><div class="v">৳ {{money(t['p'])}}</div><div class="k">ফেরত: ৳{{money(t['r'])}} · তোলা: ৳{{money(t['w'])}}</div></div></div>
{% if ledger_sum != bal %}<div class="msg error">⚠ পুল ব্যালেন্স (৳{{money(bal)}}) এবং পুল-লেজারের যোগফল (৳{{money(ledger_sum)}}) মিলছে না! অডিট করুন।</div>{% endif %}
<div class="card"><h3>বাস্তব ফান্ডের সঙ্গে মিলানো</h3><p class="k">পুলের টাকা বাস্তবে আলাদা অ্যাকাউন্টে (যেমন ব্যাংক/মোবাইল ওয়ালেট) থাকতে হবে এবং এখানকার ব্যালেন্সের সমান হতে হবে। নিয়মিত সেই অ্যাকাউন্টের আসল ব্যালেন্স এখানে রেকর্ড করুন।</p>
{% if att %}<div class="{{'msg ok' if att['difference']|abs < 0.005 else 'msg error'}}">সর্বশেষ ({{att['created'][:16]}}): ঘোষিত ৳{{money(att['declared_balance'])}} — লেজার ৳{{money(att['ledger_balance'])}} — {% if att['difference']|abs < 0.005 %}✅ মিলেছে{% else %}⚠ পার্থক্য ৳{{money(att['difference'])}}{% endif %} ({{att['holding_account']}})</div>
{% else %}<div class="k">এখনো কোনো মিলানো রেকর্ড নেই।</div>{% endif %}
{% if can('pool_fund') %}<form method="post" action="/admin/pool/attest" data-confirm="স্থায়ীভাবে রেকর্ড হবে। নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="idem" value="{{idem}}a">
<label>আলাদা অ্যাকাউন্টে এখন আসল ব্যালেন্স (৳)</label><input name="declared" type="number" step="0.01" min="0" required>
<label>কোন অ্যাকাউন্ট (নাম/শেষ ৪ ডিজিট)</label><input name="holding" required minlength="3" maxlength="80"><input name="note" placeholder="নোট (ঐচ্ছিক)" maxlength="200"><button class="s" style="width:100%">মিলানো রেকর্ড করুন</button></form>{% endif %}
{% for x in atts[1:] %}<div class="k">{{x['created'][:16]}} · ঘোষিত ৳{{money(x['declared_balance'])}} · পার্থক্য ৳{{money(x['difference'])}}</div>{% endfor %}</div>
{% if can('pool_fund') %}<div class="card"><h3>➕ পুলে ফান্ড যোগ করুন (শুধু সুপার অ্যাডমিন)</h3><p class="k">শুধু বাস্তবে আলাদা রাখা প্রচারণা/ব্যবসায়িক ফান্ড যোগ করুন। উৎস, তারিখ ও রেফারেন্স স্থায়ীভাবে সংরক্ষিত হবে; একই রেফারেন্স দুবার ব্যবহার করা যায় না।</p>
<form method="post" action="/admin/pool/fund" data-confirm="পুলে ফান্ড যোগ করবেন? এটি স্থায়ী রেকর্ড।"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="idem" value="{{idem}}f">
<label>উৎস</label><select name="source">{% for k,l in sources.items() %}<option value="{{k}}">{{l}}</option>{% endfor %}</select>
<label>পরিমাণ (৳)</label><input name="amount" type="number" step="0.01" min="0.01" required><label>তারিখ</label><input name="event_date" type="date" value="{{today}}" required>
<label>ফান্ড যে অ্যাকাউন্টে আছে (নাম/শেষ ৪ ডিজিট)</label><input name="holding" required minlength="3" maxlength="80"><label>রেফারেন্স (ব্যাংক স্লিপ / TrxID / ভাউচার নং)</label><input name="reference" required minlength="4" maxlength="60">
<input name="note" placeholder="নোট (ঐচ্ছিক)" maxlength="200"><button class="g" style="width:100%">ফান্ড যোগ করুন</button></form></div>
<div class="card"><h3>➖ পুল থেকে ফান্ড ফেরত নেওয়া / সংশোধন (সুপার অ্যাডমিন)</h3><p class="k">শুধু প্রতিশ্রুত কমিশনের বাইরের উপলব্ধ ফান্ড তোলা যায়।</p>
<form method="post" action="/admin/pool/withdraw" data-confirm="পুল থেকে তুলবেন? স্থায়ী রেকর্ড।"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="idem" value="{{idem}}w">
<input name="amount" type="number" step="0.01" min="0.01" placeholder="পরিমাণ ৳" required><input name="reason" placeholder="কারণ (কমপক্ষে ৫ অক্ষর)" required minlength="5" maxlength="200"><button class="r" style="width:100%">পুল থেকে বিয়োগ</button></form></div>{% endif %}
<div class="card"><h3>ফান্ডের উৎস (এ পর্যন্ত)</h3>{% for r in by_src %}<div class="row" style="justify-content:space-between"><span>{{sources.get(r['k'], r['k'])}} <span class="k">({{r['n']}}টি)</span></span><b>৳{{money(r['s'])}}</b></div>{% endfor %}{% if not by_src %}<div class="k">এখনো কোনো ফান্ড যোগ হয়নি</div>{% endif %}
<h3 style="margin-top:12px">কীভাবে খরচ হয়েছে</h3>{% for r in by_use %}<div class="row" style="justify-content:space-between"><span>{{use_label.get(r['k'], r['k'])}} <span class="k">({{r['n']}}টি)</span></span><b>৳{{money(r['s'])}}</b></div>{% endfor %}{% if not by_use %}<div class="k">এখনো কোনো প্রদান হয়নি</div>{% endif %}
{% if can('reports') %}<a class="btn sm s" style="margin-top:8px" href="/admin/reports/pool?fmt=csv&detail=1&from=2000-01-01&to=2099-12-31">⬇ পুল ইতিহাস CSV</a> <a class="btn sm s" style="margin-top:8px" href="/admin/reconcile">🧮 মিলানো</a>{% endif %}</div>
<div class="card"><h3>পুল লেজার</h3><div class="row" style="margin-bottom:8px">{% for k,l in [('', 'সব'),('fund','ফান্ড'),('payout','প্রদত্ত'),('reversal','ফেরত'),('withdraw','তোলা')] %}<a class="btn sm {{'' if k==kd else 's'}}" href="?kind={{k}}">{{l}}</a>{% endfor %}</div>
<div class="tw"><table><tr><th>সময়</th><th>ধরন</th><th>৳</th><th>ব্যালেন্স</th><th>উৎস/রেফারেন্স</th><th>কে</th></tr>
{% for r in rows %}<tr><td>{{r['created'][:16]}}</td><td>{{r['kind']}}</td><td>{{money(r['amount'])}}</td><td>{{money(r['balance_after'])}}</td>
<td>{% if r['kind']=='fund' %}{{sources.get(r['source_type'], r['source_type'])}} · {{r['reference']}} · {{r['event_date']}} · {{r['holding_account']}}{% else %}{% if r['user_id'] %}<a href="/admin/users/{{r['user_id']}}">ইউজার #{{r['user_id']}}</a> {% endif %}{{r['note'] or ''}}{% endif %}</td><td>{{r['actor']}}</td></tr>{% endfor %}</table></div></div>""" + PAGER,
                active="/admin/pool", rows=rows, t=t, bal=bal, res=res, att=att, atts=atts, ledger_sum=ledger_sum, sources=POOL_SOURCES, kd=kd, pg=pg, by_src=by_src, by_use=by_use, use_label=POOL_USE,
                idem=secrets.token_hex(8), today=datetime.utcnow().strftime("%Y-%m-%d"))


def _pool_form_common():
    return _tok(), request.form.get("amount", "")


@app.route("/admin/pool/fund", methods=["POST"])
@staff_required("pool_fund")
def admin_pool_fund():
    a = me()
    tok = _tok()
    amt = parse_amount(request.form.get("amount"))
    src = request.form.get("source", "")
    holding = request.form.get("holding", "").strip()[:80]
    ref = request.form.get("reference", "").strip()[:60]
    nref = re.sub(r"[^A-Z0-9]", "", ref.upper())
    ev = request.form.get("event_date", "").strip()
    try:
        evd = datetime.strptime(ev, "%Y-%m-%d")
    except ValueError:
        evd = None
    if src not in POOL_SOURCES or amt <= 0 or amt > 100_000_000 or len(holding) < 3 or len(nref) < 4 or len(tok) < 6 or not evd \
            or evd > datetime.utcnow() + timedelta(days=1):
        err("উৎস, পরিমাণ, বৈধ তারিখ (ভবিষ্যতের নয়), অ্যাকাউন্ট ও কমপক্ষে ৪ অক্ষরের রেফারেন্স দিন।"); return redirect("/admin/pool")
    try:
        with atomic():
            if _pool_apply("fund", amt, "poolfund:" + tok, ref_type="fund", note=request.form.get("note", "").strip()[:200], actor=a["member_id"],
                           source_type=src, holding=holding, reference=ref, norm_ref=nref, event_date=ev):
                audit("pool_fund", "৳%s src=%s ref=%s acct=%s date=%s" % (money(amt), src, ref, holding, ev))
                flash("৳%s পুলে যোগ হয়েছে।" % money(amt))
            else:
                flash("এই ফান্ডিং আগেই রেকর্ড হয়েছে (ডুপ্লিকেট সাবমিট)।")
    except INTEGRITY:
        err("এই রেফারেন্স দিয়ে আগেই ফান্ড যোগ করা হয়েছে।")
    except PoolError as e:
        err(str(e))
    return redirect("/admin/pool")


@app.route("/admin/pool/withdraw", methods=["POST"])
@staff_required("pool_fund")
def admin_pool_withdraw():
    a = me()
    tok = _tok()
    amt = parse_amount(request.form.get("amount"))
    reason = request.form.get("reason", "").strip()[:200]
    if amt <= 0 or len(reason) < 5 or len(tok) < 6:
        err("পরিমাণ ও কারণ (কমপক্ষে ৫ অক্ষর) দিন।"); return redirect("/admin/pool")
    try:
        with atomic():
            if pool_available() + 0.004 < amt:
                raise PoolError("উপলব্ধ ফান্ড (প্রতিশ্রুত কমিশন বাদে) ৳%s, কিন্তু চাওয়া ৳%s।" % (money(max(pool_available(), 0)), money(amt)))
            if _pool_apply("withdraw", -amt, "poolwd:" + tok, ref_type="withdraw", note=reason, actor=a["member_id"]):
                audit("pool_withdraw", "৳%s %s" % (money(amt), reason))
                flash("পুল থেকে ৳%s বিয়োগ হয়েছে।" % money(amt))
            else:
                flash("এই অপারেশন আগেই হয়েছে।")
    except PoolError as e:
        err("ব্যর্থ, কিছুই পরিবর্তন হয়নি: " + str(e))
    return redirect("/admin/pool")


@app.route("/admin/pool/attest", methods=["POST"])
@staff_required("pool_fund")
def admin_pool_attest():
    a = me()
    tok = _tok()
    try:
        declared = round(float(request.form.get("declared", "")), 2)
    except ValueError:
        declared = -1
    holding = request.form.get("holding", "").strip()[:80]
    if declared < 0 or declared != declared or len(holding) < 3 or len(tok) < 6:
        err("আসল ব্যালেন্স ও অ্যাকাউন্টের নাম দিন।"); return redirect("/admin/pool")
    try:
        with atomic():
            led = pool_balance()
            db().execute("INSERT INTO pool_attestations(declared_balance,ledger_balance,difference,holding_account,note,idem,actor,actor_id,created) VALUES(?,?,?,?,?,?,?,?,?)",
                         (declared, led, round(declared - led, 2), holding, request.form.get("note", "").strip()[:200], "att:" + tok, a["member_id"], a["id"], now()))
            audit("pool_attest", "declared ৳%s ledger ৳%s acct=%s" % (money(declared), money(led), holding))
    except INTEGRITY:
        flash("আগেই রেকর্ড হয়েছে।"); return redirect("/admin/pool")
    flash("মিলানো রেকর্ড হয়েছে।")
    return redirect("/admin/pool")


# ---------------------------------------------------------------- client decision for client_confirm requests
@app.route("/requests/<int:i>/decide", methods=["POST"])
@customer_required
def request_decide(i):
    u = me()
    act = request.form.get("act", "")
    if act not in ("approve", "reject"):
        abort(400)
    expire_requests()
    back_to = "/requests/%d" % i
    alert = None
    try:
        with atomic():
            r = q1("SELECT * FROM requests WHERE id=? AND user_id=?", (i, u["id"]))
            if not r or r["flow"] != "client_confirm":
                abort(404)
            if r["status"] != "pending":
                raise ReqError("এই অনুরোধে এখন আর সিদ্ধান্ত নেওয়া যাবে না (হয়তো আগেই সম্পন্ন, বাতিল বা মেয়াদোত্তীর্ণ)।")
            t = now()
            if r["expires_at"] and r["expires_at"] <= t:
                raise ReqError("অনুরোধটির মেয়াদ শেষ হয়েছে।")
            cu = q1("SELECT blocked FROM users WHERE id=?", (u["id"],))
            if not cu or cu["blocked"]:
                raise ReqError("আপনার অ্যাকাউন্ট সক্রিয় নয়।")
            new = "approved" if act == "approve" else "rejected"
            cur = db().execute("UPDATE requests SET status=?, updated=?, decided_by_id=?, decided_by=?, decided_at=?, client_decided_at=? "
                               "WHERE id=? AND user_id=? AND status='pending'", (new, t, u["id"], u["member_id"], t, t, i, u["id"]))
            if cur.rowcount != 1:
                raise ReqError("এই অনুরোধ আগেই প্রক্রিয়া হয়েছে।")
            notif_read_link(u["id"], "/requests/%d" % i)
            alerts_done("/admin/requests/%d" % i)
            if act == "approve":
                principal, com = round(float(r["amount"]), 2), round(float(r["commission"] or 0), 2)
                if not post(u["id"], "request_payment", -principal, "req:%d:principal" % i, "request", i, "Order %s payment" % r["order_id"], u["member_id"]):
                    raise ReqError("এই অনুরোধের লেজার এন্ট্রি আগেই আছে।")
                company_post("client_payment", principal, "req:%d:receipt" % i, u["id"], "request", i, "Order %s" % r["order_id"], u["member_id"])
                if com > 0:
                    pool_pay(u["id"], "commission", com, "req:%d:commission" % i, "request", i, "Order %s commission" % r["order_id"], u["member_id"], own_req=i)
            req_log(i, "client_" + act, "pending", new, u["member_id"], u["id"], "")
            audit("req_client_" + act, "req#%d order=%s ৳%s commission ৳%s user#%d" % (i, r["order_id"], r["amount"], r["commission"] or 0, u["id"]), actor=u)
            net = (-principal + com) if act == "approve" else 0
            alert = ("ক্লায়েন্ট অনুরোধ " + ("অনুমোদন করেছে" if act == "approve" else "বাতিল করেছে"), "#%s Order %s (৳%s)" % (u["member_id"], r["order_id"], money(r["amount"])))
    except ReqError as ex:
        err(str(ex)); return redirect(back_to)
    except LedgerError:
        err("আপনার ব্যালেন্স অপর্যাপ্ত — কিছুই কাটা হয়নি।"); return redirect(back_to)
    except PoolError:
        err("কমিশন দেওয়ার ফান্ড এই মুহূর্তে উপলব্ধ নয় — কিছুই কাটা হয়নি। অ্যাডমিনকে জানানো হয়েছে।")
        alert_admins("পুলে ফান্ড কম", "Order %s অনুমোদন আটকেছে" % r["order_id"], "/admin/pool", "pool_view")
        return redirect(back_to)
    if alert:
        alert_admins(alert[0], alert[1], "/admin/requests/%d" % i, "requests")
    flash("অনুমোদন সম্পন্ন। ওয়ালেট পরিবর্তন: ৳%s" % money(net) if act == "approve" else "অনুরোধ বাতিল করা হয়েছে।")
    return redirect(back_to)



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
    except INTEGRITY:
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
    return page("""<div class="card"><h2>📣 স্ক্রলিং নোটিশ (ড্যাশবোর্ডের উপরে)</h2><p class="k">চালু থাকলে সব ক্লায়েন্টের ড্যাশবোর্ডে ডান থেকে বামে চলতে থাকবে। বন্ধ বা ফাঁকা হলে নিজে থেকে লুকিয়ে যাবে।</p>
<form method="post" action="/admin/notices/ticker"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label class="ck"><input type="checkbox" name="on" value="1" {{'checked' if tk_on}}> চালু রাখুন</label>
<label>লেখা (বাংলা)</label><textarea name="bn" rows="2" maxlength="300">{{tk_bn}}</textarea>
<label>Text (English)</label><textarea name="en" rows="2" maxlength="300">{{tk_en}}</textarea><button style="width:100%">সেভ করুন</button></form></div>
<div class="card"><h2>নোটিশ প্রকাশ</h2><form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}"><label>শিরোনাম</label><input name="title" required maxlength="100">
<label>বিস্তারিত</label><textarea name="body" rows="3" maxlength="500"></textarea><button style="width:100%">প্রকাশ করুন</button></form></div>
{% for n in rows %}<div class="card"><b>{{(n['title_en'] if lang=='en' and n['title_en'] else n['title'])}}</b><div>{{(n['body_en'] if lang=='en' and n['body_en'] else n['body'])}}</div><div class="k">{{n['created'][:16]}}</div></div>{% endfor %}""", active="/admin/notices", rows=rows, tk_on=setting("ticker_on", "0") == "1", tk_bn=setting("ticker_text_bn"), tk_en=setting("ticker_text_en"))


@app.route("/admin/notices/ticker", methods=["POST"])
@staff_required("notices")
def admin_ticker():
    f = request.form
    on = "1" if f.get("on") == "1" else "0"
    bn, en = " ".join(f.get("bn", "").split())[:300], " ".join(f.get("en", "").split())[:300]
    if on == "1" and not (bn or en):
        err("চালু করতে অন্তত একটি লেখা দিন।"); return redirect("/admin/notices")
    with atomic():
        for k, v in (("ticker_on", on), ("ticker_text_bn", bn), ("ticker_text_en", en)):
            db().execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (k, v))
        audit("ticker_update", "on=%s chars=%d/%d" % (on, len(bn), len(en)))
    flash("সেভ হয়েছে।")
    return redirect("/admin/notices")


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
                if not q1("SELECT 1 FROM tickets WHERE status='open'"):
                    alerts_done("/admin/tickets")
        return redirect("/admin/tickets")
    t0 = now()
    rows = qa("SELECT t.*,u.member_id,u.name,u.phone FROM tickets t JOIN users u ON u.id=t.user_id ORDER BY (t.status='open') DESC, t.id DESC LIMIT 50")
    _seen_list("/admin/tickets", rows, 50, {"p": 1}, t0)
    return page("""{% if not rows %}<div class="card empty">কোনো টিকিট নেই</div>{% endif %}{% for t in rows %}<div class="card"><b>{{t['subject']}}</b> <span class="pill {{'approved' if t['status']=='closed' else 'pending'}}">{{t['status']}}</span>
<div class="k">#{{t['member_id']}} {{t['name']}} · {{t['phone']}} · {{t['created'][:16]}}</div><div>{{t['message']}}</div>
{% if t['reply'] %}<div class="k">↳ {{t['reply']}}{% if t['replied_by'] %} — {{t['replied_by']}}{% endif %}</div>{% else %}<form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="id" value="{{t['id']}}">
<input name="reply" placeholder="উত্তর লিখুন" required maxlength="500"><button class="btn sm">পাঠান</button></form>{% endif %}
{% if can('users_view') %}<a class="k" href="/admin/users/{{t['user_id']}}">👤 ইউজার দেখুন</a>{% endif %}</div>{% endfor %}""", active="/admin/tickets", rows=rows)


ONOFF = [("1", "চালু"), ("0", "বন্ধ")]
# (id, title, fields, info) - field = (key, type, label[, options]); every field listed here is actually used by the app
SET_SECTIONS = [
    ("general", "⚙️ জেনারেল সেটিংস",
     [("welcome", "textarea", "স্বাগত বার্তা (হোম পেজে দেখায়)"),
      ("req_expiry_hours", "int", "ম্যানুয়াল রিকোয়েস্টের ডিফল্ট মেয়াদ (ঘণ্টা, ০ = মেয়াদ নেই)")], ""),
    ("payment", "💳 পেমেন্ট সেটিংস",
     [("bkash", "text", "bKash নম্বর"), ("nagad", "text", "Nagad নম্বর"), ("rocket", "text", "Rocket নম্বর")], ""),
    ("deposit", "➕ ডিপোজিট সেটিংস", [("min_deposit", "money", "ন্যূনতম ডিপোজিট (৳)")], ""),
    ("withdraw", "⬆ উইথড্র সেটিংস", [("min_withdraw", "money", "ন্যূনতম উইথড্র (৳)"), ("req_cancel_fee", "money", "ইউজার রিকোয়েস্ট বাতিল ফি (৳) — অ্যাডমিনের পাঠানো উইথড্র রিকোয়েস্ট ইউজার নিজে বাতিল করলে কাটা হবে")], ""),
    ("commission", "💰 কমিশন সেটিংস", [],
     "এই সিস্টেমে কমিশন স্বয়ংক্রিয় নয়। অ্যাডমিন কাজের কারণসহ ম্যানুয়ালি কমিশন দেন (কমিশন ট্যাব)। তাই এখানে কোনো হার সেট করার নেই।"),
    ("referral", "🎁 রেফারেল সেটিংস", [],
     "রেফারেল রিওয়ার্ডের পরিমাণ এখন আলাদা পেজ থেকে নিয়ন্ত্রণ করা হয় (নিচের বাটন)। রিওয়ার্ড শুধু রেফার করা ব্যক্তির প্রথম অনুমোদিত ডিপোজিটের পর, প্রতি ব্যক্তির জন্য একবার দেওয়া হয়।"),
    ("user", "👤 ইউজার সেটিংস", [("signup_open", "sel", "নতুন সাইন আপ", ONOFF)], ""),
    ("notification", "🔔 নোটিফিকেশন সেটিংস",
     [("notif_sound", "sel", "নোটিফিকেশন সাউন্ড (ডিফল্ট; প্রতিটি ডিভাইসে ব্যবহারকারী নিজে বদলাতে পারেন)", ONOFF)], ""),
    ("security", "🔒 নিরাপত্তা সেটিংস", [],
     "• সেশন মেয়াদ ৭ দিন • ১৫ মিনিটে ৮ বার ভুল লগইন হলে সাময়িক লক • স্ক্রিনশট ≤২MB (JPG/PNG/WEBP, কনটেন্ট যাচাই সহ) • "
     "সুপার অ্যাডমিনের পাসওয়ার্ড Render Environment-এর ADMIN_PASSWORD থেকে নিয়ন্ত্রিত।"),
    ("support", "💬 সাপোর্ট সেটিংস", [("telegram_url", "text", "টেলিগ্রাম সাপোর্ট URL (https://…)")], ""),
    ("appearance", "🎨 অ্যাপিয়ারেন্স সেটিংস",
     [("site_name", "text", "সাইটের নাম"),
      ("default_theme", "sel", "ডিফল্ট থিম (ব্যবহারকারী নিজে ডার্ক মোড বদলালে সেটিই চলবে)",
       [("auto", "ডিভাইস অনুযায়ী"), ("light", "লাইট"), ("dark", "ডার্ক")])], ""),
]
SET_KEYS = [f[0] for sec in SET_SECTIONS for f in sec[2]]


def _validate_section(v):
    if "telegram_url" in v and v["telegram_url"] and not v["telegram_url"].startswith("https://"):
        return "টেলিগ্রাম লিংক https:// দিয়ে শুরু হতে হবে।"
    for k in ("min_deposit", "min_withdraw", "req_cancel_fee"):
        if k in v and parse_amount(v[k]) <= 0:
            return "পরিমাণ সঠিক দিন।"
    if "req_expiry_hours" in v:
        if not re.fullmatch(r"\d{1,3}", v["req_expiry_hours"]) or int(v["req_expiry_hours"]) > 720:
            return "মেয়াদ ০ থেকে ৭২০ ঘণ্টার মধ্যে দিন।"
    for k in ("signup_open", "notif_sound"):
        if k in v and v[k] not in ("0", "1"):
            return "অবৈধ মান।"
    if "default_theme" in v and v["default_theme"] not in ("auto", "light", "dark"):
        return "অবৈধ থিম।"
    if "site_name" in v and not (1 <= len(v["site_name"]) <= 60):
        return "সাইটের নাম ১–৬০ অক্ষরের হতে হবে।"
    return None


@app.route("/admin/settings", methods=["GET", "POST"])
@staff_required("settings")
def admin_settings():
    if request.method == "POST":
        sec = request.form.get("section", "")
        spec = next((x for x in SET_SECTIONS if x[0] == sec and x[2]), None)
        if not spec:
            abort(400)
        v = {f[0]: request.form.get(f[0], "").strip() for f in spec[2]}
        e = _validate_section(v)
        if e:
            err(e); return redirect("/admin/settings?open=" + sec)
        with atomic():
            for k, val in v.items():
                db().execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (k, val[:2000]))
            audit("settings", "updated: " + sec)
        flash("সেভ হয়েছে।")
        return redirect("/admin/settings?open=" + sec)
    st = {k: setting(k) for k in SET_KEYS}
    st.setdefault("default_theme", "auto")
    for k, d in (("default_theme", "auto"), ("signup_open", "1"), ("notif_sound", "1"), ("req_expiry_hours", "24"), ("site_name", SITE), ("req_cancel_fee", "100")):
        st[k] = st[k] or d
    op = request.args.get("open", "general")
    return page("""{% for sec in secs %}<details class="card set" {{'open' if op==sec[0]}} id="{{sec[0]}}"><summary>{{sec[1]}}</summary>
{% if sec[3] %}<div class="k">{{sec[3]}}</div>{% endif %}{% if sec[0]=='referral' %}<a class="btn sm" style="margin-top:8px" href="/admin/referral-rewards">🎁 রেফারেল রিওয়ার্ড সেটিংস খুলুন</a>{% endif %}
{% if sec[2] %}<form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="section" value="{{sec[0]}}">
{% for f in sec[2] %}<label>{{f[2]}}</label>
{% if f[1]=='textarea' %}<textarea name="{{f[0]}}" rows="6">{{st[f[0]]}}</textarea>
{% elif f[1]=='sel' %}<select name="{{f[0]}}">{% for ov,ol in f[3] %}<option value="{{ov}}" {{'selected' if st[f[0]]==ov}}>{{ol}}</option>{% endfor %}</select>
{% elif f[1]=='money' %}<input name="{{f[0]}}" type="number" step="0.01" min="0.01" value="{{st[f[0]]}}">
{% elif f[1]=='int' %}<input name="{{f[0]}}" type="number" step="1" min="0" max="720" value="{{st[f[0]]}}">
{% else %}<input name="{{f[0]}}" value="{{st[f[0]]}}">{% endif %}{% endfor %}
<button style="width:100%">সেভ</button></form>{% endif %}
{% if sec[0]=='security' %}<div><p class="k">ডাটাবেস ব্যাকআপ — নিয়মিত ডাউনলোড করে নিরাপদ জায়গায় রাখুন।</p>
<form method="post" action="/admin/backup"><input type="hidden" name="_csrf" value="{{csrf_token}}"><button class="s" style="width:100%">⬇ ডাটাবেস ব্যাকআপ নামান</button></form>
<p class="k" style="margin-top:14px">স্ক্রিনশট ব্যাকআপ — সব পেমেন্ট স্ক্রিনশট একটি ZIP-এ (সঙ্গে manifest.csv, SHA-256 সহ)।</p>
<form method="post" action="/admin/backup/screenshots"><input type="hidden" name="_csrf" value="{{csrf_token}}"><button class="s" style="width:100%">🖼 স্ক্রিনশট ZIP নামান</button></form></div>{% endif %}
</details>{% endfor %}""", active="/admin/settings", st=st, secs=SET_SECTIONS, op=op)


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
    if PG:  # no database file exists: export every table as CSV (+ manifest with row counts and SHA-256) in one ZIP
        tmp = os.path.join(tempfile.gettempdir(), "ewallet-db-%s.zip" % datetime.utcnow().strftime("%Y%m%d-%H%M%S"))
        export_tables_zip(db(), tmp)

        @after_this_request
        def _rm(resp):
            try:
                os.remove(tmp)
            except OSError:
                pass
            return resp
        audit("backup_download", os.path.basename(tmp))
        return send_file(tmp, as_attachment=True, mimetype="application/zip", download_name=os.path.basename(tmp))
    tmp = os.path.join(tempfile.gettempdir(), "ewallet-backup-%s.db" % datetime.utcnow().strftime("%Y%m%d-%H%M%S"))
    dst = sqlite3.connect(tmp)
    db().backup(dst)
    dst.close()
    audit("backup_download", os.path.basename(tmp))
    return send_file(tmp, as_attachment=True, download_name=os.path.basename(tmp))


NULL_MARK = "\\N"


def export_tables_zip(conn, path):
    """Logical backup usable on any backend: <table>.csv (NULL written as \\N) + manifest.json (row counts, SHA-256, schema version).
    Written inside one read transaction so all tables are from the same moment."""
    import json
    manifest = {"schema_version": SCHEMA_VERSION, "created": now(), "tables": {}}
    conn.execute("BEGIN IMMEDIATE") if PG else None
    try:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            for t in TABLES:
                rows = conn.execute("SELECT * FROM %s ORDER BY 1" % t).fetchall() if t != "admin_alert_reads" else \
                    conn.execute("SELECT * FROM admin_alert_reads ORDER BY alert_id, admin_id").fetchall()
                cols = list(rows[0].keys()) if rows else [r[1] for r in conn.execute("PRAGMA table_info(%s)" % t)] if not PG else \
                    [r["column_name"] for r in conn.execute("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=? ORDER BY ordinal_position", (t,))]
                buf = io.StringIO()
                w = csv.writer(buf, lineterminator="\n")
                w.writerow(cols)
                for r in rows:
                    w.writerow([NULL_MARK if v is None else v for v in r])
                data = buf.getvalue().encode("utf-8")
                z.writestr(t + ".csv", data)
                manifest["tables"][t] = {"rows": len(rows), "sha256": hashlib.sha256(data).hexdigest()}
            z.writestr("manifest.json", json.dumps(manifest, indent=1))
    finally:
        if PG:
            conn.execute("COMMIT")


# ---------------------------------------------------------------- screenshot ZIP backup (Super Admin)
@app.route("/admin/backup/screenshots", methods=["POST"])
@staff_required("backup")
def admin_backup_screenshots():
    """Streams every stored screenshot into one ZIP (+ manifest.csv with SHA-256 and the linked record)."""
    try:
        names = store_list()
    except StorageError:
        err("স্টোরেজ থেকে তালিকা আনা যায়নি। একটু পরে চেষ্টা করুন।"); return redirect("/admin/settings?open=security")
    if not names:
        err("ব্যাকআপ নেওয়ার মতো কোনো স্ক্রিনশট পাওয়া যায়নি।"); return redirect("/admin/settings?open=security")
    links = {}
    for r in qa("SELECT t.screenshot s, t.id i, u.member_id m FROM tx t JOIN users u ON u.id=t.user_id WHERE t.screenshot IS NOT NULL"):
        links[r["s"]] = ("tx", r["i"], r["m"], "")
    for r in qa("SELECT t.screenshot s, t.id i, u.member_id m, t.order_id o FROM requests t JOIN users u ON u.id=t.user_id WHERE t.screenshot IS NOT NULL"):
        links[r["s"]] = ("request", r["i"], r["m"], r["o"])
    tmp = tempfile.NamedTemporaryFile(prefix="ewallet-shots-", suffix=".zip", delete=False)
    tmp.close()

    @after_this_request
    def _cleanup(resp):
        try:
            os.remove(tmp.name)
        except OSError:
            pass
        return resp
    man = io.StringIO()
    w = csv.writer(man)
    w.writerow(["file", "bytes", "sha256", "source", "record_id", "member_id", "order_id"])
    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_STORED) as z:
        for n in names:
            try:
                blob = store_get(n)
            except StorageError:
                blob = None
            if blob is None:
                continue
            h, size = hashlib.sha256(blob), len(blob)
            z.writestr("screenshots/" + n, blob)
            src = links.get(n, ("orphan", "", "", ""))
            w.writerow([n, size, h.hexdigest(), src[0], src[1], src[2], src[3]])
        z.writestr("manifest.csv", man.getvalue())
    audit("backup_screenshots", "%d files" % len(names))
    return send_file(tmp.name, as_attachment=True, mimetype="application/zip",
                     download_name="ewallet-screenshots-%s.zip" % datetime.utcnow().strftime("%Y%m%d-%H%M%S"))


# ================================================================ v4 additions
# ---------------------------------------------------------------- admin alerts (staff notifications)
def _alert_filter(u):
    perms = [p for p in list(PERM_LABELS) + ["staff", "settings", "backup"] if has_perm(p, u)]
    ph = ",".join("?" * len(perms)) or "NULL"
    return "(a.perm IS NULL OR a.perm IN (%s))" % ph, perms


def admin_unread(u):
    f, pa = _alert_filter(u)
    return q1("SELECT COUNT(*) c FROM admin_alerts a WHERE %s AND a.created>=? AND NOT EXISTS("
              "SELECT 1 FROM admin_alert_reads r WHERE r.alert_id=a.id AND r.admin_id=?)" % f,
              pa + [u["created"] or "", u["id"]])["c"]


def alert_admins(title, body="", link="", perm=None):
    """Staff notification; `perm` = permission a staff member needs to see it (None = every staff member). Never raises."""
    try:
        db().execute("INSERT INTO admin_alerts(title,body,link,perm,created) VALUES(?,?,?,?,?)",
                     (title[:120], body[:300], link, perm, now()))
    except DBERR:
        pass


# ---------------------------------------------------------------- per-feature unread badges + admin menu grid
ADMIN_ICONS = {"/admin/alerts": "🔔", "/admin/requests": "📨", "/admin/deposits": "💰", "/admin/withdrawals": "🏧", "/admin/users": "👥", "/admin/kyc": "🪪",
               "/admin/payment-numbers": "💳", "/admin/referrals": "🎁", "/admin/vip": "👑", "/admin/commission": "💸", "/admin/pool": "🏦",
               "/admin/reports": "📊", "/admin/reconcile": "🧮", "/admin/staff": "🛡️", "/admin/tickets": "🎫", "/admin/notices": "📢",
               "/admin/content": "📝", "/admin/settings": "⚙️", "/admin/audit": "📜", "/admin/profile": "👤"}
# longest path first so "/admin/payment-numbers" etc. match before any shorter prefix
_BADGE_PATHS = sorted((p for p, _, _ in ADMIN_TABS if p not in ("/admin", "/admin/alerts")), key=len, reverse=True)
_USER_BADGE_PATHS = ("/vip", "/requests", "/history", "/referral", "/support", "/payment-numbers", "/insight")


def _admin_badge_key(link):
    l = (link or "").split("?")[0].split("#")[0].rstrip("/")
    for p in _BADGE_PATHS:
        if l == p or l.startswith(p + "/"):
            return p
    return "/admin/alerts"


def _user_badge_key(link, title):
    l = (link or "").split("?")[0].rstrip("/")
    for p in _USER_BADGE_PATHS:
        if l == p or l.startswith(p + "/"):
            return p
    if l in ("/deposit", "/withdraw"):
        return "/history"
    t = title or ""
    if "রেফারেল" in t:
        return "/referral"
    if "সাপোর্ট" in t:
        return "/support"
    if "অনুরোধ" in t:
        return "/requests"
    if "ডিপোজিট" in t or "উইথড্র" in t or "ব্যালেন্স" in t or "কমিশন" in t:
        return "/history"
    return ""


def notif_badges():
    """{feature path: unread count} for the signed-in user; '*' = total unread. Each unread notification is counted exactly once."""
    if hasattr(g, "_nb"):
        return g._nb
    u, b = me(), {}
    if u and u["is_admin"]:
        f, pa = _alert_filter(u)
        rows = qa("SELECT a.link FROM admin_alerts a WHERE %s AND a.created>=? AND NOT EXISTS("
                  "SELECT 1 FROM admin_alert_reads r WHERE r.alert_id=a.id AND r.admin_id=?)" % f,
                  pa + [u["created"] or "", u["id"]])
        visible = {p for p, _, perm in ADMIN_TABS if perm is None or has_perm(perm, u)}
        for r in rows:
            k = _admin_badge_key(r["link"])
            if k not in visible:
                k = "/admin/alerts"
            b[k] = b.get(k, 0) + 1
        b["*"] = len(rows)
    elif u:
        rows = qa("SELECT link, title FROM notifications WHERE is_read=0 AND user_id=?", (u["id"],))
        for r in rows:
            k = _user_badge_key(r["link"], r["title"])
            b[k or "/account"] = b.get(k or "/account", 0) + 1
            if k in ("/referral", "/support", "/payment-numbers"):
                b["/account"] = b.get("/account", 0) + 1
        b["*"] = len(rows)
    g._nb = b
    return b


def nb(key):
    return notif_badges().get(key, 0)


def alerts_done(link):
    """A request/queue was handled: its admin alerts are closed for every staff member (DB read-state, no duplicates)."""
    db().execute("INSERT OR IGNORE INTO admin_alert_reads(alert_id,admin_id) SELECT a.id, u.id FROM admin_alerts a, users u "
                 "WHERE a.link=? AND u.is_admin=1", (link,))
    g.pop("_nb", None)


def notif_read_link(uid, link):
    """Marks this user's own unread notifications that point at `link` as read (database)."""
    db().execute("UPDATE notifications SET is_read=1 WHERE user_id=? AND is_read=0 AND link=?", (uid, link))
    g.pop("_nb", None)


def user_seen(match):
    """Marks the signed-in customer's OWN unread notifications read when match(link, title, created) is true."""
    u = me()
    if not u or u["is_admin"]:
        return 0
    rows = qa("SELECT id,link,title,created FROM notifications WHERE user_id=? AND is_read=0", (u["id"],))
    ids = [r["id"] for r in rows if match(r["link"] or "", r["title"] or "", str(r["created"] or ""))]
    for i in ids:
        db().execute("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=? AND is_read=0", (i, u["id"]))
    if ids:
        g.pop("_nb", None)
    return len(ids)


def alerts_seen(match):
    """Marks this staff member's OWN unread alerts as read (in the database) when match(link, created) is true.
    Called only after the items an alert refers to have actually been loaded on the page."""
    u = me()
    if not u or not u["is_admin"]:
        return 0
    f, pa = _alert_filter(u)  # only alerts this staff member is allowed to see
    rows = qa("SELECT a.id,a.link,a.created FROM admin_alerts a WHERE %s AND a.created>=? AND NOT EXISTS("
              "SELECT 1 FROM admin_alert_reads r WHERE r.alert_id=a.id AND r.admin_id=?)" % f,
              pa + [u["created"] or "", u["id"]])
    ids = [r["id"] for r in rows if match(r["link"] or "", str(r["created"] or ""))]
    for i in ids:
        db().execute("INSERT OR IGNORE INTO admin_alert_reads(alert_id,admin_id) VALUES(?,?)", (i, u["id"]))
    if ids:
        g.pop("_nb", None)  # badge counts are recomputed from the database
    return len(ids)


def _seen_list(key, rows, per, pg, until):
    """After a section's first list page was loaded: its alerts are read if the loaded rows cover them
    (all of them when the list is not full, otherwise only those at/after the oldest loaded row)."""
    if pg["p"] != 1:
        return
    cut = None if len(rows) < per else min(str(r["created"] or "") for r in rows)
    alerts_seen(lambda link, ts: _admin_badge_key(link) == key and ts < until and (cut is None or ts >= cut))


TILE_LABEL = {"/admin/alerts": "নোটিফিকেশন", "/admin/reports": "আর্থিক রিপোর্ট", "/admin/reconcile": "লেজার মিলানো",
              "/admin/staff": "স্টাফ ম্যানেজমেন্ট", "/admin/users": "ইউজার", "/admin/commission": "কমিশন", "/admin/pool": "কমিশন পুল"}


@app.route("/admin/menu")
@staff_required()
def admin_menu():
    u = me()
    tiles = {}
    for p, t, perm in ADMIN_TABS:
        if p != "/admin" and (perm is None or has_perm(perm, u)):
            tiles[p] = (p, TILE_LABEL.get(p, t.replace("🔔 ", "")), ADMIN_ICONS.get(p, "•"), "*" if p == "/admin/alerts" else p)
    if has_perm("settings", u):  # existing Settings > Security section (login lock, backups) keeps its own tile
        tiles["/admin/settings?open=security"] = ("/admin/settings?open=security", "নিরাপত্তা", "🔒", "")
    if has_perm("referrals", u):
        tiles["/admin/referral-rewards"] = ("/admin/referral-rewards", "রিওয়ার্ড সেটিংস", "🎁", "")
    if has_perm("requests", u):
        tiles["/admin/requests/new"] = ("/admin/requests/new", "রিকোয়েস্ট পাঠান", "➕", "")
    layout = [("", ["/admin/requests/new", "/admin/requests", "/admin/deposits", "/admin/withdrawals", "/admin/users", "/admin/alerts"]),
              ("💰 আর্থিক ও কমিশন", ["/admin/commission", "/admin/vip", "/admin/pool", "/admin/referrals", "/admin/referral-rewards", "/admin/reports", "/admin/reconcile"]),
              ("🎫 সাপোর্ট ও কনটেন্ট", ["/admin/tickets", "/admin/kyc", "/admin/notices", "/admin/content", "/admin/payment-numbers"]),
              ("⚙️ সিস্টেম ও নিরাপত্তা", ["/admin/staff", "/admin/settings", "/admin/settings?open=security", "/admin/audit", "/admin/profile"])]
    groups, used = [], set()
    for title, keys in layout:
        items = [tiles[k] for k in keys if k in tiles]
        used.update(k for k in keys if k in tiles)
        groups.append([title, items])
    groups[-1][1].extend(v for k, v in tiles.items() if k not in used)  # safety net: no feature can ever go missing
    return page("""<div class="cc-h">🎛 কন্ট্রোল সেন্টার</div><div class="cc-sub">যে ফিচারে নতুন নোটিফিকেশন আছে, তার বাটনে সংখ্যা দেখা যাবে।</div>
<div class="mg">{% for p,t,ic,bk in groups[0][1] %}<a class="mt" href="{{p}}"><i>{{ic}}</i><span class="lb">{{t}}</span>{% if bk %}
<span class="bd2" data-bd="{{bk}}"{% if not nb(bk) %} hidden{% endif %}>{{nb(bk)}}</span>{% endif %}</a>{% endfor %}</div>
{% for g in groups[1:] if g[1] %}<details class="card set cg"><summary>{{g[0]}} <span class="k">({{g[1]|length}})</span><span class="gdot"></span></summary>
<div><div class="mg">{% for p,t,ic,bk in g[1] %}<a class="mt" href="{{p}}"><i>{{ic}}</i><span class="lb">{{t}}</span>{% if bk %}
<span class="bd2" data-bd="{{bk}}"{% if not nb(bk) %} hidden{% endif %}>{{nb(bk)}}</span>{% endif %}</a>{% endfor %}</div></div></details>{% endfor %}""",
                active="/admin/menu", groups=groups)


@app.route("/api/notif")
@login_required
def api_notif():
    u = me()
    bd = notif_badges()  # one query: total unread + per-feature counts (each notification counted once)
    if u["is_admin"]:
        f, pa = _alert_filter(u)
        latest = q1("SELECT COALESCE(MAX(a.id),0) m FROM admin_alerts a WHERE %s AND a.created>=?" % f, pa + [u["created"] or ""])["m"]
    else:
        latest = q1("SELECT COALESCE(MAX(id),0) m FROM notifications WHERE user_id=?", (u["id"],))["m"]
    return jsonify(unread=bd.get("*", 0), latest=latest, badges=bd, uid=u["id"])


def _safe_link(link, admin):
    l = link or ""
    if admin:
        return l if l.startswith("/admin") else "/admin/alerts"
    return l if l.startswith("/") and not l.startswith("//") else "/notifications"


@app.route("/api/notif/new")
@login_required
def api_notif_new():
    """Read-only: the signed-in user's own notifications (staff: permitted alerts) newer than ?after=<id>, for native browser notifications."""
    u = me()
    after = request.args.get("after", type=int)
    if after is None or after < 0:
        abort(400)
    en = cur_lang() == "en"
    if u["is_admin"]:
        f, pa = _alert_filter(u)
        where, args = "%s AND a.created>=? AND a.id>?" % f, pa + [u["created"] or "", after]
        rows = qa("SELECT a.id,a.title,a.body,a.link FROM admin_alerts a WHERE %s ORDER BY a.id DESC LIMIT 5" % where, args)
        count = q1("SELECT COUNT(*) c FROM admin_alerts a WHERE %s" % where, args)["c"]
        items = [dict(id=r["id"], title=r["title"], body=r["body"], link=r["link"]) for r in rows]
    else:
        rows = qa("SELECT id,title,body,link,title_en,body_en FROM notifications WHERE user_id=? AND id>? ORDER BY id DESC LIMIT 5", (u["id"], after))
        count = q1("SELECT COUNT(*) c FROM notifications WHERE user_id=? AND id>?", (u["id"], after))["c"]
        items = [dict(id=r["id"], title=(r["title_en"] if en and r["title_en"] else r["title"]),
                      body=(r["body_en"] if en and r["body_en"] else r["body"]), link=r["link"]) for r in rows]
    out = [dict(id=i["id"], title=tr(i["title"] or "") if en else (i["title"] or ""), body=tr(i["body"] or "") if en else (i["body"] or ""),
                url=_safe_link(i["link"], bool(u["is_admin"]))) for i in reversed(items)]
    resp = jsonify(items=out, count=count, admin=bool(u["is_admin"]), site=(setting("site_name") or SITE)[:60])
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/notif/read", methods=["POST"])
@login_required
def api_notif_read():
    """Marks exactly ONE notification as read (own notification only) and returns fresh counts."""
    u = me()
    i = request.form.get("id", type=int)
    if not i:
        abort(400)
    if u["is_admin"]:
        f, pa = _alert_filter(u)  # only alerts this staff member is permitted to see
        if q1("SELECT 1 FROM admin_alerts a WHERE a.id=? AND %s AND a.created>=?" % f, [i] + pa + [u["created"] or ""]):
            db().execute("INSERT OR IGNORE INTO admin_alert_reads(alert_id,admin_id) VALUES(?,?)", (i, u["id"]))
    else:
        db().execute("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=? AND is_read=0", (i, u["id"]))
    g.pop("_nb", None)
    bd = notif_badges()
    return jsonify(unread=bd.get("*", 0), badges=bd)


@app.route("/admin/alerts")
@staff_required()
def admin_alerts():
    u = me()
    f, pa = _alert_filter(u)
    rows = qa("SELECT a.*, EXISTS(SELECT 1 FROM admin_alert_reads r WHERE r.alert_id=a.id AND r.admin_id=?) AS rd "
              "FROM admin_alerts a WHERE %s AND a.created>=? ORDER BY a.id DESC LIMIT 60" % f,
              [u["id"]] + pa + [u["created"] or ""])
    return page("""<div class="card"><h2>নোটিফিকেশন</h2><div class="row">
<form method="post" action="/admin/alerts/readall"><input type="hidden" name="_csrf" value="{{csrf_token}}"><button class="btn sm s" style="width:100%">✔ সব পঠিত করুন</button></form>
<button type="button" class="btn sm s" onclick="setSnd(!sndOn())">🔊 সাউন্ড: <span id="sndv"></span></button>
<button type="button" class="btn sm s" onclick="enableBrowserNotif()">📲 ব্রাউজার: <span id="bnv"></span></button></div></div>
{% if not rows %}<div class="card empty">কোনো নোটিফিকেশন নেই</div>{% endif %}
<div id="nlist" data-csrf="{{csrf_token}}">{% for a in rows %}<div class="card {{'' if a['rd'] else 'new'}}"{% if not a['rd'] %} data-nid="{{a['id']}}"{% endif %}><b>{{a['title']}}</b>{% if not a['rd'] %} <span class="pill pending">নতুন</span>{% endif %}
<div>{{a['body']}}</div><div class="k">{{a['created'][:16]}}</div>
<form method="post" action="/admin/alerts/{{a['id']}}/open" style="margin-top:8px"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<button class="btn sm">{{'খুলুন' if a['link'] else 'পঠিত করুন'}}</button></form></div>{% endfor %}</div>
<script>(function(){function go(){if(typeof autoRead==='function')autoRead();else setTimeout(go,50)}go()})()</script>""", active="/admin/alerts", rows=rows)


@app.route("/admin/alerts/readall", methods=["POST"])
@staff_required()
def admin_alerts_readall():
    u = me()
    f, pa = _alert_filter(u)
    db().execute("INSERT OR IGNORE INTO admin_alert_reads(alert_id,admin_id) SELECT a.id, ? FROM admin_alerts a WHERE %s AND a.created>=?" % f,
                 [u["id"]] + pa + [u["created"] or ""])
    return redirect("/admin/alerts")


@app.route("/admin/alerts/<int:i>/open", methods=["POST"])
@staff_required()
def admin_alert_open(i):
    u = me()
    a = q1("SELECT * FROM admin_alerts WHERE id=?", (i,))
    if not a:
        abort(404)
    db().execute("INSERT OR IGNORE INTO admin_alert_reads(alert_id,admin_id) VALUES(?,?)", (i, u["id"]))
    link = a["link"] or ""
    return redirect(link if link.startswith("/admin") else "/admin/alerts")


# ---------------------------------------------------------------- payment numbers (user)
ACCT_TYPES = ("Personal", "Agent", "Merchant")
ACCT_LABEL = {"Personal": "পার্সোনাল", "Agent": "এজেন্ট", "Merchant": "মার্চেন্ট"}
PHONE_RE = re.compile(r"01\d{9}")
PN_MAX = 12

PN_FORM = """<form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>মাধ্যম</label><select name="method">{% for m in methods %}<option value="{{m}}" {{'selected' if m==v.method}}>{{m}}</option>{% endfor %}</select>
<label>অ্যাকাউন্টের ধরন</label><select name="account_type">{% for t in types %}<option value="{{t}}" {{'selected' if t==v.account_type}}>{{tl[t]}} ({{t}})</option>{% endfor %}</select>
<label>মোবাইল নম্বর (১১ ডিজিট)</label><input name="number" inputmode="numeric" maxlength="11" required value="{{v.number}}">
<button style="width:100%">{{btn}}</button></form>"""


def pn_log(uid, pid, action, m, t, n, old=""):
    db().execute("INSERT INTO payment_number_log(user_id,pn_id,action,method,account_type,number,old,created) VALUES(?,?,?,?,?,?,?,?)",
                 (uid, pid, action, m, t, n, old, now()))


def _pn_input():
    m, t = request.form.get("method"), request.form.get("account_type")
    n = request.form.get("number", "").strip()
    if m not in METHODS or t not in ACCT_TYPES or not PHONE_RE.fullmatch(n):
        return None
    return m, t, n


@app.route("/payment-numbers", methods=["GET", "POST"])
@customer_required
def payment_numbers():
    u = me()
    if request.method == "POST":
        d = _pn_input()
        if not d:
            err("মাধ্যম, অ্যাকাউন্টের ধরন ও সঠিক ১১ ডিজিটের নম্বর দিন।"); return redirect("/payment-numbers")
        if rate_hit("pn:%d" % u["id"], 20, 3600):
            err("অনেক রিকোয়েস্ট হয়েছে, পরে চেষ্টা করুন।"); return redirect("/payment-numbers")
        m, t, n = d
        try:
            with atomic():
                if q1("SELECT COUNT(*) c FROM payment_numbers WHERE user_id=?", (u["id"],))["c"] >= PN_MAX:
                    raise OverflowError
                cur = db().execute("INSERT INTO payment_numbers(user_id,method,account_type,number,created,updated) VALUES(?,?,?,?,?,?)",
                                   (u["id"], m, t, n, now(), now()))
                pn_log(u["id"], cur.lastrowid, "add", m, t, n)
                audit("pn_add", "user#%d %s %s %s" % (u["id"], m, t, n))
        except INTEGRITY:
            err("এই মাধ্যমে এই নম্বরটি আগেই যোগ করা আছে।")
        except OverflowError:
            err("সর্বোচ্চ %d টি নম্বর যোগ করা যায়।" % PN_MAX)
        else:
            alert_admins("পেমেন্ট নম্বর যোগ", "#%s %s — %s (%s) %s" % (u["member_id"], u["name"], m, t, n),
                         "/admin/payment-numbers?q=" + u["member_id"], "payment_numbers")
            flash("নম্বর সংরক্ষিত হয়েছে।")
        return redirect("/payment-numbers")
    rows = qa("SELECT * FROM payment_numbers WHERE user_id=? ORDER BY id", (u["id"],))
    return page("""<div class="card"><h2>পেমেন্ট নম্বর ব্যবস্থাপনা</h2><p class="k">আপনার bKash, Nagad ও Rocket নম্বর এখানে জমা দিন ও সম্পাদনা করুন। অ্যাডমিন এগুলো দেখতে পাবেন।</p></div>
{% if not rows %}<div class="card empty">এখনো কোনো নম্বর যোগ করা হয়নি</div>{% endif %}
{% for r in rows %}<div class="card"><div class="row" style="align-items:center"><b>{{r['method']}}</b><span class="pill" style="flex:0">{{tl[r['account_type']]}}</span></div>
<div style="font-size:18px;margin:4px 0">{{r['number']}}</div><div class="k">যোগ: {{r['created'][:16]}}{% if r['updated']!=r['created'] %} · আপডেট: {{r['updated'][:16]}}{% endif %}</div>
<a class="btn sm s" href="/payment-numbers/{{r['id']}}/edit" style="margin-top:8px">✏️ সম্পাদনা</a></div>{% endfor %}
<div class="card"><h3>নতুন নম্বর যোগ করুন</h3>""" + PN_FORM + """</div>""",
                active="/account", rows=rows, tl=ACCT_LABEL, methods=METHODS, types=ACCT_TYPES, btn="যোগ করুন",
                v=dict(method="bKash", account_type="Personal", number=""))


@app.route("/payment-numbers/<int:i>/edit", methods=["GET", "POST"])
@customer_required
def payment_number_edit(i):
    u = me()
    r = q1("SELECT * FROM payment_numbers WHERE id=? AND user_id=?", (i, u["id"]))
    if not r:
        abort(404)
    if request.method == "POST":
        d = _pn_input()
        if not d:
            err("মাধ্যম, অ্যাকাউন্টের ধরন ও সঠিক ১১ ডিজিটের নম্বর দিন।"); return redirect("/payment-numbers/%d/edit" % i)
        m, t, n = d
        if (m, t, n) == (r["method"], r["account_type"], r["number"]):
            flash("কোনো পরিবর্তন নেই।"); return redirect("/payment-numbers")
        try:
            with atomic():
                db().execute("UPDATE payment_numbers SET method=?, account_type=?, number=?, updated=? WHERE id=? AND user_id=?",
                             (m, t, n, now(), i, u["id"]))
                pn_log(u["id"], i, "edit", m, t, n, "%s/%s/%s" % (r["method"], r["account_type"], r["number"]))
                audit("pn_edit", "user#%d pn#%d %s/%s/%s -> %s/%s/%s" % (u["id"], i, r["method"], r["account_type"], r["number"], m, t, n))
        except INTEGRITY:
            err("এই মাধ্যমে এই নম্বরটি আগেই যোগ করা আছে।"); return redirect("/payment-numbers/%d/edit" % i)
        alert_admins("পেমেন্ট নম্বর আপডেট", "#%s %s — %s (%s) %s" % (u["member_id"], u["name"], m, t, n),
                     "/admin/payment-numbers?q=" + u["member_id"], "payment_numbers")
        flash("নম্বর আপডেট হয়েছে।"); return redirect("/payment-numbers")
    return page("""<div class="card"><h2>নম্বর সম্পাদনা</h2>""" + PN_FORM + """<a class="btn s" href="/payment-numbers" style="width:100%;margin-top:10px">← ফিরে যান</a></div>""",
                active="/account", tl=ACCT_LABEL, methods=METHODS, types=ACCT_TYPES, btn="আপডেট করুন", v=dict(r))


@app.route("/admin/payment-numbers")
@staff_required("payment_numbers")
def admin_payment_numbers():
    q = request.args.get("q", "").strip().lstrip("#")[:40]
    m, t = request.args.get("method", ""), request.args.get("type", "")
    like = "%" + q + "%"
    where, args = ["u.is_admin=0"], []
    if q:
        where.append("(u.name LIKE ? OR u.phone LIKE ? OR u.member_id LIKE ? OR p.number LIKE ?)"); args += [like] * 4
    if m in METHODS:
        where.append("p.method=?"); args.append(m)
    if t in ACCT_TYPES:
        where.append("p.account_type=?"); args.append(t)
    pg = make_pg(q1("SELECT COUNT(*) n FROM payment_numbers p JOIN users u ON u.id=p.user_id WHERE %s" % " AND ".join(where), args)["n"], 30)
    rows = qa("SELECT p.*,u.name,u.phone,u.member_id FROM payment_numbers p JOIN users u ON u.id=p.user_id WHERE %s "
              "ORDER BY p.updated DESC LIMIT ? OFFSET ?" % " AND ".join(where), args + [30, pg["off"]])
    shown = {"/admin/payment-numbers?q=%s" % r["member_id"] for r in rows}
    alerts_seen(lambda link, ts: link in shown)
    logs = qa("SELECT l.*,u.name,u.member_id FROM payment_number_log l LEFT JOIN users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 20")
    return page("""<div class="card"><form><input name="q" value="{{q}}" placeholder="নাম / ফোন / মেম্বার আইডি / নম্বর">
<select name="method"><option value="">সব মাধ্যম</option>{% for x in methods %}<option {{'selected' if x==m}}>{{x}}</option>{% endfor %}</select>
<select name="type"><option value="">সব ধরন</option>{% for x in types %}<option value="{{x}}" {{'selected' if x==t}}>{{tl[x]}} ({{x}})</option>{% endfor %}</select>
<button style="width:100%">খুঁজুন</button></form></div>
{% if not rows %}<div class="card empty">কোনো নম্বর নেই</div>{% endif %}
{% for r in rows %}<div class="card"><div class="row" style="align-items:center"><b>{{r['method']}} · {{tl[r['account_type']]}}</b></div>
<div style="font-size:18px;margin:4px 0">{{r['number']}}</div>
<div class="k"><a href="/admin/users/{{r['user_id']}}">#{{r['member_id']}} {{r['name']}}</a> · {{r['phone']}}</div>
<div class="k">জমা: {{r['created'][:16]}} · আপডেট: {{r['updated'][:16]}}</div></div>{% endfor %}""" + PAGER + """
{% if logs %}<div class="card"><h3>সাম্প্রতিক পরিবর্তন</h3><div class="tw"><table>{% for l in logs %}<tr><td>{{(l['created'] or '')[:16]}}</td><td>#{{l['member_id']}} {{l['name']}}</td>
<td>{{l['action']}}</td><td>{{l['method']}}/{{l['account_type']}}/{{l['number']}}{% if l['old'] %} ← {{l['old']}}{% endif %}</td></tr>{% endfor %}</table></div></div>{% endif %}""",
                active="/admin/payment-numbers", rows=rows, logs=logs, q=q, m=m, t=t, tl=ACCT_LABEL, methods=METHODS, types=ACCT_TYPES, pg=pg)


# ---------------------------------------------------------------- Phase 2B: commission rates, Commission Pool, admin-initiated flows
from decimal import Decimal, ROUND_HALF_UP

COMM_RATE_CEILING = 10.0  # business rule: the commission rate can never exceed 10%
POOL_SOURCES = {"promo_budget": "প্রচারণা বাজেট (Promotional Budget)", "business_capital": "ব্যবসার পুঁজি (Business Capital)",
                "merchant_fee": "মার্চেন্ট ফি", "service_revenue": "সার্ভিস আয়"}
FLOW_LABEL = {"client_confirm": "ডিপোজিট রিকোয়েস্ট", "admin_review": "উইথড্র/পেমেন্ট রিকোয়েস্ট"}
OPEN_REQ = ("pending", "submitted", "review")


class PoolError(Exception):
    pass


def req_label(r):
    try:
        f = r["flow"]
    except (KeyError, IndexError):
        f = None
    if f in FLOW_LABEL:
        return FLOW_LABEL[f]
    return REQ_KIND.get(r["kind"], r["kind"])


def req_dtype(r):
    """Displayed request type: 'deposit' / 'withdraw'. For admin-created flow requests the type the admin chose (flow) decides
    (client_confirm = Deposit, admin_review = Withdrawal/payment); `kind` is only the wallet direction and is the opposite for them.
    Legacy requests without a flow use kind. Display only - never used for money movement."""
    try:
        f = r["flow"]
    except (KeyError, IndexError):
        f = None
    return {"client_confirm": "deposit", "admin_review": "withdraw"}.get(f or "", r["kind"])


def rate_cfg():
    """(default %, max %). The max can never exceed COMM_RATE_CEILING (10%)."""
    try:
        m = float(setting("comm_rate_max", "10"))
    except ValueError:
        m = COMM_RATE_CEILING
    try:
        d = float(setting("comm_rate_default", "5"))
    except ValueError:
        d = 5.0
    m = min(max(m, 0.0), COMM_RATE_CEILING)
    return min(max(d, 0.0), m), m


def effective_rate(u):
    d, m = rate_cfg()
    try:
        r = u["comm_rate"] if u is not None else None
    except (KeyError, IndexError):
        r = None
    r = d if r is None else float(r)
    try:
        vr = u["vip_rate"] if u is not None else None
    except (KeyError, IndexError):
        vr = None
    if vr:  # approved VIP level: permanent rate, never lowers an existing higher rate
        r = max(r, float(vr))
    return round(min(max(r, 0.0), m), 3)


@app.template_filter("pct")
def _pct(r):
    """5.0 -> '5', 7.5 -> '7.5' (no trailing zeros)."""
    t = ("%.3f" % float(r or 0)).rstrip("0").rstrip(".")
    return t or "0"


def commission_for(amount, rate):
    """Exact decimal math, half-up to 2 places (e.g. 333 x 5% = 16.65)."""
    return float((Decimal(str(amount)) * Decimal(str(rate)) / Decimal(100)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def pool_balance():
    r = q1("SELECT balance FROM pool_account WHERE id=1")
    return round(float(r["balance"]), 2) if r else 0.0


def pool_reserved(exclude=None):
    """Commission already promised in open admin-initiated requests (must stay fundable)."""
    sql = "SELECT COALESCE(SUM(commission),0) s FROM requests WHERE flow IN ('client_confirm','admin_review') AND status IN ('pending','submitted','review')"
    a = ()
    if exclude:
        sql += " AND id<>?"; a = (exclude,)
    return round(float(q1(sql, a)["s"]), 2)


def pool_available(exclude=None):
    return round(pool_balance() - pool_reserved(exclude), 2)


def _pool_apply(kind, amount, idem, user_id=None, ref_type=None, ref_id=None, ledger_idem=None, note="", actor=None,
                source_type=None, holding=None, reference=None, norm_ref=None, event_date=None):
    """The ONLY writer of pool_account/pool_ledger. Caller holds atomic(). Never lets the pool go below zero
    (checked here AND by CHECK(balance>=0) in the database). Returns False for a duplicate idempotency key."""
    amount = round(float(amount), 2)
    if not amount:
        raise PoolError("amount is zero")
    if q1("SELECT 1 FROM pool_ledger WHERE idem=?", (idem,)):
        return False
    n = "CAST(? AS NUMERIC)" if PG else "?"
    cur = db().execute("UPDATE pool_account SET balance=round(balance+%s,2), updated=? WHERE id=1 AND round(balance+%s,2)>=0" % (n, n),
                       (amount, now(), amount))
    if cur.rowcount != 1:
        raise PoolError("কমিশন পুলে পর্যাপ্ত ফান্ড নেই (উপলব্ধ ৳%s)" % money(pool_balance()))
    a = actor if isinstance(actor, str) or actor is None else actor
    who = a if isinstance(a, str) else (a["member_id"] if a else "system")
    db().execute("INSERT INTO pool_ledger(kind,amount,source_type,holding_account,reference,norm_ref,event_date,user_id,ref_type,ref_id,"
                 "ledger_idem,idem,balance_after,note,actor,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 (kind, amount, source_type, holding, reference, norm_ref, event_date, user_id, ref_type, ref_id, ledger_idem, idem,
                  pool_balance(), (note or "")[:300], who, now()))
    return True


def pool_pay(user_id, ledger_kind, amount, idem, ref_type, ref_id, note, actor, own_req=None):
    """Atomic: pool -amount AND user +amount (one transaction). Fails -> nothing changes. Never uses unbacked money."""
    amount = round(float(amount), 2)
    if amount <= 0:
        raise PoolError("invalid amount")
    if q1("SELECT 1 FROM pool_ledger WHERE idem=?", ("pool:" + idem,)):
        return False
    avail = pool_available(exclude=own_req)
    if avail + 0.004 < amount:
        raise PoolError("কমিশন পুলে পর্যাপ্ত ফান্ড নেই (উপলব্ধ ৳%s, দরকার ৳%s)" % (money(max(avail, 0)), money(amount)))
    _pool_apply("payout", -amount, "pool:" + idem, user_id, ref_type, ref_id, idem, note, actor)
    if not post(user_id, ledger_kind, amount, idem, ref_type, ref_id, note, actor if isinstance(actor, str) else (actor["member_id"] if actor else "system")):
        raise PoolError("duplicate ledger entry")
    return True


def pool_return(user_id, amount, idem, ref_type, ref_id, note, actor):
    """Commission reversal: user -amount (cannot go negative) AND pool +amount."""
    amount = round(float(amount), 2)
    if amount <= 0:
        raise PoolError("invalid amount")
    if q1("SELECT 1 FROM pool_ledger WHERE idem=?", ("pool:" + idem,)):
        return False
    if not post(user_id, "commission_reversal", -amount, idem, ref_type, ref_id, note, actor):
        raise PoolError("duplicate ledger entry")
    _pool_apply("reversal", amount, "pool:" + idem, user_id, ref_type, ref_id, idem, note, actor)
    return True


def company_post(kind, amount, idem, user_id, ref_type, ref_id, note, actor):
    """Counter-entry (other side) of a client payment: principal received by the company. Idempotent, immutable."""
    if q1("SELECT 1 FROM company_ledger WHERE idem=?", (idem,)):
        return False
    db().execute("INSERT INTO company_ledger(kind,amount,user_id,ref_type,ref_id,idem,note,actor,created) VALUES(?,?,?,?,?,?,?,?,?)",
                 (kind, round(float(amount), 2), user_id, ref_type, ref_id, idem, (note or "")[:300], actor, now()))
    return True

REQ_TYPES = {"client_confirm": ("withdraw", "client_confirm"), "admin_review": ("deposit", "admin_review"),
             "deposit": ("deposit", None), "withdraw": ("withdraw", None)}


# Purpose is optional: when the admin leaves it empty a neutral default label is used (existing records are never rewritten).
PURPOSE_DEFAULT = {"client_confirm": ("ডিপোজিট রিকোয়েস্ট", "Deposit request"),
                   "admin_review": ("উইথড্র/পেমেন্ট রিকোয়েস্ট", "Withdrawal / payment request")}


def default_purpose(flow, lang="bn"):
    d = PURPOSE_DEFAULT.get(flow)
    return d[1 if lang == "en" else 0] if d else ""


RD_STYLE = """<style>
.rd .card{padding:10px 12px;margin-bottom:8px;border-radius:12px}
.rd h2{margin:0;font-size:15px;line-height:1.3;font-weight:700}
.rd h3{margin:0 0 6px;font-size:13.5px;line-height:1.3}
.rd .k{font-size:12px}
.rd .rq-amt{font-size:18px;font-weight:700;line-height:1.3;margin:4px 0 2px;color:var(--tx)}
.rd .rq-dl{margin:4px 0 0}
.rd .rq-dl>div{display:flex;gap:10px;justify-content:space-between;align-items:flex-start;padding:5px 0;border-top:1px solid var(--ln)}
.rd .rq-dl dt{flex:0 0 36%;margin:0;color:var(--mut);font-size:12px;line-height:1.5}
.rd .rq-dl dd{margin:0;flex:1;min-width:0;text-align:right;font-size:13px;line-height:1.5;overflow-wrap:anywhere}
.rd .hl{font-size:12.5px;line-height:1.5}
.rd .tw table td,.rd .tw table th{font-size:12.5px;padding:5px 6px}
.rd .btn{font-size:13px;padding:8px 12px}.rd .btn.sm{font-size:12px;padding:5px 10px}
.rd .pill{font-size:11px;padding:2px 9px}
.rd .msg{font-size:12.5px;padding:8px 10px}
</style>"""


def _confirm_view(r, u):
    lang = cur_lang()
    pur = (r["purpose_en"] if lang == "en" and r["purpose_en"] else r["purpose"]) or default_purpose(r["flow"], lang)
    principal, com = round(float(r["amount"]), 2), round(float(r["commission"] or 0), 2)
    bal = round(float(u["balance"]), 2)
    return page(RD_STYLE + """<div class="rd"><div class="card"><div class="row" style="align-items:center;justify-content:space-between"><h2>ডিপোজিট রিকোয়েস্ট</h2>
<span class="pill {{r['status']}}" style="flex:0;white-space:nowrap">{{labels[r['status']]}}</span></div>
<div class="rq-amt">৳ {{money(principal)}}</div>
<dl class="rq-dl">
<div><dt>Order ID</dt><dd><b style="user-select:all">{{r['order_id']}}</b></dd></div>
<div><dt>ধরন</dt><dd>ডিপোজিট</dd></div>
<div><dt>উদ্দেশ্য (Purpose)</dt><dd style="white-space:pre-line">{{pur}}</dd></div>
{% if r['instructions'] %}<div><dt>নির্দেশনা</dt><dd style="white-space:pre-line">{{r['instructions']}}</dd></div>{% endif %}
{% if r['expires_at'] and r['status']=='pending' %}<div><dt>⏳ মেয়াদ</dt><dd>{{r['expires_at'][:16]}} (UTC)</dd></div>{% endif %}</dl>
<div class="tw" style="margin-top:8px"><table>
<tr><td>মূল পরিমাণ (আপনার ওয়ালেট থেকে কাটা হবে)</td><td><b>− ৳ {{money(principal)}}</b></td></tr>
<tr><td>কমিশন ({{'%g'|format(r['commission_rate'] or 0)}}%) — কোম্পানির প্রচারণা পুল থেকে যুক্ত হবে</td><td><b>+ ৳ {{money(com)}}</b></td></tr>
<tr><td>নিট ওয়ালেট পরিবর্তন</td><td><b>− ৳ {{money(principal-com)}}</b></td></tr>
<tr><td>বর্তমান ব্যালেন্স</td><td>৳ {{money(bal)}}</td></tr>
<tr><td>অনুমোদনের পর ব্যালেন্স</td><td>৳ {{money(bal-principal+com)}}</td></tr></table></div>
<div class="k" style="margin-top:8px">অনুমোদন করলে সঙ্গে সঙ্গে সম্পন্ন হবে; আর কোনো অ্যাডমিন অনুমোদন লাগবে না। বাতিল করলে আপনার ব্যালেন্স অপরিবর্তিত থাকবে।</div></div>
{% if r['status']=='pending' %}<div class="card">{% if bal < principal %}<div class="msg error">আপনার ব্যালেন্স এই অনুরোধের জন্য পর্যাপ্ত নয়।</div>{% endif %}
<form method="post" action="/requests/{{r['id']}}/decide" data-confirm="উদ্দেশ্য, মূল পরিমাণ ও কমিশন দেখে নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<div class="row"><button name="act" value="approve" class="btn g" {{'disabled' if bal < principal}}>✅ অনুমোদন করুন</button><button name="act" value="reject" class="btn r">❌ বাতিল করুন</button></div></form></div>{% endif %}
<a class="btn s" href="/requests" style="width:100%">← সব অনুরোধ</a></div>""", active="/requests", r=r, pur=pur, principal=principal, com=com, bal=bal, labels=REQ_LABEL)


# ---------------------------------------------------------------- manual requests (admin -> user)
REQ_LABEL = {"pending": "অপেক্ষমাণ", "submitted": "জমা হয়েছে", "review": "যাচাইয়ে", "approved": "অনুমোদিত",
             "rejected": "রিজেক্ট", "expired": "মেয়াদোত্তীর্ণ", "cancelled": "বাতিল"}
REQ_KIND = {"deposit": "ডিপোজিট", "withdraw": "উইথড্র"}
REQ_ALLOWED = {"review": ("submitted",), "approve": ("submitted", "review"), "reject": ("submitted", "review"),
               "cancel": ("pending", "submitted", "review")}
REQ_NEW = {"review": "review", "approve": "approved", "reject": "rejected", "cancel": "cancelled"}


class ReqError(Exception):
    pass


def req_log(rid, action, frm, to, actor, actor_id, note=""):
    db().execute("INSERT INTO request_log(request_id,action,from_status,to_status,actor,actor_id,note,created) VALUES(?,?,?,?,?,?,?,?)",
                 (rid, action, frm, to, actor, actor_id, (note or "")[:300], now()))


# ---------------------------------------------------------------- v7: withdrawal payment details, user cancellation fee, extra commission, admin warnings
REQ_CANCEL_FEE_DEFAULT = 100.0   # fallback only: the live value is the ONE central setting `req_cancel_fee` (Admin -> Settings -> Withdraw)
PAY_TYPE_LABEL = {"personal": "Personal: Send Money", "agent": "Agent: Cash Out", "merchant": "Merchant: Payment"}
PAY_TYPES = tuple(PAY_TYPE_LABEL)
EXTRA_COMM_TYPES = ("agent",)    # Extra Commission is allowed ONLY for Agent Cash Out (enforced on the server, never only in the UI)
EXTRA_RE = re.compile(r"[0-9]{1,8}(\.[0-9]{1,2})?")


def is_wd(kind, flow=None):
    """Admin-created *withdrawal* request = the user is shown a payment number to pay: the 'withdraw/payment' flow and the plain withdraw type.
    For these the admin must type the provider / number / type; the user's saved payment numbers are never used."""
    return flow == "admin_review" or (not flow and kind == "withdraw")


def xc_ok(r):
    """Display helper: may the approve dialog offer the optional Extra Commission field? (the server re-checks everything)"""
    try:
        return r["flow"] == "admin_review" and (r["pay_type"] or "") in EXTRA_COMM_TYPES and r["status"] in ("submitted", "review")
    except (KeyError, IndexError):
        return False


def cancel_fee():
    """The user-side cancellation fee (central setting; falls back to the default if missing or invalid)."""
    v = parse_amount(setting("req_cancel_fee", ""))
    return v if v > 0 else REQ_CANCEL_FEE_DEFAULT


def user_can_cancel(r):
    """A customer may cancel only an admin-created withdrawal request that is still waiting for their payment (nothing submitted yet)."""
    return is_wd(r["kind"], r["flow"]) and r["status"] == "pending"


def parse_extra(v):
    """Extra commission input: blank -> 0; otherwise a plain positive number with up to 2 decimals (no sign, exponent, NaN or Infinity)."""
    v = (v or "").replace(",", "").strip()
    if not v:
        return 0.0
    if not EXTRA_RE.fullmatch(v):
        raise ReqError("এক্সট্রা কমিশনের পরিমাণ সঠিক নয় (শুধু ০ বা ধনাত্মক সংখ্যা, সর্বোচ্চ ২ দশমিক)।")
    return round(float(v), 2)


def warnings_for(uid, rid=None, limit=5):
    """Admin warnings visible to the customer: those attached to this request plus user-level ones (or all of the user's when rid is None)."""
    if rid:
        return qa("SELECT * FROM user_warnings WHERE user_id=? AND (request_id=? OR request_id IS NULL) ORDER BY id DESC LIMIT ?", (uid, rid, limit))
    return qa("SELECT * FROM user_warnings WHERE user_id=? ORDER BY id DESC LIMIT ?", (uid, limit))


WARN_TPL = """{% if warns %}<div class="card" style="border-left:4px solid #d97706"><h3 style="margin:0 0 8px">⚠ অ্যাডমিনের সতর্কবার্তা</h3>{% for w in warns %}<div style="white-space:pre-line;overflow-wrap:anywhere;margin-bottom:8px">{{w['message']}}<div class="k">{{w['created'][:16]}}</div></div>{% endfor %}</div>{% endif %}"""


def expire_requests():
    """Lazily moves overdue, not-yet-submitted requests to 'expired' (no balance effect). Call outside atomic()."""
    t = now()
    rows = qa("SELECT id,user_id,order_id FROM requests WHERE status='pending' AND expires_at IS NOT NULL AND expires_at<=?", (t,))
    if not rows:
        return
    with atomic():
        for r in rows:
            cur = db().execute("UPDATE requests SET status='expired', updated=? WHERE id=? AND status='pending'", (t, r["id"]))
            if cur.rowcount == 1:
                req_log(r["id"], "expire", "pending", "expired", "system", None, "")
                notif_read_link(r["user_id"], "/requests/%d" % r["id"])
                notify(r["user_id"], "অনুরোধের মেয়াদ শেষ", "Order %s এর মেয়াদ শেষ হয়েছে।" % r["order_id"], "/requests/%d" % r["id"])


def _rm_upload(name):
    if name:
        store_delete(name)


# ---- user side
@app.route("/requests")
@customer_required
def requests_list():
    u = me()
    expire_requests()
    rows = qa("SELECT * FROM requests WHERE user_id=? ORDER BY (status='pending') DESC, id DESC LIMIT 100", (u["id"],))
    shown = {"/requests/%d" % r["id"] for r in rows}
    user_seen(lambda link, title, ts: link in shown)
    cnt = {"all": len(rows), "pending": sum(1 for r in rows if r["status"] in OPEN_REQ),
           "success": sum(1 for r in rows if r["status"] == "approved")}
    return page(WARN_TPL + """<style>
.ur-f{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:0 0 12px}
.ur-f button{display:flex;align-items:center;justify-content:center;gap:6px;width:100%;height:42px;margin:0;padding:0 8px;border-radius:12px;border:1.5px solid var(--ln);background:var(--card);background-image:none;box-shadow:none;color:var(--mut);font-weight:700;font-size:14px;touch-action:manipulation;-webkit-tap-highlight-color:transparent}
.ur-f button i{font-style:normal;font-size:12px;min-width:20px;padding:1px 6px;border-radius:99px;background:var(--bg)}
.ur-f button.on{color:#fff;border-color:#1E90FF;background:#1E90FF}
.ur-f button.on[data-f=pending]{border-color:#d97706;background:#d97706}
.ur-f button.on[data-f=success]{border-color:#0EA371;background:#0EA371}
.ur-f button.on i{background:#ffffff33;color:#fff}
.ur-card{display:block;background:var(--card);border:1px solid var(--ln);border-radius:14px;padding:12px 14px;margin-bottom:10px;color:var(--tx);text-decoration:none}
.ur-card[hidden]{display:none}
.ur-card[data-g=pending]{border-left:2px solid #fbbf24}.ur-card[data-s=rejected]{border-left:2px solid #fca5a5}
.ur-h{padding:10px 14px;margin-bottom:10px}.ur-h h2{margin:0 0 2px;font-size:18px;line-height:1.25}.ur-h p{margin:0;font-size:12.5px;line-height:1.4}
.ur-top{display:flex;justify-content:space-between;align-items:center;gap:10px}
.ur-ty{font-size:13.5px;font-weight:600;color:var(--mut);min-width:0}
.ur-am{font-size:21px;font-weight:800;margin:5px 0 8px;line-height:1.2}
.ur-meta{display:flex;flex-wrap:wrap;gap:3px 14px;font-size:12.5px;color:var(--mut)}
.ur-meta b{color:var(--tx);font-weight:600}
.ur-b{display:inline-flex;align-items:center;gap:5px;flex:none;padding:3px 10px;border-radius:99px;font-size:12px;font-weight:700;white-space:nowrap;background:#E8F3F4;color:#456170}
.ur-b::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.ur-b.pending,.ur-b.review{background:#fef3c7;color:#b45309}.ur-b.submitted{background:#DCEEFF;color:var(--bt)}
.ur-b.approved{background:#DDF8EC;color:#0B7A50}.ur-b.rejected{background:#FFE4E6;color:#b91c1c}
.ur-b.expired,.ur-b.cancelled{background:#E8F3F4;color:#5A7587}
</style>
<div class="card ur-h"><h2>অনুরোধ</h2><p class="k">অ্যাডমিনের পাঠানো ডিপোজিট/উইথড্র অনুরোধ এখানে দেখা যায়।</p></div>
{% if not rows %}<div class="card empty">কোনো অনুরোধ নেই</div>{% else %}
<div class="ur-f" id="urf"><button type="button" data-f="all" class="on" aria-pressed="true">{{'All' if lang=='en' else 'সব'}} <i>{{cnt.all}}</i></button>
<button type="button" data-f="pending" aria-pressed="false">{{'Pending' if lang=='en' else 'অপেক্ষমাণ'}} <i>{{cnt.pending}}</i></button>
<button type="button" data-f="success" aria-pressed="false">{{'Success' if lang=='en' else 'সফল'}} <i>{{cnt.success}}</i></button></div>
<div class="card empty" id="urn" hidden>কোনো অনুরোধ নেই</div>
{% for r in rows %}<a class="ur-card" data-s="{{r['status']}}" data-g="{{'success' if r['status']=='approved' else ('pending' if r['status'] in ('pending','submitted','review') else 'other')}}" href="/requests/{{r['id']}}">
<div class="ur-top"><span class="ur-ty">{{rk(r)}}</span><span class="ur-b {{r['status']}}">{{labels[r['status']]}}</span></div>
<div class="ur-am">৳ {{money(r['amount'])}}</div>
<div class="ur-meta"><span>Order: <b>{{r['order_id']}}</b></span><span>{{r['method']}}</span><span>{{r['created'][:16]}}</span></div></a>{% endfor %}
<script>(function(){var bar=document.getElementById('urf');if(!bar)return;var cards=document.querySelectorAll('.ur-card'),none=document.getElementById('urn');
bar.addEventListener('click',function(e){var b=e.target.closest('button[data-f]');if(!b)return;var f=b.getAttribute('data-f'),n=0;
bar.querySelectorAll('button').forEach(function(x){var on=x===b;x.classList.toggle('on',on);x.setAttribute('aria-pressed',on?'true':'false')});
cards.forEach(function(c){var show=f==='all'||c.getAttribute('data-g')===f;c.hidden=!show;if(show)n++});none.hidden=n>0})})()</script>{% endif %}""",
                active="/requests", rows=rows, kinds=REQ_KIND, labels=REQ_LABEL, cnt=cnt, warns=warnings_for(u["id"]))


@app.route("/requests/<int:i>", methods=["GET", "POST"])
@customer_required
def request_view(i):
    u = me()
    expire_requests()
    r = q1("SELECT * FROM requests WHERE id=? AND user_id=?", (i, u["id"]))
    if not r:
        abort(404)
    notif_read_link(u["id"], "/requests/%d" % i)  # the customer opened this request
    if r["flow"] == "client_confirm":
        if request.method == "POST":
            abort(400)  # decisions go through /requests/<id>/decide only
        return _confirm_view(r, u)
    if request.method == "POST":
        back_to = "/requests/%d" % i
        if r["status"] != "pending":
            err("এই অনুরোধে এখন আর জমা দেওয়া যাবে না।"); return redirect(back_to)
        trx = request.form.get("trx", "").strip()[:40]
        nt = norm_trx(trx)
        if len(nt) < 6:
            err("কমপক্ষে ৬ অক্ষরের সঠিক TrxID দিন।"); return redirect(back_to)
        if rate_hit("rq:%d" % u["id"], 10, 3600):
            err("অনেক রিকোয়েস্ট হয়েছে, পরে চেষ্টা করুন।"); return redirect(back_to)
        shot_name, e = save_shot(request.files.get("shot"))
        if e:
            err(e); return redirect(back_to)
        if not shot_name:
            err("ট্রানজেকশনের স্ক্রিনশট আপলোড করুন।"); return redirect(back_to)
        try:
            with atomic():
                if q1("SELECT 1 FROM tx WHERE kind='deposit' AND norm_trx=?", (nt,)) or \
                        q1("SELECT 1 FROM requests WHERE norm_trx=? AND id<>?", (nt, i)):
                    raise ReqError("এই TrxID আগেই ব্যবহার করা হয়েছে।")
                t = now()
                cur = db().execute("UPDATE requests SET status='submitted', trx=?, norm_trx=?, screenshot=?, submitted_at=?, updated=? "
                                   "WHERE id=? AND user_id=? AND status='pending' AND (expires_at IS NULL OR expires_at>?)",
                                   (trx, nt, shot_name, t, t, i, u["id"], t))
                if cur.rowcount != 1:
                    raise ReqError("অনুরোধটির মেয়াদ শেষ হয়েছে বা আগেই জমা হয়েছে।")
                req_log(i, "submit", "pending", "submitted", u["member_id"], u["id"], "trx=%s" % nt)
                audit("req_submit", "req#%d order=%s user#%d trx=%s" % (i, r["order_id"], u["id"], nt))
        except (ReqError,) + INTEGRITY as ex:
            _rm_upload(shot_name)
            err(str(ex) if isinstance(ex, ReqError) else "এই TrxID আগেই ব্যবহার করা হয়েছে।"); return redirect(back_to)
        except Exception:
            _rm_upload(shot_name)
            raise
        alert_admins("অনুরোধ জমা", "#%s %s — Order %s (%s ৳%s)" % (u["member_id"], u["name"], r["order_id"], REQ_KIND[req_dtype(r)], money(r["amount"])),
                     "/admin/requests/%d" % i, "requests")
        alert_admins("ট্রানজেকশন স্ক্রিনশট আপলোড", "#%s Order %s" % (u["member_id"], r["order_id"]), "/admin/requests/%d" % i, "requests")
        flash("জমা হয়েছে। অ্যাডমিন যাচাই করবেন।"); return redirect(back_to)
    return page(RD_STYLE + '<div class="rd">' + WARN_TPL + """<div class="card"><div class="row" style="align-items:center;justify-content:space-between"><h2>{{rk(r)}}</h2>
<span class="pill {{r['status']}}" style="flex:0;white-space:nowrap">{{labels[r['status']]}}</span></div>
<div class="rq-amt">৳ {{money(r['amount'])}}</div>
<dl class="rq-dl">
<div><dt>Order ID</dt><dd><b style="user-select:all">{{r['order_id']}}</b></dd></div>
<div><dt>ধরন</dt><dd>{{kinds[rdt(r)]}}</dd></div>
<div><dt>পেমেন্ট প্রোভাইডার</dt><dd>{{r['method']}}</dd></div>
<div><dt>পেমেন্ট নম্বর</dt><dd><b style="user-select:all">{{r['pay_number']}}</b> <button type="button" class="btn sm" style="flex:0" data-copy="{{r['pay_number']}}">📋 কপি</button></dd></div>
{% if r['pay_type'] %}<div><dt>পেমেন্ট টাইপ</dt><dd>{{ptl.get(r['pay_type'], r['pay_type'])}}</dd></div>{% endif %}
{% if r['expires_at'] and r['status']=='pending' %}<div><dt>⏳ মেয়াদ</dt><dd>{{r['expires_at'][:16]}} (UTC)</dd></div>{% endif %}</dl>
{% if r['instructions'] %}<div class="k" style="margin-top:8px">অ্যাডমিনের নির্দেশনা</div><div class="hl" style="white-space:pre-line">{{r['instructions']}}</div>{% endif %}
{% if r['pay_type'] and r['status']=='pending' %}<div class="hl" style="margin-top:8px"><b>কীভাবে পেমেন্ট করবেন</b><br>
{% if r['pay_type']=='personal' %}আপনার {{r['method']}} অ্যাপ/মেনু থেকে <b>Send Money</b> বেছে নিন এবং উপরের নম্বরে ঠিক <b>৳{{money(r['amount'])}}</b> পাঠান।
{% elif r['pay_type']=='agent' %}আপনার {{r['method']}} অ্যাপ/মেনু থেকে <b>Cash Out</b> বেছে নিন, এজেন্ট নম্বর হিসেবে উপরের নম্বর দিন এবং ঠিক <b>৳{{money(r['amount'])}}</b> Cash Out করুন।
{% else %}আপনার {{r['method']}} অ্যাপ/মেনু থেকে <b>Payment</b> বেছে নিন, মার্চেন্ট নম্বর হিসেবে উপরের নম্বর দিন এবং ঠিক <b>৳{{money(r['amount'])}}</b> পেমেন্ট করুন।{% endif %}
<br>পেমেন্ট শেষে নিচের ফর্মে TrxID ও স্ক্রিনশট জমা দিন।</div>{% endif %}
{% if r['flow']=='admin_review' and r['commission'] and r['status']!='approved' %}<div class="hl" style="margin-top:8px">🎁 কমিশন ({{'%g'|format(r['commission_rate'] or 0)}}%): ৳{{money(r['commission'])}} — কোম্পানির প্রচারণা পুল থেকে। অনুমোদনের পর মোট ৳{{money(r['amount']+r['commission'])}} ওয়ালেটে যুক্ত হবে (মূল ৳{{money(r['amount'])}} + কমিশন ৳{{money(r['commission'])}})।</div>{% endif %}
{% if r['flow']=='admin_review' and r['status']=='approved' %}<div class="k" style="margin-top:10px"><b>ওয়ালেটে যুক্ত হয়েছে</b></div><div class="tw"><table>
<tr><td>মূল পরিমাণ</td><td><b>+ ৳ {{money(r['amount'])}}</b></td></tr>
{% if r['commission'] %}<tr><td>কমিশন ({{'%g'|format(r['commission_rate'] or 0)}}%)</td><td><b>+ ৳ {{money(r['commission'])}}</b></td></tr>{% endif %}
{% if r['extra_commission'] %}<tr><td>এক্সট্রা কমিশন</td><td><b>+ ৳ {{money(r['extra_commission'])}}</b></td></tr>{% endif %}
<tr><td>মোট ওয়ালেটে যুক্ত</td><td><b>+ ৳ {{money((r['amount'] or 0)+(r['commission'] or 0)+(r['extra_commission'] or 0))}}</b></td></tr></table></div>{% endif %}
<div class="k" style="margin-top:8px">{% if r['kind']=='deposit' %}অ্যাডমিন অনুমোদন করলে ৳{{money(r['amount'])}} আপনার ওয়ালেটে যুক্ত হবে।
{% else %}অ্যাডমিন অনুমোদন করলে ৳{{money(r['amount'])}} আপনার ওয়ালেট থেকে কাটা হবে।{% endif %} জমা দিলে ব্যালেন্স নিজে থেকে বদলায় না।</div></div>
{% if r['status']=='pending' %}<div class="card"><h3>পেমেন্টের তথ্য জমা দিন</h3>
<form method="post" enctype="multipart/form-data" data-confirm="তথ্য ঠিক আছে? জমা দেবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>Transaction ID (TrxID)</label><input name="trx" required autocomplete="off" maxlength="40">
<label>ট্রানজেকশনের স্ক্রিনশট (JPG/PNG/WEBP, ≤২MB)</label><input type="file" name="shot" accept="image/*" required>
<button style="width:100%">যাচাইয়ের জন্য জমা দিন</button></form></div>
{% elif r['trx'] %}<div class="card"><h3>আপনার জমা দেওয়া তথ্য</h3><div>TrxID: <b>{{r['trx']}}</b></div><div class="k">জমা: {{(r['submitted_at'] or '')[:16]}}</div>
{% if r['screenshot'] %}<a href="/shot/{{r['screenshot']}}" target="_blank"><img class="shot" src="/shot/{{r['screenshot']}}" alt="screenshot"></a>{% endif %}</div>{% endif %}
{% if can_cancel %}<div class="card"><h3 style="margin-top:0">অনুরোধ বাতিল</h3><div class="k">পেমেন্ট করতে না চাইলে এই অনুরোধ বাতিল করতে পারেন। বাতিল করলে আপনার ওয়ালেট থেকে <b>৳{{money(fee)}}</b> ফি কাটা হবে (পরের ধাপে নিশ্চিত করতে হবে)।</div>
<a class="btn r" href="/requests/{{r['id']}}/cancel" style="width:100%;margin-top:8px">🚫 অনুরোধ বাতিল করুন</a></div>{% endif %}
{% if r['status']=='cancelled' and r['cancel_by']=='user' %}<div class="card"><b>আপনি এই অনুরোধ বাতিল করেছেন</b><div class="k">বাতিল ফি ৳{{money(r['cancel_fee'] or 0)}} কাটা হয়েছে।</div></div>{% endif %}
{% if r['status']=='rejected' and r['reject_reason'] %}<div class="card"><b>রিজেক্টের কারণ</b><div>{{r['reject_reason']}}</div></div>{% endif %}
<a class="btn s" href="/requests" style="width:100%">← সব অনুরোধ</a></div>""", active="/requests", r=r, kinds=REQ_KIND, labels=REQ_LABEL, warns=warnings_for(u["id"], i), can_cancel=user_can_cancel(r), fee=cancel_fee())


@app.route("/requests/<int:i>/cancel", methods=["GET", "POST"])
@customer_required
def request_cancel(i):
    """Customer cancels an eligible admin-created withdrawal request. The cancellation fee (central setting) is a separate ledger entry written in the
    SAME transaction as the status change, exactly once (status guard + unique ledger key); a balance that cannot cover it blocks the cancellation."""
    u = me()
    expire_requests()
    back_to = "/requests/%d" % i
    r = q1("SELECT * FROM requests WHERE id=? AND user_id=?", (i, u["id"]))
    if not r:
        abort(404)
    if not user_can_cancel(r):
        err("এই অনুরোধটি এখন আর বাতিল করা যাবে না।"); return redirect(back_to)
    if request.method == "POST":
        if rate_hit("rqx:%d" % u["id"], 10, 3600):
            err("অনেকবার চেষ্টা হয়েছে, পরে চেষ্টা করুন।"); return redirect(back_to)
        alert = None
        try:
            with atomic():
                c = q1("SELECT * FROM requests WHERE id=? AND user_id=?", (i, u["id"]))
                if not c or not user_can_cancel(c):
                    raise ReqError("এই অনুরোধটি আর বাতিল করা যাবে না (হয়তো আগেই জমা, বাতিল বা মেয়াদোত্তীর্ণ হয়েছে)।")
                cu = q1("SELECT blocked,balance FROM users WHERE id=?", (u["id"],))
                if not cu or cu["blocked"]:
                    raise ReqError("আপনার অ্যাকাউন্ট সক্রিয় নয়।")
                fee = cancel_fee()
                bal = round(float(cu["balance"]), 2)
                if round(bal - fee, 2) < 0:
                    raise ReqError("বাতিল করতে ৳%s ফি লাগবে, কিন্তু আপনার ব্যালেন্স ৳%s। অনুরোধ বাতিল হয়নি, কিছুই কাটা হয়নি।" % (money(fee), money(bal)))
                t = now()
                cur = db().execute("UPDATE requests SET status='cancelled', updated=?, decided_by_id=?, decided_by=?, decided_at=?, reject_reason=?, cancel_fee=?, cancel_by='user' "
                                   "WHERE id=? AND user_id=? AND status='pending'", (t, u["id"], u["member_id"], t, "ইউজার নিজে বাতিল করেছেন", fee, i, u["id"]))
                if cur.rowcount != 1:
                    raise ReqError("এই অনুরোধ আগেই প্রক্রিয়া হয়েছে।")
                if not post(u["id"], "request_cancel_fee", -fee, "req:%d:cancelfee" % i, "request", i, "Order %s cancellation fee" % c["order_id"], u["member_id"]):
                    raise ReqError("এই অনুরোধের বাতিল ফি আগেই কাটা হয়েছে।")
                req_log(i, "cancel", "pending", "cancelled", u["member_id"], u["id"], "ইউজার বাতিল করেছেন · ফি ৳%s" % money(fee))
                audit("req_user_cancel", "req#%d order=%s user#%d fee=৳%s at=%s" % (i, c["order_id"], u["id"], money(fee), t), actor=u)
                notif_read_link(u["id"], back_to)
                alerts_done("/admin/requests/%d" % i)
                notify(u["id"], "অনুরোধ বাতিল", "Order %s বাতিল করা হয়েছে। বাতিল ফি ৳%s আপনার ওয়ালেট থেকে কাটা হয়েছে।" % (c["order_id"], money(fee)), back_to,
                       "Request cancelled", "Order %s was cancelled. A cancellation fee of ৳%s was deducted from your wallet." % (c["order_id"], money(fee)))
                alert = ("ইউজার অনুরোধ বাতিল করেছেন", "#%s %s — Order %s (ফি ৳%s)" % (u["member_id"], u["name"], c["order_id"], money(fee)))
        except ReqError as ex:
            err(str(ex)); return redirect(back_to)
        except LedgerError:
            err("আপনার ব্যালেন্স অপর্যাপ্ত — অনুরোধ বাতিল হয়নি, কিছুই কাটা হয়নি।"); return redirect(back_to)
        if alert:
            alert_admins(alert[0], alert[1], "/admin/requests/%d" % i, "requests")
        flash("অনুরোধ বাতিল হয়েছে। বাতিল ফি ৳%s কাটা হয়েছে।" % money(fee))
        return redirect(back_to)
    fee = cancel_fee()
    bal = round(float(q1("SELECT balance FROM users WHERE id=?", (u["id"],))["balance"]), 2)
    return page("""<div class="card"><h2 style="margin-top:0">🚫 অনুরোধ বাতিল করবেন?</h2>
<div class="k">Order ID</div><div class="copybox">{{r['order_id']}}</div>
<div class="k" style="margin-top:8px">পরিমাণ</div><div class="v">৳ {{money(r['amount'])}}</div>
<div class="hl" style="margin-top:10px">⚠ অ্যাডমিনের পাঠানো এই অনুরোধ আপনি নিজে বাতিল করলে আপনার ওয়ালেট থেকে <b>বাতিল ফি ৳{{money(fee)}}</b> কেটে নেওয়া হবে।</div>
<div class="tw" style="margin-top:10px"><table>
<tr><td>বর্তমান ব্যালেন্স</td><td>৳ {{money(bal)}}</td></tr>
<tr><td>বাতিল ফি</td><td><b>− ৳ {{money(fee)}}</b></td></tr>
<tr><td>বাতিলের পর ব্যালেন্স</td><td>৳ {{money(bal-fee)}}</td></tr></table></div></div>
{% if bal < fee %}<div class="msg error">আপনার ব্যালেন্স বাতিল ফি-এর জন্য পর্যাপ্ত নয়, তাই এখন বাতিল করা যাবে না।</div>{% endif %}
<div class="card"><form method="post" data-confirm="নিশ্চিত? আপনার ওয়ালেট থেকে ৳{{money(fee)}} কাটা হবে এবং অনুরোধটি বাতিল হবে।"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<div class="row"><button class="btn r" {{'disabled' if bal < fee}}>🚫 হ্যাঁ, বাতিল করুন</button><a class="btn s" href="/requests/{{r['id']}}">← ফিরে যান</a></div></form></div>""",
                active="/requests", r=r, fee=fee, bal=bal)


# ---- admin side (Admin Desk upgrade: guided "send request" flow, server-side preview, payment-method picker, inline actions)
RQ_BTN = {"approve": ("✅ অ্যাপ্রুভ", "g"), "reject": ("❌ রিজেক্ট", "r"), "cancel": ("🚫 বাতিল", "s"), "review": ("🔎 যাচাইয়ে নিন", "s")}
TYPE_DESC = {"client_confirm": "ডিপোজিট রিকোয়েস্ট: ইউজার নিজে কনফার্ম করবে। কনফার্ম করলে মূল টাকা ওয়ালেট থেকে কাটা যাবে এবং কমিশন পুল থেকে যোগ হবে।",
             "admin_review": "উইথড্র/পেমেন্ট রিকোয়েস্ট: ইউজার পেমেন্ট জমা দেবে, অ্যাডমিন যাচাই করে অ্যাপ্রুভ করলে মূল টাকা + কমিশন ওয়ালেটে যোগ হবে।",
             "deposit": "সাধারণ ডিপোজিট: কমিশন ছাড়া। অ্যাডমিন অ্যাপ্রুভ করলে ওয়ালেটে যোগ হবে।",
             "withdraw": "সাধারণ উইথড্র: কমিশন ছাড়া। অ্যাডমিন অ্যাপ্রুভ করলে ওয়ালেট থেকে কাটা যাবে।"}
TYPE_LABEL = {"client_confirm": "ডিপোজিট রিকোয়েস্ট (ক্লায়েন্ট কনফার্ম)", "admin_review": "উইথড্র/পেমেন্ট রিকোয়েস্ট (অ্যাডমিন যাচাই)",
              "deposit": "সাধারণ ডিপোজিট (কমিশন ছাড়া)", "withdraw": "সাধারণ উইথড্র (কমিশন ছাড়া)"}


def _find_users(q):
    like = "%" + _clean_q(q) + "%"
    return qa("SELECT id,name,phone,member_id,balance,blocked FROM users WHERE is_admin=0 AND "
              "(name LIKE ? OR phone LIKE ? OR member_id LIKE ? OR referral_code LIKE ?) ORDER BY id DESC LIMIT 20", (like, like, like, like))


def _safe_next(default):
    """Return-to path posted by the inline action dialogs: only same-site /admin paths are accepted (no open redirect)."""
    n = request.form.get("next", "")
    return n if n.startswith("/admin") and not n.startswith("//") and "\\" not in n and "\n" not in n and len(n) < 300 else default


def req_actions(r):
    """Which buttons an admin may see for an admin-created request right now. Display helper only - admin_request_act / edit re-check on the server."""
    st, cc = r["status"], r["flow"] == "client_confirm"
    dec = has_perm(KIND_PERM.get(r["kind"], "-"))   # review / approve / reject move money -> deposits / withdrawals permission
    out = []
    if st in REQ_EDIT_OPEN:
        out.append("edit")
    if st == "submitted" and not cc and dec:
        out.append("review")
    if st in ("submitted", "review") and not cc and dec:
        out += ["approve", "reject"]
    if st in REQ_ALLOWED["cancel"]:
        out.append("cancel")
    return out


def req_note(r, act):
    """One-line money effect shown in the confirmation dialog (display only; the server decides everything)."""
    amt, com, oid = money(r["amount"]), float(r["commission"] or 0), r["order_id"]
    if act == "approve":
        if r["kind"] == "deposit":
            return "ইউজারের ওয়ালেটে ৳%s যোগ হবে%s। Order %s" % (amt, (" + কমিশন ৳%s (পুল থেকে)" % money(com)) if com else "", oid)
        return "ইউজারের ওয়ালেট থেকে ৳%s কাটা হবে। Order %s" % (amt, oid)
    if act == "reject":
        return "কোনো টাকা বদলাবে না; ইউজারকে কারণসহ জানানো হবে। Order %s" % oid
    if act == "cancel":
        return "কোনো টাকা বদলাবে না; ইউজারকে বাতিলের কথা জানানো হবে। Order %s" % oid
    return "Order %s যাচাইয়ে নেওয়া হবে।" % oid


def tx_note(t, act):
    amt = money(t["amount"])
    if t["kind"] == "deposit" and act == "approve":
        return "ইউজারের ওয়ালেটে ৳%s যোগ হবে।" % amt
    if t["kind"] == "withdraw" and act == "reject":
        return "ইউজারকে ৳%s ফেরত দেওয়া হবে।" % amt
    return ""


ACT_MODAL = """<div class="dm" id="dmod" hidden><div class="dm-box"><h3 id="dm-t"></h3><div class="dm-note" id="dm-m" hidden></div>
<label id="dm-l">নোট (ঐচ্ছিক)</label><textarea id="dm-r" rows="3" maxlength="200"></textarea>
<div id="dm-xw" hidden><label>এক্সট্রা কমিশন / অতিরিক্ত ক্ষতিপূরণ (৳, ঐচ্ছিক)</label><input id="dm-xv" type="number" step="0.01" min="0" inputmode="decimal" value="0"><div class="k" style="margin-bottom:6px">শুধু Agent Cash Out রিকোয়েস্টে। ০ রাখলে কিছু যোগ হবে না। দিলে ইউজারের ওয়ালেটে আলাদা এন্ট্রিতে যোগ হবে (কমিশন পুল থেকে) — নোটে কারণ/রেফারেন্স লিখুন।</div></div><div class="dm-err" id="dm-e" hidden></div>
<div class="dm-btns"><button type="button" class="btn s" id="dm-x">← ফিরে যান</button><button type="button" class="btn" id="dm-ok">নিশ্চিত করুন</button></div></div></div>
<form method="post" id="dform" style="display:none"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="act"><input type="hidden" name="reason"><input type="hidden" name="note"><input type="hidden" name="extra_commission" value="0"><input type="hidden" name="next"></form>
<script>(function(){var m=document.getElementById('dmod'),f=document.getElementById('dform');if(!m||!f)return;
var T=document.getElementById('dm-t'),M=document.getElementById('dm-m'),R=document.getElementById('dm-r'),E=document.getElementById('dm-e'),OK=document.getElementById('dm-ok'),L=document.getElementById('dm-l'),XW=document.getElementById('dm-xw'),XV=document.getElementById('dm-xv'),cur=null,host=m.closest('main')||document;
function close(){m.hidden=true;cur=null}
host.addEventListener('click',function(e){var b=e.target.closest('[data-do]');if(!b)return;e.preventDefault();cur=b;
 T.textContent=b.dataset.t||'নিশ্চিত?';var msg=b.dataset.m||'';M.textContent=msg;M.hidden=!msg;R.value='';E.hidden=true;XW.hidden=b.dataset.extra!=='1';XV.value='0';
 L.textContent=b.dataset.need==='1'?'কারণ (আবশ্যক, কমপক্ষে ৩ অক্ষর)':(b.dataset.extra==='1'?'নোট / কারণ (এক্সট্রা কমিশন দিলে আবশ্যক)':'নোট (ঐচ্ছিক)');OK.className='btn '+(b.dataset.c||'');OK.textContent=b.dataset.t||'নিশ্চিত করুন';OK.disabled=false;m.hidden=false;R.focus()});
document.getElementById('dm-x').onclick=close;m.addEventListener('click',function(e){if(e.target===m)close()});
OK.onclick=function(){if(!cur)return;var v=R.value.trim();if(cur.dataset.need==='1'&&v.length<3){E.textContent='কমপক্ষে ৩ অক্ষরের কারণ লিখুন।';E.hidden=false;R.focus();return}
 var xa=0;if(!XW.hidden){var xr=(XV.value||'0').trim();xa=parseFloat(xr);if(!/^[0-9]{1,8}([.][0-9]{1,2})?$/.test(xr)||isNaN(xa)||xa<0){E.textContent='এক্সট্রা কমিশনের পরিমাণ সঠিক নয় (০ বা ধনাত্মক সংখ্যা, সর্বোচ্চ ২ দশমিক)।';E.hidden=false;XV.focus();return}
  if(xa>0&&v.length<3){E.textContent='এক্সট্রা কমিশনের কারণ/রেফারেন্স নোটে লিখুন (কমপক্ষে ৩ অক্ষর)।';E.hidden=false;R.focus();return}}
 f.elements['extra_commission'].value=xa>0?xr:'0';
 OK.disabled=true;f.action=cur.dataset.u;f.elements['act'].value=cur.dataset['do'];f.elements['reason'].value=v;f.elements['note'].value=v;f.elements['next'].value=location.pathname+location.search;
 if(typeof ldShow==='function')ldShow();f.submit()}})()</script>"""

PN_JS = """function pnBind(f){var man=document.getElementById('manual');if(!man)return;var rs=f.querySelectorAll('input[name=pn]');
 function sync(){var v='manual';rs.forEach(function(r){var l=r.closest('.pmc');if(l)l.classList.toggle('on',r.checked);if(r.checked)v=r.value});man.hidden=(rs.length>0&&v!=='manual')}
 rs.forEach(function(r){r.addEventListener('change',sync)});sync()}"""

UPANEL_TPL = """<div class="copybox" style="user-select:auto"><b>#{{x['member_id']}} {{x['name']}}</b>
<div class="k">{{x['phone']}} · ব্যালেন্স ৳ {{money(x['balance'])}} · কমিশন রেট {{rate|pct}}%</div>
<div class="row" style="margin-top:6px"><a class="btn sm s" href="/admin/users/{{x['id']}}">👤 প্রোফাইল</a>{% if chg %}<button type="button" class="btn sm s" id="uchg">ইউজার বদলান</button>{% endif %}</div></div>
{% if show_pn %}<div class="pnsel">{% if can_pn %}<label>পেমেন্ট মাধ্যম — {{x['name']}} এর নিবন্ধিত নম্বর থেকে বাছুন</label>
{% for p in pns %}<label class="pmc{{' on' if p['id']==sel}}" style="--mc:{{mcol.get(p['method'],'#1E90FF')}}"><input type="radio" name="pn" value="{{p['id']}}" {{'checked' if p['id']==sel}}><span><b>{{p['method']}} · {{acct_lbl.get(p['account_type'],p['account_type'])}}</b><span class="n">{{p['number']}}</span></span></label>{% endfor %}
{% if not pns %}<div class="k" style="margin-bottom:8px">ইউজার এখনো কোনো নম্বর যোগ করেননি — নিচে নিজে লিখুন।</div>{% endif %}
<label class="pmc{{' on' if not sel}}"><input type="radio" name="pn" value="manual" {{'checked' if not sel}}><span><b>✍️ অন্য নম্বর / নিজে লিখব</b></span></label>
{% else %}<div class="k" style="margin-bottom:8px">পেমেন্ট নম্বর দেখার অনুমতি নেই — মাধ্যম ও নম্বর নিজে লিখুন।</div>{% endif %}</div>{% endif %}"""


def _panel_html(x, sel=0, chg=True, show_pn=True):
    """User box + that user's own registered payment methods (only rows WHERE user_id = x.id, only for staff holding payment_numbers)."""
    can_pn = has_perm("payment_numbers")
    pns = qa("SELECT id,method,account_type,number FROM payment_numbers WHERE user_id=? ORDER BY id", (x["id"],)) if can_pn else []
    if sel not in {p["id"] for p in pns}:
        sel = 0
    return _frag(UPANEL_TPL, x=x, pns=pns, sel=sel, can_pn=can_pn, rate=effective_rate(x), chg=chg, show_pn=show_pn)


def _pn_resolve(uid, raw):
    """(row, error). A selected registered number must belong to THIS user and the staff member must hold payment_numbers."""
    raw = (raw or "").strip()
    if not raw or raw == "manual":
        return None, None
    if not raw.isdigit() or len(raw) > 12:
        return None, "পেমেন্ট নম্বর বাছাই সঠিক নয়।"
    if not has_perm("payment_numbers"):
        return None, "পেমেন্ট নম্বর ব্যবহারের অনুমতি আপনার নেই — নম্বর নিজে লিখুন।"
    r = q1("SELECT * FROM payment_numbers WHERE id=? AND user_id=?", (int(raw), uid))
    if not r:
        return None, "এই পেমেন্ট নম্বরটি এই ইউজারের নয়।"
    return r, None


def _req_prepare(f):
    """Validate a 'send request' form entirely on the server (never trusts client-side amounts, commission or numbers). Raises ReqError."""
    uid = f.get("uid", type=int)
    x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (uid,)) if uid else None
    if not x or x["blocked"]:
        raise ReqError("সঠিক (ব্লক নয় এমন) ইউজার নির্বাচন করুন।")
    rtype = f.get("type") or f.get("kind") or ""
    if rtype not in REQ_TYPES:
        raise ReqError("অনুরোধের ধরন বাছাই করুন।")
    kind, flow = REQ_TYPES[rtype]
    wd = is_wd(kind, flow)
    pn, e = (None, None) if wd else _pn_resolve(x["id"], f.get("pn"))  # withdrawal requests NEVER use the user's saved payment numbers
    if e:
        raise ReqError(e)
    method = pn["method"] if pn else f.get("method", "")
    num = pn["number"] if pn else f.get("number", "").strip()
    paytype = (f.get("pay_type") or "").strip().lower() if wd else ""
    if wd and paytype not in PAY_TYPES:
        raise ReqError("পেমেন্ট টাইপ বাছাই করুন (Personal: Send Money / Agent: Cash Out / Merchant: Payment)।")
    order = re.sub(r"[^A-Z0-9_-]", "", f.get("order_id", "").upper())[:32] or ("ORD" + secrets.token_hex(4).upper())
    amt = parse_amount(f.get("amount"))
    ins = f.get("instructions", "").strip()[:500]
    purpose = f.get("purpose", "").strip()[:300]
    purpose_en = f.get("purpose_en", "").strip()[:300]
    hrs_raw = f.get("hours", "").strip() or "0"
    if flow == "client_confirm":  # keep the real method (bKash/Nagad/Rocket) so History shows it; "Wallet" only as a fallback
        method = method if method in METHODS else "Wallet"
        num = num if PHONE_RE.fullmatch(num) else "-"
    bad = len(order) < 4 or amt <= 0 or amt > 100_000_000 or not re.fullmatch(r"\d{1,3}", hrs_raw) or int(hrs_raw) > 720
    if flow != "client_confirm" and (method not in METHODS or not PHONE_RE.fullmatch(num)):
        bad = True
    pdef = False
    if flow and not purpose:  # Purpose is optional: fall back to a neutral default label
        purpose, pdef = default_purpose(flow, "bn"), True
        purpose_en = purpose_en or default_purpose(flow, "en")
    if bad:
        raise ReqError("ধরন, ৪+ অক্ষরের Order ID (A-Z, 0-9, -, _), সঠিক পরিমাণ, মাধ্যম, ১১ ডিজিটের নম্বর (ক্লায়েন্ট-কনফার্ম ছাড়া) ও ০–৭২০ ঘণ্টার মেয়াদ দিন।")
    hrs = int(hrs_raw)
    exp = (datetime.utcnow() + timedelta(hours=hrs)).strftime("%Y-%m-%d %H:%M:%S") if hrs else None
    rate = effective_rate(x) if flow else None
    com = commission_for(amt, rate) if flow else None
    dup = q1("SELECT id,order_id FROM requests WHERE user_id=? AND kind=? AND COALESCE(flow,'')=? AND status IN ('pending','submitted','review') "
             "AND ABS(amount-?)<0.005 ORDER BY id DESC LIMIT 1", (x["id"], kind, flow or "", amt))
    return dict(x=x, rtype=rtype, kind=kind, flow=flow, method=method, num=num, order=order, amt=amt, ins=ins, purpose=purpose,
                purpose_en=purpose_en, purpose_default=pdef, hrs=hrs, exp=exp, rate=rate, com=com, pn=pn, dup=dup, paytype=paytype)


def _req_checks(d):
    """Balance / pool checks. Run once for the preview (no lock) and again inside the atomic block that inserts the request."""
    x, amt, com, flow = d["x"], d["amt"], d["com"], d["flow"]
    if flow == "client_confirm" and float(q1("SELECT balance FROM users WHERE id=?", (x["id"],))["balance"]) + 1e-9 < amt:
        raise ReqError("ইউজারের বর্তমান ব্যালেন্স অনুরোধের পরিমাণের চেয়ে কম।")
    if flow and com > 0 and pool_available() + 0.004 < com:
        raise PoolError("কমিশন পুলে পর্যাপ্ত ফান্ড নেই (উপলব্ধ ৳%s, দরকার ৳%s)। আগে পুলে ফান্ড যোগ করুন।" % (money(max(pool_available(), 0)), money(com)))


@app.route("/admin/requests/new", methods=["GET", "POST"])
@staff_required("requests")
def admin_request_new():
    a = me()
    if request.method == "POST":
        uid = request.form.get("uid", type=int)
        ptype_back = request.form.get("type") if request.form.get("type") in REQ_TYPES else "client_confirm"
        back_to = ("/admin/requests/new?uid=%d&type=%s" % (uid, ptype_back)) if uid else "/admin/requests/new"
        try:
            d = _req_prepare(request.form)
        except ReqError as ex:
            err(str(ex)); return redirect(back_to)
        x, kind, flow = d["x"], d["kind"], d["flow"]
        if d["dup"] and request.form.get("dup_ok") != "1":
            err("এই ইউজারের একই ধরন ও পরিমাণের একটি খোলা অনুরোধ (Order %s) আগে থেকেই আছে। নিশ্চিত হলে পর্যালোচনার ধাপে 'তবুও পাঠান' টিক দিন।" % d["dup"]["order_id"])
            return redirect(back_to)
        if rate_hit("rqc:%d" % a["id"], 60, 3600):
            err("অনেক রিকোয়েস্ট হয়েছে।"); return redirect(back_to)
        try:
            with atomic():
                cu = q1("SELECT blocked FROM users WHERE id=?", (x["id"],))
                if not cu or cu["blocked"]:
                    raise ReqError("সঠিক (ব্লক নয় এমন) ইউজার নির্বাচন করুন।")
                if d["pn"]:  # the registered number must still be exactly what the admin saw
                    cp = q1("SELECT method,number FROM payment_numbers WHERE id=? AND user_id=?", (d["pn"]["id"], x["id"]))
                    if not cp or cp["method"] != d["pn"]["method"] or cp["number"] != d["pn"]["number"]:
                        raise ReqError("ইউজার এইমাত্র তার পেমেন্ট নম্বর বদলেছেন — পেজ রিলোড করে আবার দেখে নিন।")
                _req_checks(d)
                amt, com, order = d["amt"], d["com"], d["order"]
                cur = db().execute("INSERT INTO requests(order_id,user_id,kind,amount,method,pay_number,instructions,expires_at,status,"
                                   "created_by_id,created_by,created,updated,flow,commission,commission_rate,purpose,purpose_en,pay_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                   (order, x["id"], kind, amt, d["method"], d["num"], d["ins"], d["exp"], "pending", a["id"], a["member_id"], now(), now(),
                                    flow, com, d["rate"], d["purpose"] or None, d["purpose_en"] or None, d["paytype"] or None))
                rid = cur.lastrowid
                req_log(rid, "create", None, "pending", a["member_id"], a["id"], "%s/%s ৳%s commission ৳%s%s" % (kind, flow or "-", amt, com or 0, (" pn#%d" % d["pn"]["id"]) if d["pn"] else "") + ((" type=%s" % d["paytype"]) if d["paytype"] else ""))
                if flow == "client_confirm":
                    notify(x["id"], "নতুন ডিপোজিট রিকোয়েস্ট", "৳%s কাটা হবে, কমিশন ৳%s। উদ্দেশ্য: %s। Order: %s" % (money(amt), money(com), d["purpose"], order), "/requests/%d" % rid,
                           "New deposit request", "৳%s will be deducted, commission ৳%s. Purpose: %s. Order: %s" % (money(amt), money(com), d["purpose_en"] or d["purpose"], order))
                else:
                    notify(x["id"], "নতুন অনুরোধ", "%s অনুরোধ — ৳%s (%s)%s। Order: %s" % (REQ_KIND[req_dtype({"flow": flow, "kind": kind})], money(amt), d["method"] + ((" · " + PAY_TYPE_LABEL[d["paytype"]] + " · " + d["num"]) if d["paytype"] else ""), (" + কমিশন ৳%s" % money(com)) if com else "", order),
                           "/requests/%d" % rid)
                audit("req_create", "req#%d order=%s %s/%s ৳%s commission ৳%s user#%d admin_id=%d%s" % (rid, order, kind, flow or "-", amt, com or 0, x["id"], a["id"],
                                                                                                    (" pn#%d" % d["pn"]["id"]) if d["pn"] else ""))
        except (ReqError, PoolError) as ex:
            err(str(ex)); return redirect(back_to)
        except INTEGRITY:
            same = q1("SELECT id FROM requests WHERE order_id=? AND user_id=? AND created_by_id=? AND created>=?",
                      (d["order"], x["id"], a["id"], (datetime.utcnow() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")))
            if same:  # double click / retry of the same form: the request already exists - never create a second one
                flash("এই অনুরোধটি আগেই পাঠানো হয়েছে।"); return redirect("/admin/requests/%d" % same["id"])
            err("এই Order ID আগেই ব্যবহার করা হয়েছে।"); return redirect(back_to)
        flash("অনুরোধ পাঠানো হয়েছে।"); return redirect("/admin/requests/%d" % rid)
    q = _clean_q(request.args.get("q", ""))
    uid = request.args.get("uid", type=int)
    x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (uid,)) if uid else None
    if x and x["blocked"]:
        err("ব্লকড ইউজারকে রিকোয়েস্ট পাঠানো যায় না।"); x = None
    try:
        dh = int(setting("req_expiry_hours", "24") or 0)
    except ValueError:
        dh = 24
    ptype = request.args.get("type", "client_confirm")
    if ptype not in REQ_TYPES:
        ptype = "client_confirm"
    panel = _panel_html(x, request.args.get("pn", type=int) or 0) if x else ""
    return page(DESK_STYLE + """<div class="card"><h2 style="margin-top:0">➕ নতুন রিকোয়েস্ট পাঠান</h2>
<form method="post" id="rf"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="uid" id="uid" value="{{x['id'] if x else ''}}"><input type="hidden" name="dup_ok" id="dupok" value="">
<style>.upl{max-height:56vh;overflow:auto;margin-bottom:8px}
.upr{display:block;width:100%;text-align:left;margin:0 0 7px;padding:10px 12px;border-radius:12px;border:1.5px solid var(--ln);background:var(--card);background-image:none;box-shadow:none;color:var(--tx);font-weight:400;touch-action:manipulation}
.upr:active{border-color:var(--b);transform:none}.upr-t{display:flex;justify-content:space-between;gap:8px;font-size:15px}.upr-t b{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}.upr-t span{flex:none;font-weight:700;color:var(--okt)}
.upr-m{font-size:12.5px;color:var(--mut);margin-top:2px}</style>
<label>১. ক্লায়েন্ট বাছাই করুন (একজনকে)</label>
<div id="upick"{% if x %} hidden{% endif %}><input id="uq" type="search" inputmode="search" enterkeyhint="search" value="{{q}}" placeholder="নাম / ফোন / মেম্বার আইডি" autocomplete="off">
<div class="chips" id="ufl">{% for k,l in flt %}<button type="button" data-f="{{k}}" class="{{'on' if k=='all'}}">{{l}}</button>{% endfor %}</div>
<div class="sq-st" id="ust"></div><div id="ures" class="upl"></div></div>
<div id="upanel">{{panel|safe}}</div>
<div id="rest"{% if not x %} hidden{% endif %}>
<label>২. ধরন</label><select name="type" id="rtype">
<optgroup label="ডিপোজিট"><option value="client_confirm" {{'selected' if ptype=='client_confirm'}}>ডিপোজিট রিকোয়েস্ট — ক্লায়েন্ট কনফার্ম করবে</option><option value="deposit" {{'selected' if ptype=='deposit'}}>সাধারণ ডিপোজিট (কমিশন ছাড়া)</option></optgroup>
<optgroup label="উইথড্র"><option value="admin_review" {{'selected' if ptype=='admin_review'}}>উইথড্র/পেমেন্ট রিকোয়েস্ট — অ্যাডমিন যাচাই করবে</option><option value="withdraw" {{'selected' if ptype=='withdraw'}}>সাধারণ উইথড্র (কমিশন ছাড়া)</option></optgroup></select>
<div class="k" id="tydesc" style="margin:-6px 0 10px"></div>
<label>৩. পরিমাণ (৳ BDT)</label><input name="amount" type="number" step="0.01" min="0.01" required inputmode="decimal">
<div class="k" style="margin:-6px 0 10px">পুলে উপলব্ধ ফান্ড: <b>৳{{money(avail)}}</b> · কমিশন সার্ভার হিসাব করবে, পর্যালোচনায় দেখানো হবে।</div>
<div id="manual"><label>পেমেন্ট মাধ্যম</label><select name="method">{% for m in methods %}<option>{{m}}</option>{% endfor %}</select>
<label>পেমেন্ট নম্বর (১১ ডিজিট; ডিপোজিট রিকোয়েস্টে লাগবে না)</label><input name="number" inputmode="numeric" maxlength="11"></div>
<div id="wdbox" hidden><label>পেমেন্ট টাইপ</label><select name="pay_type"><option value="">— বাছাই করুন —</option><option value="personal">Personal: Send Money</option><option value="agent">Agent: Cash Out</option><option value="merchant">Merchant: Payment</option></select>
<div class="k" style="margin:-6px 0 10px">উইথড্র রিকোয়েস্টে ইউজারের সেভ করা নম্বর ব্যবহার হয় না — এখানে দেওয়া প্রোভাইডার, নম্বর ও টাইপই ইউজারকে দেখানো হবে।</div></div>
<label>পেমেন্ট নির্দেশনা (ঐচ্ছিক — ইউজারকে দেখানো হবে)</label><textarea name="instructions" rows="3" maxlength="500"></textarea>
<details class="dt"><summary>⚙ আরও অপশন (সবই ঐচ্ছিক)</summary><div class="inn">
<label>উদ্দেশ্য — বাংলা (ঐচ্ছিক; ফাঁকা থাকলে ডিফল্ট লেবেল বসবে)</label><textarea name="purpose" id="purp" rows="2" maxlength="300"></textarea>
<label>Purpose — English (optional)</label><textarea name="purpose_en" rows="2" maxlength="300"></textarea>
<label>Order ID (ফাঁকা রাখলে স্বয়ংক্রিয়)</label><input name="order_id" maxlength="32" value="{{oid}}" autocapitalize="characters">
<label>মেয়াদ (ঘণ্টা; ০ = মেয়াদ নেই)</label><input name="hours" type="number" min="0" max="720" value="{{dh}}"></div></details>
<button type="button" class="btn" id="rv" style="width:100%">🔍 পর্যালোচনা করুন</button>
<div class="k" style="margin-top:6px">পাঠানোর আগে সব তথ্য একবার দেখানো হবে। শুধু অনুরোধ পাঠালে কোনো টাকা, কমিশন বা লেজার এন্ট্রি তৈরি হয় না।</div></div></form></div>
<div class="dm" id="rmod" hidden><div class="dm-box"><h3>📋 পাঠানোর আগে দেখে নিন</h3><div id="rbody"></div>
<div class="dm-btns"><button type="button" class="btn s" id="rback">← সম্পাদনা</button><button type="button" class="btn g" id="rsend">📨 নিশ্চিত করে পাঠান</button></div></div></div>
<script>(function(){var $=function(i){return document.getElementById(i)},f=$('rf');if(!f)return;""" + PN_JS + """
var uq=$('uq'),res=$('ures'),chips=$('ufl'),st=$('ust'),fl='all',tm=null,seq=0,TY=$('rtype'),DESC={{tydesc|tojson}},rm=$('rmod'),rb=$('rbody'),rs=$('rsend');
function wdSync(){var wd=TY.value==='admin_review'||TY.value==='withdraw',w=$('wdbox'),man=$('manual');if(w){w.hidden=!wd;var ps=f.elements['pay_type'];if(ps)ps.required=wd}
 document.querySelectorAll('#upanel .pnsel').forEach(function(e){e.hidden=wd});
 if(wd){var mr=f.querySelector('input[name=pn][value=manual]');if(mr)mr.checked=true;if(man)man.hidden=false}
 else{var ck=f.querySelector('input[name=pn]:checked');if(ck)ck.dispatchEvent(new Event('change',{bubbles:true}))}}
function tyc(){$('tydesc').textContent=DESC[TY.value]||'';wdSync()}TY.addEventListener('change',tyc);pnBind(f);tyc();
function pick(u){fetch('/admin/requests/panel/'+u.id+'?type='+encodeURIComponent(TY.value),{credentials:'same-origin'}).then(function(r){return r.ok?r.text():Promise.reject()}).then(function(h){
 $('upanel').innerHTML=h;$('uid').value=u.id;$('upick').hidden=true;$('rest').hidden=false;pnBind(f);wdSync();
 try{history.replaceState(null,'','/admin/requests/new?uid='+u.id+'&type='+TY.value)}catch(e){}}).catch(function(){alert('ইউজারের তথ্য লোড করা যায়নি।')})}
function row(u){var b=document.createElement('button');b.type='button';b.className='upr';
 var t=document.createElement('div');t.className='upr-t';var n=document.createElement('b');n.textContent=u.name;var bl=document.createElement('span');bl.textContent='৳ '+u.balance;t.appendChild(n);t.appendChild(bl);
 var m=document.createElement('div');m.className='upr-m';m.textContent='#'+u.member_id+' · 📱 '+u.phone+(u.open_req?' · ⏳ '+u.open_req+'টি খোলা রিকোয়েস্ট':'');
 b.appendChild(t);b.appendChild(m);b.addEventListener('click',function(){pick(u)});return b}
function load(p,append,btn){var my=++seq;st.textContent='খুঁজছে…';
 fetch('/admin/requests/find?q='+encodeURIComponent(uq.value.trim())+'&f='+encodeURIComponent(fl)+'&p='+p,{credentials:'same-origin'}).then(function(r){if(!r.ok)throw 0;return r.json()}).then(function(j){if(my!==seq)return;
  if(btn)btn.remove();if(!append)res.innerHTML='';
  j.rows.forEach(function(u){res.appendChild(row(u))});
  if(!j.rows.length&&!append){var d=document.createElement('div');d.className='k';d.style.padding='8px 2px';d.textContent='কোনো ক্লায়েন্ট পাওয়া যায়নি';res.appendChild(d)}
  if(j.more){var mb=document.createElement('button');mb.type='button';mb.className='btn s';mb.style.cssText='width:100%;margin:4px 0 8px';mb.textContent='আরও দেখান';mb.addEventListener('click',function(){mb.disabled=true;load(p+1,true,mb)});res.appendChild(mb)}
  st.textContent=''}).catch(function(){if(my===seq){st.textContent='লোড করা যায়নি — আবার চেষ্টা করুন';if(btn)btn.disabled=false}})}
uq.addEventListener('input',function(){clearTimeout(tm);tm=setTimeout(function(){load(1,false)},250)});
uq.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();clearTimeout(tm);load(1,false);uq.blur()}});
chips.addEventListener('click',function(e){var b=e.target.closest('button[data-f]');if(!b)return;chips.querySelectorAll('button').forEach(function(x){x.classList.toggle('on',x===b)});fl=b.dataset.f;load(1,false)});
$('upanel').addEventListener('click',function(e){if(e.target.closest('#uchg')){$('uid').value='';$('upanel').innerHTML='';$('rest').hidden=true;$('upick').hidden=false;if(!res.children.length)load(1,false);uq.focus()}});
if(!$('uid').value)load(1,false);
function line(dl,k,v){var d=document.createElement('div'),a=document.createElement('dt'),b=document.createElement('dd');a.textContent=k;b.textContent=v;d.appendChild(a);d.appendChild(b);dl.appendChild(d)}
function box(cls,t){var d=document.createElement('div');d.className=cls;d.textContent=t;return d}
function show(d){rb.innerHTML='';$('dupok').value='';rs.disabled=false;
 if(!d.ok){rb.appendChild(box('dm-err',d.error||'যাচাই করা যায়নি'));rs.hidden=true}else{rs.hidden=false;var dl=document.createElement('dl');dl.className='dm-dl';d.rows.forEach(function(r){line(dl,r[0],r[1])});rb.appendChild(dl);
  d.effects.forEach(function(t){rb.appendChild(box('dm-note',t))});
  if(d.dup){var w=box('dm-warn','⚠ '+d.dup);var l=document.createElement('label');l.className='ck';var c=document.createElement('input');c.type='checkbox';c.addEventListener('change',function(){$('dupok').value=c.checked?'1':'';rs.disabled=!c.checked});
   l.appendChild(c);l.appendChild(document.createTextNode('তবুও পাঠান'));w.appendChild(l);rb.appendChild(w);rs.disabled=true}}
 rm.hidden=false}
function review(){if(!$('uid').value){alert('আগে ইউজার বাছাই করুন।');uq.focus();return}if(!f.reportValidity())return;
 var fd=new FormData(f),b=$('rv');b.disabled=true;
 fetch('/admin/requests/preview',{method:'POST',body:fd,credentials:'same-origin'}).then(function(r){return r.json()}).then(function(d){b.disabled=false;show(d)}).catch(function(){b.disabled=false;alert('পর্যালোচনা লোড করা যায়নি — আবার চেষ্টা করুন।')})}
$('rv').addEventListener('click',review);$('rback').addEventListener('click',function(){rm.hidden=true});rm.addEventListener('click',function(e){if(e.target===rm)rm.hidden=true});
rs.addEventListener('click',function(){rs.disabled=true;f.dataset.ok='1';if(typeof ldShow==='function')ldShow();f.submit()});
f.addEventListener('submit',function(e){if(f.dataset.ok==='1')return;e.preventDefault();e.stopPropagation();review()},true)})()</script>""",
                active="/admin/requests", x=x, q=q, flt=FIND_FILTERS, methods=METHODS, dh=dh, oid="ORD" + secrets.token_hex(4).upper(),
                avail=pool_available(), ptype=ptype, panel=panel, tydesc=TYPE_DESC)


@app.route("/admin/requests/preview", methods=["POST"])
@staff_required("requests")
def admin_request_preview():
    """Server-side review of a 'send request' form: validates exactly like the real send and computes every figure. Writes nothing."""
    try:
        d = _req_prepare(request.form)
        _req_checks(d)
        if q1("SELECT 1 FROM requests WHERE order_id=?", (d["order"],)):
            raise ReqError("এই Order ID আগেই ব্যবহার করা হয়েছে — অন্য একটি দিন।")
    except (ReqError, PoolError) as ex:
        return jsonify(ok=False, error=str(ex))
    x, amt, com, flow, kind = d["x"], d["amt"], d["com"] or 0.0, d["flow"], d["kind"]
    bal = round(float(x["balance"]), 2)
    rows = [["ইউজার", "#%s %s" % (x["member_id"], x["name"])], ["ফোন", x["phone"]], ["বর্তমান ব্যালেন্স", "৳ " + money(bal)],
            ["ধরন", TYPE_LABEL[d["rtype"]]], ["পরিমাণ", "৳ " + money(amt)]]
    if flow:
        rows.append(["কমিশন (%s%%)" % _pct(d["rate"]), "৳ " + money(com)])
    rows += [["পেমেন্ট মাধ্যম", d["method"]], ["পেমেন্ট নম্বর", (d["num"] if d["num"] != "-" else "—") + (" (ইউজারের নিবন্ধিত নম্বর)" if d["pn"] else "")]]
    if d["paytype"]:
        rows.append(["পেমেন্ট টাইপ", PAY_TYPE_LABEL[d["paytype"]]])
    if d["purpose"]:
        rows.append(["উদ্দেশ্য", d["purpose"] + (" (ডিফল্ট)" if d["purpose_default"] else "")])
    rows += [["নোট / নির্দেশনা", d["ins"] or "—"], ["মেয়াদ", ("%d ঘণ্টা" % d["hrs"]) if d["hrs"] else "মেয়াদ নেই"], ["Order ID", d["order"]]]
    eff = ["এখন শুধু অনুরোধটি ইউজারের ড্যাশবোর্ডে ও নোটিফিকেশনে যাবে। এই ধাপে কোনো টাকা, কমিশন বা লেজার এন্ট্রি তৈরি হবে না।"]
    if flow == "client_confirm":
        eff.append("ইউজার কনফার্ম করলে: ওয়ালেট − ৳%s + কমিশন ৳%s = নিট − ৳%s (ব্যালেন্স দাঁড়াবে ৳%s)।" % (money(amt), money(com), money(amt - com), money(bal - amt + com)))
    elif flow == "admin_review":
        eff.append("ইউজার পেমেন্ট জমা দিলে এবং আপনি অ্যাপ্রুভ করলে: ওয়ালেটে + ৳%s + কমিশন ৳%s (মোট ৳%s)।" % (money(amt), money(com), money(amt + com)))
    elif kind == "deposit":
        eff.append("অ্যাপ্রুভ করলে ওয়ালেটে + ৳%s যোগ হবে।" % money(amt))
    else:
        eff.append("অ্যাপ্রুভ করলে ওয়ালেট থেকে ৳%s কাটা হবে।" % money(amt))
    if flow:
        eff.append("কমিশন শুধু কমিশন পুল থেকে যাবে (উপলব্ধ ৳%s)।" % money(pool_available()))
    if flow == "admin_review" and d["paytype"] == "agent":
        eff.append("Agent Cash Out: অ্যাপ্রুভের সময় ঐচ্ছিক এক্সট্রা কমিশন (এজেন্টের Cash Out ফি-এর ক্ষতিপূরণ) যোগ করা যাবে।")
    dup = ("এই ইউজারের একই ধরন ও পরিমাণের একটি খোলা অনুরোধ (Order %s) আগে থেকেই আছে।" % d["dup"]["order_id"]) if d["dup"] else None
    return jsonify(ok=True, rows=rows, effects=eff, dup=dup)


@app.route("/admin/requests/panel/<int:uid>")
@staff_required("requests")
def admin_request_panel(uid):
    """HTML fragment: the selected user's box + THEIR payment methods only (uid is validated; rows are filtered by user_id)."""
    x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (uid,))
    if not x:
        abort(404)
    if x["blocked"]:
        return Response("blocked", status=409, mimetype="text/plain")
    r = Response(_panel_html(x, request.args.get("pn", type=int) or 0), mimetype="text/html")
    r.headers["Cache-Control"] = "no-store"
    return r


FIND_FILTERS = (("all", "সব ইউজার"), ("funded", "ব্যালেন্স আছে"), ("zero", "ব্যালেন্স শূন্য"), ("active7", "৭ দিনে সক্রিয়"),
                ("inactive7", "৭+ দিন নিষ্ক্রিয়"), ("new", "নতুন নিবন্ধিত"), ("openreq", "খোলা রিকোয়েস্ট আছে"))
FIND_PER = 15


def _find_clients(q, f, p, per=FIND_PER):
    """Client picker for 'send request': searchable + filterable, LIMIT/OFFSET pagination (per+1 rows fetched, no COUNT per keystroke).
    Blocked users are never listed (they cannot receive requests). Read-only."""
    where, args = ["u.is_admin=0", "COALESCE(u.blocked,0)=0"], []
    if q:
        like = "%" + q + "%"
        cond = "u.name LIKE ? OR u.phone LIKE ? OR u.member_id LIKE ? OR u.referral_code LIKE ?"
        args += [like] * 4
        if has_perm("payment_numbers"):
            cond += " OR EXISTS(SELECT 1 FROM payment_numbers pn WHERE pn.user_id=u.id AND pn.number LIKE ?)"
            args.append(like)
        where.append("(" + cond + ")")
    if f == "funded":
        where.append("u.balance>0")
    elif f == "zero":
        where.append("COALESCE(u.balance,0)<=0")
    elif f == "active7":
        where.append("u.last_login>=datetime('now','-7 days')")
    elif f == "inactive7":
        where.append("(u.last_login IS NULL OR u.last_login<datetime('now','-7 days'))")
    elif f == "new":
        where.append("u.created>=datetime('now','-7 days')")
    elif f == "openreq":
        where.append("EXISTS(SELECT 1 FROM requests r WHERE r.user_id=u.id AND r.status IN ('pending','submitted','review'))")
    order, oargs = "u.id DESC", []
    if q:
        order, oargs = "(CASE WHEN u.member_id=? OR u.phone=? OR u.referral_code=? THEN 0 ELSE 1 END), u.id DESC", [q, q, q.upper()]
    p = min(max(p, 1), 500)
    rows = qa("SELECT u.id,u.name,u.phone,u.member_id,u.balance,u.comm_rate,u.vip_rate,"
              "(SELECT COUNT(*) FROM requests r WHERE r.user_id=u.id AND r.status IN ('pending','submitted','review')) open_req "
              "FROM users u WHERE " + " AND ".join(where) + " ORDER BY " + order + " LIMIT ? OFFSET ?",
              args + oargs + [per + 1, (p - 1) * per])
    return rows[:per], len(rows) > per


@app.route("/admin/requests/find")
@staff_required("requests")
def admin_request_find():
    """Client list for the one-page 'send request' form (same permission as creating a request). Works with an empty search too."""
    q = _clean_q(request.args.get("q", ""))
    f = request.args.get("f", "all")
    if f not in {k for k, _ in FIND_FILTERS}:
        f = "all"
    p = request.args.get("p", type=int) or 1
    rows, more = _find_clients(q, f, p)
    resp = jsonify(rows=[dict(id=r["id"], name=r["name"], phone=r["phone"], member_id=r["member_id"], balance=money(r["balance"]),
                              open_req=int(r["open_req"] or 0), rate=_pct(effective_rate(r))) for r in rows], more=more)
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---- Request Management UI: two tabs (Admin -> User = `requests`, User -> Admin = `tx`), serial card lists, details, editing
TX_LABEL = {"pending": "অপেক্ষমাণ", "review": "যাচাইয়ে", "processing": "প্রসেসিং", "approved": "অনুমোদিত",
            "paid": "সম্পন্ন", "rejected": "রিজেক্ট"}
TX_OPEN = {"deposit": ("pending", "review"), "withdraw": ("pending", "processing", "approved")}
REQ_EDIT_OPEN = ("pending", "submitted", "review")   # an admin-created request can be edited only until it is completed

RQ_STYLE = """<style>
.rq-tabs{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:0 0 12px}
.rq-tab{position:relative;display:flex;align-items:center;gap:8px;padding:10px 10px;border-radius:14px;background:var(--card);border:1.5px solid var(--ln);color:var(--tx);min-width:0;box-shadow:0 1px 3px #0A3D6614;text-decoration:none}
.rq-tab .ic{font-size:20px;flex:none}
.rq-tab .tt{display:flex;flex-direction:column;font-weight:700;font-size:14px;line-height:1.25;min-width:0}
.rq-tab small{font-weight:500;font-size:11px;opacity:.75}
.rq-tab.on{background:linear-gradient(100deg,#1E90FF,#1668D0);color:#fff;border-color:transparent;box-shadow:0 4px 12px -4px #1E90FF80}
.rq-tab .n{position:absolute;top:-7px;right:-3px;min-width:20px;height:20px;padding:0 5px;border-radius:10px;background:#ef4444;color:#fff;font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center}
.rq-card{display:flex;gap:10px;align-items:flex-start;background:var(--card);border:1px solid var(--ln);border-left:4px solid #1E90FF;border-radius:14px;padding:10px 12px;margin-bottom:8px;color:var(--tx);box-shadow:0 1px 3px #0A3D6614;touch-action:manipulation;text-decoration:none}
.rq-card[data-by=user]{border-left-color:#0EA371}
.rq-main{display:block;color:var(--tx)}
.rq-sn{flex:none;min-width:34px;height:34px;padding:0 6px;border-radius:10px;background:#1E90FF14;color:var(--bt);font-weight:800;font-size:13px;display:flex;align-items:center;justify-content:center}
.rq-b{flex:1;min-width:0}
.rq-t,.rq-m{display:flex;justify-content:space-between;align-items:center;gap:8px}
.rq-id{font-size:14.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rq-t .pill{flex:none;white-space:nowrap}
.rq-u{font-size:13px;margin:2px 0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rq-ty{font-size:12.5px;color:var(--mut)}
.rq-am{font-size:15px;color:var(--okt);white-space:nowrap}
.rq-d{font-size:12px;color:var(--mut);margin-top:2px}
.rq-tag{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11.5px;font-weight:700;background:#DCEEFF;color:#0B4F9C;margin-right:4px}
.rq-tag.u{background:#DDF8EC;color:#0B6B47}
.rq-acts{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.rq-acts .btn{padding:6px 10px;font-size:12.5px}
.rq-f input,.rq-f select{margin-bottom:8px}
.rq-f2{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.rq-amt{font-size:26px;font-weight:800;margin:6px 0 4px;color:var(--okt)}
.rq-dl{margin:6px 0 0}
.rq-dl>div{display:flex;gap:10px;justify-content:space-between;padding:7px 0;border-top:1px solid var(--ln)}
.rq-dl dt{flex:0 0 38%;color:var(--mut);font-size:13px}
.rq-dl dd{margin:0;flex:1;text-align:right;font-size:14px;word-break:break-word}
.rq-lock{font-size:13px;line-height:1.5}
</style>"""

RQ2_STYLE = """<style>
.sum{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin:0 0 12px}
.sum a{display:flex;flex-direction:column;gap:2px;background:var(--card);border:1.5px solid var(--ln);border-radius:14px;padding:9px 11px;color:var(--tx);box-shadow:0 1px 3px #0A3D6614;min-width:0}
.sum a b{font-size:21px;line-height:1.15}
.sum a span{font-size:12px;color:var(--mut);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sum a.on{border-color:var(--b);background:var(--aqs)}
.sum a.s-pending b{color:#b45309}.sum a.s-review b{color:#0B4F9C}.sum a.s-approved b{color:var(--okt)}.sum a.s-rejected b,.sum a.s-cancelled b{color:#b91c1c}
.rq-tag.dep{background:#DDF8EC;color:#0B6B47}.rq-tag.wd{background:#FEF3C7;color:#92400E}
.rq2 .rq-id small{font-weight:400}
.rq-sel{display:grid;grid-template-columns:1fr;gap:8px;margin:0 0 6px}
</style>"""

RQ_STATUS_CHIPS = {
    "admin": [("all", "সব"), ("pending", "অপেক্ষমাণ"), ("submitted", "জমা হয়েছে"), ("review", "যাচাইয়ে"), ("approved", "অনুমোদিত"),
              ("rejected", "রিজেক্ট"), ("cancelled", "বাতিল"), ("expired", "মেয়াদোত্তীর্ণ")],
    "user": [("all", "সব"), ("pending", "অপেক্ষমাণ"), ("review", "যাচাইয়ে / প্রসেসিং"), ("approved", "অনুমোদিত / সম্পন্ন"), ("rejected", "রিজেক্ট")]}
TX_GROUP = {"pending": ("pending",), "review": ("review", "processing"), "approved": ("approved", "paid"), "rejected": ("rejected",)}
RQ_PER = 25

RQ_HEAD = """<div class="rq-tabs">
<a class="rq-tab {{'on' if tab=='admin'}}" href="/admin/requests?tab=admin"><span class="ic">📤</span><span class="tt">অ্যাডমিন → ইউজার<small>অ্যাডমিনের পাঠানো</small></span>{% if n_admin %}<b class="n">{{n_admin}}</b>{% endif %}</a>
<a class="rq-tab {{'on' if tab=='user'}}" href="/admin/requests?tab=user"><span class="ic">📥</span><span class="tt">ইউজার → অ্যাডমিন<small>ইউজারের জমা দেওয়া</small></span>{% if n_user %}<b class="n">{{n_user}}</b>{% endif %}</a></div>
<div class="sum">
<a class="{{'on' if tab=='admin'}}" href="/admin/requests?tab=admin"><b>{{tot_a}}</b><span>মোট অ্যাডমিন → ইউজার</span></a>
<a class="{{'on' if tab=='user'}}" href="/admin/requests?tab=user"><b>{{tot_u}}</b><span>মোট ইউজার → অ্যাডমিন</span></a>
{% for k,l in cards %}<a class="s-{{k}} {{'on' if st==k}}" href="/admin/requests?tab={{tab}}&status={{k}}"><b>{{cnt[k]}}</b><span>{{l}}</span></a>{% endfor %}</div>
<div class="k" style="margin:-4px 0 10px">স্ট্যাটাস কার্ডগুলো বর্তমান তালিকার ({{'অ্যাডমিন → ইউজার' if tab=='admin' else 'ইউজার → অ্যাডমিন'}}) জন্য — ট্যাপ করলে ফিল্টার হবে।</div>
<div class="card" style="padding:12px 14px"><div class="row" style="align-items:center"><h2 style="margin:0">{{'📤 অ্যাডমিন → ইউজার রিকোয়েস্ট' if tab=='admin' else '📥 ইউজার → অ্যাডমিন রিকোয়েস্ট'}}</h2>
{% if tab=='admin' %}<a class="btn sm g" href="/admin/requests/new" style="flex:0;white-space:nowrap">➕ নতুন</a>{% endif %}</div>
<div class="sq" style="margin-top:10px"><input id="rq" type="search" inputmode="search" enterkeyhint="search" autocomplete="off" value="{{q}}" placeholder="{{ph}}"></div>
<div class="chips" id="rf2">{% for k,l in chips %}<button type="button" data-f="{{k}}" class="{{'on' if k==st}}">{{l}}</button>{% endfor %}</div>
<div class="rq-sel"><select id="rty">{% if tab=='admin' %}<option value="">সব ধরন</option>{% for k,l in tyopts %}<option value="{{k}}" {{'selected' if ty==k}}>{{l}}</option>{% endfor %}
{% else %}<option value="">ডিপোজিট + উইথড্র</option>{% for k,l in kopts %}<option value="{{k}}" {{'selected' if kd==k}}>{{l}}</option>{% endfor %}{% endif %}</select></div>
<div class="sq-st" id="rst"></div></div>"""

RQ_ROWS_TPL = """{% if not rows and start==0 %}<div class="card empty">{{empty}}</div>{% endif %}
{% for r in rows %}{% set sn = start + loop.index %}{% if tab=='admin' %}
<div class="rq-card rq2" data-by="admin"><span class="rq-sn">{{sn}}</span><div class="rq-b">
<a class="rq-main" href="/admin/requests/{{r['id']}}"><div class="rq-t"><b class="rq-id">{{r['order_id']}} <small class="k">#{{r['id']}}</small></b><span class="pill {{r['status']}}">{{labels[r['status']]}}</span></div>
<div class="rq-u">{{r['name']}} · Member #{{r['member_id']}} · 📱 {{r['phone']}}</div>
<div class="rq-m"><span class="rq-ty"><span class="rq-tag {{rtag(r)}}">{{rk(r)}}</span> {{r['method']}}</span><b class="rq-am">৳ {{money(r['amount'])}}</b></div>
{% if r['commission'] %}<div class="rq-d">🎁 কমিশন ({{'%g'|format(r['commission_rate'] or 0)}}%): ৳{{money(r['commission'])}}</div>{% endif %}
<div class="rq-d">📅 {{r['created'][:16]}} · {% if r['expires_at'] %}⏳ মেয়াদ: {{r['expires_at'][:16]}} UTC{% else %}⏳ মেয়াদ নেই{% endif %}{% if r['trx'] %} · TrxID: {{r['trx']}}{% endif %}{% if r['screenshot'] %} · 🖼{% endif %}</div></a>
<div class="rq-acts"><a class="btn sm" href="/admin/requests/{{r['id']}}">⚙ দেখুন / ম্যানেজ</a>""" + REQ_BTNS + """</div></div></div>
{% else %}
<div class="rq-card rq2" data-by="user"><span class="rq-sn">{{sn}}</span><div class="rq-b">
<a class="rq-main" href="/admin/requests/user/{{r['id']}}"><div class="rq-t"><b class="rq-id">{{'DEP' if r['kind']=='deposit' else 'WD'}}-{{'%05d'|format(r['id'])}} <small class="k">#{{r['id']}}</small></b><span class="pill {{r['status']}}">{{txl.get(r['status'], r['status'])}}</span></div>
<div class="rq-u">{{r['name']}} · Member #{{r['member_id']}} · 📱 {{r['phone']}}</div>
<div class="rq-m"><span class="rq-ty"><span class="rq-tag {{'dep' if r['kind']=='deposit' else 'wd'}}">{{kinds[r['kind']]}}</span> 💳 {{r['method']}}{% if r['number'] %} {{r['number']}}{% endif %}</span><b class="rq-am">৳ {{money(r['amount'])}}</b></div>
<div class="rq-d">📅 {{r['created'][:16]}}{% if r['trx'] %} · TrxID: {{r['trx']}}{% endif %}{% if r['screenshot'] %} · 🖼{% endif %}</div></a>
<div class="rq-acts"><a class="btn sm" href="/admin/requests/user/{{r['id']}}">⚙ দেখুন / ম্যানেজ</a>{% for a,l,c in acts[r['kind']] %}{% if r['status'] in a %}<button type="button" class="btn sm {{c}}" data-do="{{l[0]}}" data-u="/admin/tx/{{r['id']}}" data-c="{{c}}" data-t="{{l[1]}}" data-need="0" data-m="{{tnote(r,l[0])}}">{{l[1]}}</button>{% endif %}{% endfor %}</div></div></div>
{% endif %}{% endfor %}
{% if more %}<button type="button" class="btn s rq-more" data-next="{{p+1}}" style="width:100%;margin-bottom:10px">আরও দেখান</button>{% endif %}"""


def rtag(r):
    """'dep' / 'wd' colour class of an admin-created request (the app's own deposit/withdraw naming)."""
    return "dep" if (r["flow"] == "client_confirm" or (not r["flow"] and r["kind"] == "deposit")) else "wd"


def _rq_kinds(u=None):
    return [k for k, p in KIND_PERM.items() if has_perm(p, u)]


def _rq_rows(tab, st, q, ty, kd, p):
    """One page of a request list (LIMIT/OFFSET, newest first). Returns (rows, more, status). Permissions: the user->admin list only ever
    contains the transaction kinds (deposits / withdrawals) the signed-in staff member may handle."""
    like, where, args = "%" + q + "%", [], []
    p = min(max(p, 1), 2000)
    if tab == "admin":
        if st == "open":
            where.append("r.status IN ('submitted','review')")
        elif st in REQ_LABEL:
            where.append("r.status=?"); args.append(st)
        else:
            st = "all"
        if kd in REQ_KIND:
            where.append("r.kind=?"); args.append(kd)
        if ty in REQ_TYPES:
            tk, tf = REQ_TYPES[ty]
            where.append("r.kind=?"); args.append(tk)
            if tf:
                where.append("r.flow=?"); args.append(tf)
            else:
                where.append("COALESCE(r.flow,'')=''")
        if q:
            cond, qx = "r.order_id LIKE ? OR u.name LIKE ? OR u.phone LIKE ? OR u.member_id LIKE ? OR r.trx LIKE ?", [like] * 5
            if q.isdigit() and len(q) <= 12:
                cond += " OR r.id=?"; qx.append(int(q))
            where.append("(" + cond + ")"); args += qx
        wh = (" WHERE " + " AND ".join(where)) if where else ""
        rows = qa("SELECT r.*,u.name,u.phone,u.member_id FROM requests r JOIN users u ON u.id=r.user_id%s ORDER BY r.id DESC LIMIT ? OFFSET ?" % wh,
                  args + [RQ_PER + 1, (p - 1) * RQ_PER])
        return rows[:RQ_PER], len(rows) > RQ_PER, st
    ks = [kd] if kd in _rq_kinds() else _rq_kinds()
    if not ks:
        return [], False, "all"
    where.append("t.kind IN (%s)" % ",".join("?" * len(ks))); args += ks
    if st == "open":
        parts = []
        for k in ks:
            parts.append("(t.kind=? AND t.status IN (%s))" % ",".join("?" * len(TX_OPEN[k]))); args += [k] + list(TX_OPEN[k])
        where.append("(" + " OR ".join(parts) + ")")
    elif st in TX_GROUP:
        where.append("t.status IN (%s)" % ",".join("?" * len(TX_GROUP[st]))); args += list(TX_GROUP[st])
    elif st in TX_LABEL:
        where.append("t.status=?"); args.append(st)
    else:
        st = "all"
    if q:
        m = re.fullmatch(r"(?i)(dep|wd)-?0*(\d+)", q)
        if m:
            where.append("(t.id=? AND t.kind=?)"); args += [int(m.group(2)), "deposit" if m.group(1).lower() == "dep" else "withdraw"]
        else:
            cond, qx = "u.name LIKE ? OR u.phone LIKE ? OR u.member_id LIKE ? OR t.trx LIKE ? OR t.number LIKE ?", [like] * 5
            if q.isdigit() and len(q) <= 12:
                cond += " OR t.id=?"; qx.append(int(q))
            where.append("(" + cond + ")"); args += qx
    rows = qa("SELECT t.*,u.name,u.phone,u.member_id FROM tx t JOIN users u ON u.id=t.user_id WHERE %s ORDER BY t.id DESC LIMIT ? OFFSET ?" % " AND ".join(where),
              args + [RQ_PER + 1, (p - 1) * RQ_PER])
    return rows[:RQ_PER], len(rows) > RQ_PER, st


def _rq_frag(tab, st, q, ty, kd, p, conv):
    rows, more, st = _rq_rows(tab, st, q, ty, kd, p)
    html = _frag(RQ_ROWS_TPL, _conv=conv, rows=rows, more=more, p=p, start=(p - 1) * RQ_PER, tab=tab, rk=req_label, rtag=rtag, ra=req_actions,
                 rbtn=RQ_BTN, rnote=req_note, tnote=tx_note, txl=TX_LABEL, kinds=REQ_KIND, acts=ACTIONS,
                 empty="কোনো রিকোয়েস্ট পাওয়া যায়নি" if _rq_kinds() or tab == "admin" else "এই তালিকা দেখার অনুমতি নেই")
    return html, rows, st


@app.route("/admin/requests/list")
@staff_required("requests")
def admin_requests_list():
    """HTML fragment (live search / filters / 'show more') of the two request lists."""
    tab = "user" if request.args.get("tab") == "user" else "admin"
    if tab == "admin":
        expire_requests()
    p = min(max(request.args.get("p", type=int) or 1, 1), 2000)
    html, _r, _s = _rq_frag(tab, request.args.get("status", "all"), _clean_q(request.args.get("q", "")), request.args.get("ty", ""), request.args.get("kind", ""), p, True)
    r = Response(html, mimetype="text/html")
    r.headers["Cache-Control"] = "no-store"
    return r


def _rq_summary(tab):
    """Counts for the summary cards (grouped, one query per category)."""
    ca = {r["status"]: r["n"] for r in qa("SELECT status, COUNT(*) n FROM requests GROUP BY status")}
    ks = _rq_kinds()
    cu = {}
    if ks:
        cu = {r["status"]: r["n"] for r in qa("SELECT status, COUNT(*) n FROM tx WHERE kind IN (%s) GROUP BY status" % ",".join("?" * len(ks)), ks)}
    tot_a, tot_u = sum(ca.values()), sum(cu.values())
    if tab == "admin":
        cnt = {k: ca.get(k, 0) for k in ("pending", "review", "approved", "rejected", "cancelled")}
    else:
        cnt = {"pending": cu.get("pending", 0), "review": cu.get("review", 0) + cu.get("processing", 0), "approved": cu.get("approved", 0) + cu.get("paid", 0),
               "rejected": cu.get("rejected", 0), "cancelled": 0}
    n_admin = ca.get("submitted", 0) + ca.get("review", 0)
    n_user = 0
    for k in ks:
        n_user += q1("SELECT COUNT(*) n FROM tx WHERE kind=? AND status IN (%s)" % ",".join("?" * len(TX_OPEN[k])), (k,) + TX_OPEN[k])["n"]
    return tot_a, tot_u, cnt, n_admin, n_user


@app.route("/admin/requests")
@staff_required("requests")
def admin_requests():
    expire_requests()
    tab = "user" if request.args.get("tab") == "user" else "admin"
    st, kd, ty = request.args.get("status", "all"), request.args.get("kind", ""), request.args.get("ty", "")
    q = _clean_q(request.args.get("q", ""))
    p = min(max(request.args.get("p", type=int) or 1, 1), 2000)
    t0 = now()
    html, rows, st = _rq_frag(tab, st, q, ty, kd, p, False)
    tot_a, tot_u, cnt, n_admin, n_user = _rq_summary(tab)
    if tab == "admin" and not q and not kd and not ty and st in ("open", "all") and p == 1:
        shown = {"/admin/requests/%d" % r["id"] for r in rows}
        every = len(rows) < RQ_PER
        alerts_seen(lambda link, ts: _admin_badge_key(link) == "/admin/requests" and ((every and ts < t0) or link in shown))
    chips = RQ_STATUS_CHIPS[tab]
    if st not in {k for k, _ in chips}:
        st = "all" if st != "open" else "open"
    return page(RQ_STYLE + RQ2_STYLE + DESK_STYLE + RQ_HEAD + """<div id="rl">{{rl|safe}}</div>""" + ACT_MODAL + """
<script>(function(){var box=document.getElementById('rl'),inp=document.getElementById('rq'),chips=document.getElementById('rf2'),sel=document.getElementById('rty'),stt=document.getElementById('rst');
if(!box||!inp)return;var TAB={{tab|tojson}},f=(chips.querySelector('button.on')||{dataset:{f:{{st|tojson}}}}).dataset.f,tm=null,seq=0;
function qs(p){return 'tab='+TAB+'&status='+encodeURIComponent(f)+'&'+(TAB==='admin'?'ty':'kind')+'='+encodeURIComponent(sel.value)+'&q='+encodeURIComponent(inp.value.trim())+(p?'&p='+p:'')}
function sync(){try{history.replaceState(null,'','/admin/requests?'+qs(0))}catch(e){}}
function load(p,append,btn){var my=++seq;stt.textContent='খুঁজছে…';fetch('/admin/requests/list?'+qs(p),{credentials:'same-origin'}).then(function(r){if(!r.ok)throw 0;return r.text()}).then(function(h){if(my!==seq)return;
 if(append){if(btn)btn.remove();box.insertAdjacentHTML('beforeend',h)}else box.innerHTML=h;stt.textContent=''}).catch(function(){if(my===seq){stt.textContent='লোড করা যায়নি — আবার চেষ্টা করুন';if(btn)btn.disabled=false}})}
inp.addEventListener('input',function(){clearTimeout(tm);tm=setTimeout(function(){sync();load(1,false)},250)});
inp.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();clearTimeout(tm);sync();load(1,false);inp.blur()}});
chips.addEventListener('click',function(e){var b=e.target.closest('button[data-f]');if(!b)return;chips.querySelectorAll('button').forEach(function(x){x.classList.toggle('on',x===b)});f=b.dataset.f;sync();load(1,false)});
sel.addEventListener('change',function(){sync();load(1,false)});
box.addEventListener('click',function(e){var b=e.target.closest('.rq-more');if(!b)return;b.disabled=true;load(+b.dataset.next,true,b)})})()</script>""",
                active="/admin/requests", rl=html, tab=tab, st=st, q=q, ty=ty, kd=kd, n_admin=n_admin, n_user=n_user, tot_a=tot_a, tot_u=tot_u, cnt=cnt, chips=chips,
                cards=[("pending", "অপেক্ষমাণ"), ("review", "যাচাইয়ে"), ("approved", "অনুমোদিত"), ("rejected", "রিজেক্ট"), ("cancelled", "বাতিল")],
                tyopts=[(k, TYPE_LABEL[k]) for k in ("client_confirm", "admin_review", "deposit", "withdraw")],
                kopts=[(k, REQ_KIND[k]) for k in _rq_kinds()],
                ph="Request ID / Member ID / নাম / ফোন / TrxID")


@app.route("/admin/requests/<int:i>/note", methods=["POST"])
@staff_required("requests")
def admin_request_note(i):
    """Internal admin note (never shown to the user). Stored as an immutable request_log row + audit entry."""
    a = me()
    note = request.form.get("note", "").strip()[:300]
    back_to = "/admin/requests/%d" % i
    if len(note) < 2:
        err("নোট লিখুন।"); return redirect(back_to)
    if rate_hit("rqn:%d" % a["id"], 60, 3600):
        err("অনেক নোট যোগ হয়েছে, পরে চেষ্টা করুন।"); return redirect(back_to)
    with atomic():
        r = q1("SELECT id,status,order_id FROM requests WHERE id=?", (i,))
        if not r:
            abort(404)
        req_log(i, "note", r["status"], r["status"], a["member_id"], a["id"], note)
        audit("req_note", "req#%d order=%s admin_id=%d" % (i, r["order_id"], a["id"]))
    flash("নোট সংরক্ষিত হয়েছে (ইউজার দেখতে পাবে না)।")
    return redirect(back_to)


@app.route("/admin/requests/user/<int:i>/note", methods=["POST"])
@staff_required("requests")
def admin_request_user_note(i):
    a = me()
    note = request.form.get("note", "").strip()[:300]
    back_to = "/admin/requests/user/%d" % i
    t = q1("SELECT id,kind FROM tx WHERE id=?", (i,))
    if not t or t["kind"] not in KIND_PERM:
        abort(404)
    if not has_perm(KIND_PERM[t["kind"]], a):
        abort(403)
    if len(note) < 2:
        err("নোট লিখুন।"); return redirect(back_to)
    if rate_hit("rqn:%d" % a["id"], 60, 3600):
        err("অনেক নোট যোগ হয়েছে, পরে চেষ্টা করুন।"); return redirect(back_to)
    with atomic():
        audit("tx_note", "tx#%d %s" % (i, note))
    flash("নোট সংরক্ষিত হয়েছে (ইউজার দেখতে পাবে না)।")
    return redirect(back_to)


def _related_money(ref_type, ref_id, uid):
    """Wallet / pool entries produced by this request (read-only) + the user's latest ledger lines for context."""
    led = qa("SELECT kind,amount,note,actor,created FROM ledger WHERE ref_type=? AND ref_id=? ORDER BY id", (ref_type, ref_id))
    pool = qa("SELECT kind,amount,actor,created FROM pool_ledger WHERE ref_type=? AND ref_id=? ORDER BY id", (ref_type, ref_id)) if has_perm("pool_view") else []
    recent = qa("SELECT kind,amount,created FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 5", (uid,)) if (has_perm("dashboard_fin") or has_perm("users_manage")) else []
    return led, pool, recent


MONEY_TPL = """<div class="card"><h3 style="margin-top:0">💰 সংশ্লিষ্ট ওয়ালেট / লেনদেন</h3><div class="k">ইউজারের বর্তমান ব্যালেন্স: <b>৳ {{money(bal)}}</b> · <a href="/admin/users/{{uid}}#tx"><b>সব লেনদেন →</b></a></div>
{% if led %}<div class="tw"><table><tr><th>ধরন</th><th>৳</th><th>কে</th><th>সময়</th></tr>{% for l in led %}<tr><td>{{l['kind']}}</td><td>{{money(l['amount'])}}</td><td>{{l['actor']}}</td><td>{{l['created'][:16]}}</td></tr>{% endfor %}</table></div>
{% else %}<div class="k" style="margin-top:6px">এই রিকোয়েস্টের কোনো লেজার এন্ট্রি নেই — লেজারে এন্ট্রি হয় কেবল অ্যাপ্রুভ/কনফার্মের সময়।</div>{% endif %}
{% if pool %}<div class="k" style="margin-top:8px">কমিশন পুল এন্ট্রি</div><div class="tw"><table>{% for l in pool %}<tr><td>{{l['kind']}}</td><td>{{money(l['amount'])}}</td><td>{{l['actor']}}</td><td>{{l['created'][:16]}}</td></tr>{% endfor %}</table></div>{% endif %}
{% if recent %}<div class="k" style="margin-top:8px">ইউজারের সর্বশেষ লেজার</div><div class="tw"><table>{% for l in recent %}<tr><td>{{l['kind']}}</td><td>{{money(l['amount'])}}</td><td>{{l['created'][:16]}}</td></tr>{% endfor %}</table></div>{% endif %}</div>"""

NOTES_TPL = """<div class="card"><h3 style="margin-top:0">📝 অভ্যন্তরীণ নোট <span class="k">(ইউজার দেখতে পায় না)</span></h3>
<form method="post" action="{{note_url}}"><input type="hidden" name="_csrf" value="{{csrf_token}}"><textarea name="note" rows="2" maxlength="300" required minlength="2" placeholder="নোট লিখুন"></textarea><button style="width:100%">💾 নোট সংরক্ষণ</button></form>
{% for n in notes %}<div class="pf-act"><span>📝</span><span style="flex:1;min-width:0;overflow-wrap:anywhere">{{n['text']}}<br><span class="k">{{n['actor']}}</span></span><span class="k">{{n['created'][:16]}}</span></div>{% endfor %}</div>"""

TIMELINE_TPL = """<div class="card"><h3 style="margin-top:0">🕘 স্ট্যাটাস ইতিহাস (কে · কী · কখন · কেন)</h3>
{% for l in log %}<div class="pf-act"><span>{{'✏️' if l['action']=='edit' else ('✅' if l['action'] in ('approve','client_approve') else ('❌' if l['action'] in ('reject','client_reject') else ('🚫' if l['action'] in ('cancel','expire') else '•')))}}</span>
<span style="flex:1;min-width:0;overflow-wrap:anywhere"><b>{{l['action']}}</b>{% if l['from_status'] or l['to_status'] %} · {{l['from_status'] or '-'}} → {{l['to_status'] or '-'}}{% endif %} · {{l['actor'] or 'system'}}{% if l['note'] %}<br><span class="k">{{l['note']}}</span>{% endif %}</span><span class="k">{{l['created'][:16]}}</span></div>
{% else %}<div class="k">এখনো কোনো ইতিহাস নেই।</div>{% endfor %}</div>"""


@app.route("/admin/requests/user/<int:i>")
@staff_required("requests")
def admin_request_user_view(i):
    """Details of a user-submitted deposit/withdrawal. Processing still goes through the existing /admin/tx/<id> action."""
    u = me()
    t = q1("SELECT t.*,u.name,u.phone,u.member_id,u.balance FROM tx t JOIN users u ON u.id=t.user_id WHERE t.id=?", (i,))
    if not t or t["kind"] not in KIND_PERM:
        abort(404)
    if not has_perm(KIND_PERM[t["kind"]], u):
        abort(403)
    hist_all = qa("SELECT actor,action,detail,created FROM audit WHERE SUBSTR(action,1,3)='tx_' AND detail LIKE ? ORDER BY id", ("tx#%d %%" % i,))
    hist = [{"action": h["action"][3:], "from_status": None, "to_status": None, "actor": h["actor"], "note": None, "created": h["created"]} for h in hist_all if h["action"] != "tx_note"]
    notes = [{"text": (h["detail"] or "")[len("tx#%d " % i):], "actor": h["actor"], "created": h["created"]} for h in reversed(hist_all) if h["action"] == "tx_note"]
    led, pool, recent = _related_money("tx", i, t["user_id"])
    pns = qa("SELECT * FROM payment_numbers WHERE user_id=? ORDER BY id", (t["user_id"],)) if has_perm("payment_numbers") else []
    return page(RQ_STYLE + DESK_STYLE + RD_STYLE + """<div class="rd"><div class="card"><div class="row" style="align-items:center;justify-content:space-between"><h2>{{kinds[t['kind']]}} রিকোয়েস্ট</h2>
<span class="pill {{t['status']}}" style="flex:0;white-space:nowrap">{{txl.get(t['status'], t['status'])}}</span></div>
<div class="rq-amt">৳ {{money(t['amount'])}}</div>
<dl class="rq-dl">
<div><dt>Order ID</dt><dd><b>{{'DEP' if t['kind']=='deposit' else 'WD'}}-{{'%05d'|format(t['id'])}}</b></dd></div>
<div><dt>ইউজার</dt><dd><a href="/admin/users/{{t['user_id']}}">{{t['name']}} · #{{t['member_id']}}</a><br><span class="k">{{t['phone']}} · ব্যালেন্স ৳ {{money(t['balance'])}}</span></dd></div>
<div><dt>ধরন</dt><dd>{{kinds[t['kind']]}}</dd></div>
<div><dt>পেমেন্ট মাধ্যম</dt><dd>{{t['method']}}</dd></div>
<div><dt>পেমেন্ট নম্বর</dt><dd>{{t['number'] or '—'}}</dd></div>
<div><dt>পরিমাণ</dt><dd>৳ {{money(t['amount'])}}</dd></div>
<div><dt>Transaction ID</dt><dd>{{t['trx'] or '—'}}</dd></div>
<div><dt>জমা দেওয়ার সময়</dt><dd>{{t['created'][:16]}}</dd></div>
<div><dt>সর্বশেষ আপডেট</dt><dd>{{(t['updated'] or t['created'])[:16]}}</dd></div>
<div><dt>বর্তমান অবস্থা</dt><dd>{{txl.get(t['status'], t['status'])}}</dd></div>
{% if t['note'] %}<div><dt>নোট</dt><dd>{{t['note']}}</dd></div>{% endif %}</dl>
{% if t['screenshot'] %}<div class="k" style="margin-top:8px">স্ক্রিনশট</div><a href="/shot/{{t['screenshot']}}" target="_blank"><img class="shot" src="/shot/{{t['screenshot']}}" alt="screenshot"></a>{% endif %}</div>
{% if t['status'] in open_st %}<div class="card"><h3 style="margin-top:0">কাজ</h3><div class="row" style="gap:8px">{% for a,l,c in acts[t['kind']] %}{% if t['status'] in a %}<button type="button" class="btn sm {{c}}" data-do="{{l[0]}}" data-u="/admin/tx/{{t['id']}}" data-c="{{c}}" data-t="{{l[1]}}" data-need="0" data-m="{{tnote(t,l[0])}}">{{l[1]}}</button>{% endif %}{% endfor %}</div></div>{% endif %}
{% if can('payment_numbers') %}<div class="card"><h3 style="margin-top:0">💳 {{t['name']}} এর নিবন্ধিত পেমেন্ট নম্বর</h3>{% if not pns %}<div class="k">কোনো নম্বর যোগ করা নেই</div>{% endif %}</div>
{% set hl = t['number'] %}{% set hm = t['method'] %}{% set send_uid = none %}""" + PM_CARDS_TPL + """{% endif %}
<div class="row" style="gap:8px;margin-bottom:10px"><a class="btn sm s" href="/admin/users/{{t['user_id']}}">👤 ইউজার প্রোফাইল</a><a class="btn sm s" href="/admin/requests?tab=user&q={{t['member_id']}}&status=all">📚 এই ইউজারের সব রিকোয়েস্ট</a></div>""" + MONEY_TPL + TIMELINE_TPL.replace("{{l['created'][:16]}}", "{{l['created'][:16]}}") + NOTES_TPL + """
<a class="btn s" href="/admin/requests?tab=user" style="width:100%">← সব রিকোয়েস্ট</a></div>""" + ACT_MODAL, active="/admin/requests", t=t, hist=hist, kinds=REQ_KIND, txl=TX_LABEL,
                open_st=TX_OPEN[t["kind"]], acts=ACTIONS, pns=pns, tnote=tx_note, log=hist, notes=notes, led=led, pool=pool, recent=recent,
                bal=t["balance"], uid=t["user_id"], note_url="/admin/requests/user/%d/note" % i)


@app.route("/admin/requests/<int:i>")
@staff_required("requests")
def admin_request_view(i):
    expire_requests()
    r = q1("SELECT r.*,u.name,u.phone,u.member_id,u.balance,u.blocked FROM requests r JOIN users u ON u.id=r.user_id WHERE r.id=?", (i,))
    if not r:
        abort(404)
    log = qa("SELECT * FROM request_log WHERE request_id=? AND action<>'note' ORDER BY id", (i,))
    notes = [{"text": n["note"], "actor": n["actor"], "created": n["created"]} for n in qa("SELECT * FROM request_log WHERE request_id=? AND action='note' ORDER BY id DESC", (i,))]
    led, pool, recent = _related_money("request", i, r["user_id"])
    le = q1("SELECT actor,created FROM request_log WHERE request_id=? AND action='edit' ORDER BY id DESC LIMIT 1", (i,))
    pns = qa("SELECT * FROM payment_numbers WHERE user_id=? ORDER BY id", (r["user_id"],)) if has_perm("payment_numbers") else []
    alerts_seen(lambda link, ts: link == "/admin/requests/%d" % i)
    return page(RQ_STYLE + DESK_STYLE + RD_STYLE + """<div class="rd"><div class="card"><div class="row" style="align-items:center;justify-content:space-between"><h2>{{rk(r)}}</h2>
<span class="pill {{r['status']}}" style="flex:0;white-space:nowrap">{{labels[r['status']]}}</span></div>
<div class="rq-amt">৳ {{money(r['amount'])}}</div>
<dl class="rq-dl">
<div><dt>Order ID</dt><dd><b>{{r['order_id']}}</b></dd></div>
<div><dt>ইউজার</dt><dd><a href="/admin/users/{{r['user_id']}}">{{r['name']}} · #{{r['member_id']}}</a><br><span class="k">{{r['phone']}} · ব্যালেন্স ৳ {{money(r['balance'])}}</span></dd></div>
<div><dt>ধরন</dt><dd>{{kinds[rdt(r)]}}</dd></div>
<div><dt>পেমেন্ট মাধ্যম</dt><dd>{{r['method']}}</dd></div>
<div><dt>পেমেন্ট নম্বর</dt><dd>{{r['pay_number']}}</dd></div>
{% if r['pay_type'] %}<div><dt>পেমেন্ট টাইপ</dt><dd>{{ptl.get(r['pay_type'], r['pay_type'])}}</dd></div>{% endif %}
<div><dt>পরিমাণ</dt><dd>৳ {{money(r['amount'])}}</dd></div>
<div><dt>Transaction ID</dt><dd>{{r['trx'] or '—'}}{% if r['submitted_at'] %}<br><span class="k">(জমা: {{(r['submitted_at'] or '')[:16]}})</span>{% endif %}</dd></div>
<div><dt>তৈরি</dt><dd>{{r['created'][:16]}}<br><span class="k">📤 অ্যাডমিন: {{r['created_by']}}</span></dd></div>
{% if r['expires_at'] %}<div><dt>মেয়াদ</dt><dd>{{r['expires_at'][:16]}} UTC</dd></div>{% endif %}
<div><dt>সর্বশেষ আপডেট</dt><dd>{{(r['updated'] or r['created'])[:16]}}</dd></div>
{% if le %}<div><dt>সর্বশেষ সম্পাদনা</dt><dd>{{le['actor']}}<br><span class="k">{{le['created'][:16]}}</span></dd></div>{% endif %}</dl>
{% if r['flow'] %}<div class="hl" style="margin-top:6px"><b>{{rk(r)}}</b> · মূল ৳{{money(r['amount'])}} · কমিশন ({{'%g'|format(r['commission_rate'] or 0)}}%) ৳{{money(r['commission'] or 0)}}{% if r['purpose'] %}<br>উদ্দেশ্য: {{r['purpose']}}{% endif %}{% if r['purpose_en'] %}<br>Purpose: {{r['purpose_en']}}{% endif %}<br>
{% if r['flow']=='client_confirm' %}ক্লায়েন্টের সিদ্ধান্তের অপেক্ষা — অ্যাডমিন অ্যাপ্রুভ/রিজেক্ট করতে পারবে না (শুধু বাতিল)।{% else %}অ্যাপ্রুভ করলে ওয়ালেটে যোগ: ৳{{money(r['amount']+(r['commission'] or 0))}}{% endif %}</div>
{% if r['flow']=='admin_review' and r['status'] in ('submitted','review') and (r['commission'] or 0) > pool_av %}<div class="msg error" style="margin-top:8px">⚠ কমিশন পুলে পর্যাপ্ত ফান্ড নেই — অ্যাপ্রুভ করা যাবে না (উপলব্ধ ৳{{money(pool_av)}}) — আগে পুলে ফান্ড যোগ করুন।</div>{% endif %}{% endif %}
{% if r['instructions'] %}<div class="k" style="margin-top:8px">নোট / নির্দেশনা</div><div class="hl" style="margin-top:2px">{{r['instructions']}}</div>{% endif %}
{% if r['screenshot'] %}<div class="k" style="margin-top:8px">স্ক্রিনশট</div><a href="/shot/{{r['screenshot']}}" target="_blank"><img class="shot" src="/shot/{{r['screenshot']}}" alt="screenshot"></a>{% endif %}
{% if r['decided_by'] %}<div class="k">সিদ্ধান্ত: {{r['decided_by']}} · {{(r['decided_at'] or '')[:16]}}{% if r['reject_reason'] %} · {{r['reject_reason']}}{% endif %}</div>{% endif %}
{% if r['extra_commission'] %}<div class="hl" style="margin-top:8px">➕ এক্সট্রা কমিশন (Agent Cash Out): ৳{{money(r['extra_commission'])}} — মূল ৳{{money(r['amount'])}} + কমিশন ৳{{money(r['commission'] or 0)}} + এক্সট্রা ৳{{money(r['extra_commission'])}} = মোট ৳{{money((r['amount'] or 0)+(r['commission'] or 0)+(r['extra_commission'] or 0))}} ওয়ালেটে যুক্ত হয়েছে।</div>{% endif %}
{% if r['cancel_by']=='user' %}<div class="hl" style="margin-top:8px">🚫 ইউজার নিজে বাতিল করেছেন — বাতিল ফি ৳{{money(r['cancel_fee'] or 0)}} ইউজারের ওয়ালেট থেকে কাটা হয়েছে।</div>{% elif r['cancel_by']=='admin' %}<div class="hl" style="margin-top:8px">🚫 অ্যাডমিন বাতিল করেছেন — কোনো ফি বা কমিশন কাটা হয়নি।</div>{% endif %}
{% if xc_ok(r) %}<div class="hl" style="margin-top:8px">ℹ Agent Cash Out: অ্যাপ্রুভ করার সময় ঐচ্ছিক “এক্সট্রা কমিশন” দিয়ে এজেন্টের Cash Out ফি-এর ক্ষতিপূরণ ইউজারকে দিতে পারবেন।</div>{% endif %}
{% if r['kind']=='withdraw' and r['status'] in ('submitted','review') and r['balance'] < r['amount'] %}<div class="msg error" style="margin-top:8px">⚠ ইউজারের বর্তমান ব্যালেন্স অনুরোধের চেয়ে কম — অ্যাপ্রুভ করা যাবে না।</div>{% endif %}</div>
{% set al = ra(r) %}
{% if al %}<div class="card"><h3 style="margin-top:0">কাজ</h3><div class="row" style="gap:8px">{% for a in al %}{% if a=='edit' %}<a class="btn sm s" href="/admin/requests/{{r['id']}}/edit">✏️ সম্পাদনা</a>
{% else %}<button type="button" class="btn sm {{rbtn[a][1]}}" data-do="{{a}}" data-u="/admin/requests/{{r['id']}}/act" data-c="{{rbtn[a][1]}}" data-t="{{rbtn[a][0]}}" data-need="{{1 if a in ('reject','cancel') else 0}}" data-m="{{rnote(r,a)}}"{% if a=='approve' and xc_ok(r) %} data-extra="1"{% endif %}>{{rbtn[a][0]}}</button>{% endif %}{% endfor %}</div>
<div class="k" style="margin-top:8px">সম্পাদনা শুধু মাধ্যম, নম্বর, উদ্দেশ্য, নোট ও মেয়াদে। পরিমাণ ও কমিশন বদলানো যায় না। প্রতিটি কাজের কারণ ও কে করেছেন তা ইতিহাসে স্থায়ীভাবে থাকে।</div></div>
{% else %}<div class="card"><div class="hl rq-lock">🔒 এই রিকোয়েস্ট সম্পন্ন/বন্ধ — এটি আর সম্পাদনা করা যায় না এবং লেজারের কোনো এন্ট্রি বদলানো হয় না।
{% if r['status']=='approved' and can('adjust') %}<br>ভুল হলে <a href="/admin/users/{{r['user_id']}}"><b>ইউজার প্রোফাইল → ব্যালেন্স সমন্বয়</b></a> দিয়ে নতুন সংশোধন এন্ট্রি যোগ করুন (পুরনো এন্ট্রি অপরিবর্তিত থাকে)।{% endif %}</div></div>{% endif %}
<div class="card"><h3 style="margin-top:0">⚠ ইউজারকে সতর্কবার্তা</h3>
<form method="post" action="/admin/warnings/new" data-confirm="সতর্কবার্তা ইউজারকে পাঠাবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="uid" value="{{r['user_id']}}"><input type="hidden" name="request_id" value="{{r['id']}}"><input type="hidden" name="next" value="/admin/requests/{{r['id']}}">
<textarea name="message" rows="3" required minlength="5" maxlength="500" placeholder="যেমন: Repeated cancellation of requests may result in temporary transaction restrictions."></textarea><button style="width:100%">⚠ সতর্কবার্তা পাঠান</button></form>
<div class="k" style="margin-top:6px">সতর্কবার্তা ইউজার নোটিফিকেশনে ও অনুরোধের পেজে দেখবেন। শুধু সতর্কবার্তায় কোনো লেনদেন সীমাবদ্ধ হয় না — সীমাবদ্ধতার জন্য আলাদা অনুমোদিত অ্যাকশন (ইউজার ব্লক) লাগবে।</div>
{% for w in warns %}<div class="pf-act"><span>⚠</span><span style="flex:1;min-width:0;overflow-wrap:anywhere;white-space:pre-line">{{w['message']}}<br><span class="k">{{w['admin']}} · {{'এই রিকোয়েস্ট' if w['request_id'] else 'ইউজার-লেভেল'}}</span></span><span class="k">{{w['created'][:16]}}</span></div>{% endfor %}</div>
{% if can('payment_numbers') and not is_wd(r['kind'], r['flow']) %}<div class="card"><h3 style="margin-top:0">💳 {{r['name']}} এর নিবন্ধিত পেমেন্ট নম্বর</h3>{% if not pns %}<div class="k">কোনো নম্বর যোগ করা নেই</div>{% endif %}</div>
{% set hl = r['pay_number'] %}{% set hm = r['method'] %}{% set send_uid = none %}""" + PM_CARDS_TPL + """{% endif %}
<div class="row" style="gap:8px;margin-bottom:10px"><a class="btn sm s" href="/admin/users/{{r['user_id']}}">👤 ইউজার প্রোফাইল</a><a class="btn sm s" href="/admin/requests?tab=admin&q={{r['member_id']}}&status=all">📚 এই ইউজারের সব রিকোয়েস্ট</a>{% if not r['blocked'] %}<a class="btn sm" href="/admin/requests/new?uid={{r['user_id']}}">➕ নতুন রিকোয়েস্ট</a>{% endif %}</div>
""" + MONEY_TPL + TIMELINE_TPL + NOTES_TPL + """
<a class="btn s" href="/admin/requests?tab=admin" style="width:100%">← সব রিকোয়েস্ট</a></div>""" + ACT_MODAL, active="/admin/requests", r=r, log=log, le=le, kinds=REQ_KIND, labels=REQ_LABEL,
                pool_av=pool_available(exclude=i), pns=pns, ra=req_actions, rbtn=RQ_BTN, rnote=req_note, warns=warnings_for(r["user_id"], i, 20),
                notes=notes, led=led, pool=pool, recent=recent, bal=r["balance"], uid=r["user_id"], note_url="/admin/requests/%d/note" % i)


@app.route("/admin/requests/<int:i>/edit", methods=["GET", "POST"])
@staff_required("requests")
def admin_request_edit(i):
    """Edit an admin-created request (table `requests`) until it is completed. Never touches amount, commission, ledger or balances.
    Every change is written to the immutable request_log (who / when / old -> new / why) and to the audit trail; the user is notified."""
    a = me()
    expire_requests()
    r = q1("SELECT r.*,u.name,u.member_id FROM requests r JOIN users u ON u.id=r.user_id WHERE r.id=?", (i,))
    if not r:
        abort(404)
    back_to = "/admin/requests/%d" % i
    if r["status"] not in REQ_EDIT_OPEN:
        err("এই রিকোয়েস্ট আর সম্পাদনা করা যাবে না (সম্পন্ন বা বন্ধ হয়ে গেছে)।"); return redirect(back_to)
    cc = r["flow"] == "client_confirm"
    wd = is_wd(r["kind"], r["flow"])
    if request.method == "POST":
        pn, e = (None, None) if wd else _pn_resolve(r["user_id"], request.form.get("pn"))  # withdrawal requests never use saved numbers
        if e:
            err(e); return redirect(back_to + "/edit")
        paytype = r["pay_type"]  # the payment type can be changed only while the request is still pending (before the user pays)
        if wd and r["status"] == "pending":
            paytype = (request.form.get("pay_type") or "").strip().lower()
            if (paytype and paytype not in PAY_TYPES) or (not paytype and r["pay_type"]):
                err("সঠিক পেমেন্ট টাইপ বাছাই করুন।"); return redirect(back_to + "/edit")
        method = pn["method"] if pn else request.form.get("method", "")
        num = pn["number"] if pn else request.form.get("number", "").strip()
        ins = request.form.get("instructions", "").strip()[:500]
        purpose = request.form.get("purpose", "").strip()[:300]
        purpose_en = request.form.get("purpose_en", "").strip()[:300]
        hrs_raw = request.form.get("hours", "").strip()
        reason = request.form.get("reason", "").strip()[:200]
        if len(reason) < 3:
            err("সম্পাদনার কারণ লিখুন (কমপক্ষে ৩ অক্ষর) — এটি ইতিহাসে সংরক্ষিত হয়।"); return redirect(back_to + "/edit")
        if cc:
            num = num if PHONE_RE.fullmatch(num) else "-"
        if not (method in METHODS or (cc and method == r["method"])):
            err("সঠিক পেমেন্ট মাধ্যম বাছাই করুন।"); return redirect(back_to + "/edit")
        if not cc and not PHONE_RE.fullmatch(num):
            err("১১ ডিজিটের সঠিক পেমেন্ট নম্বর দিন।"); return redirect(back_to + "/edit")
        if hrs_raw and (not re.fullmatch(r"\d{1,3}", hrs_raw) or int(hrs_raw) > 720):
            err("মেয়াদ ০–৭২০ ঘণ্টার মধ্যে দিন।"); return redirect(back_to + "/edit")
        try:
            with atomic():
                c = q1("SELECT * FROM requests WHERE id=?", (i,))
                if not c or c["status"] not in REQ_EDIT_OPEN:
                    raise ReqError("এই রিকোয়েস্ট আর সম্পাদনা করা যাবে না (সম্পন্ন বা বন্ধ হয়ে গেছে)।")
                if pn:
                    cp = q1("SELECT method,number FROM payment_numbers WHERE id=? AND user_id=?", (pn["id"], c["user_id"]))
                    if not cp or cp["method"] != pn["method"] or cp["number"] != pn["number"]:
                        raise ReqError("ইউজার এইমাত্র তার পেমেন্ট নম্বর বদলেছেন — পেজ রিলোড করে আবার দেখে নিন।")
                exp = c["expires_at"]
                if hrs_raw and c["status"] == "pending":
                    exp = (datetime.utcnow() + timedelta(hours=int(hrs_raw))).strftime("%Y-%m-%d %H:%M:%S") if int(hrs_raw) else None
                new = {"method": method, "pay_number": num, "instructions": ins, "expires_at": exp}
                if wd:
                    new["pay_type"] = (paytype or None) if c["status"] == "pending" else c["pay_type"]
                if c["flow"]:
                    if not purpose and c["purpose"]:  # cleared on purpose -> default label (an already-empty old record stays unchanged)
                        purpose, purpose_en = default_purpose(c["flow"], "bn"), purpose_en or default_purpose(c["flow"], "en")
                    new["purpose"], new["purpose_en"] = purpose or None, purpose_en or None
                names = {"method": "মাধ্যম", "pay_number": "নম্বর", "instructions": "নির্দেশনা", "purpose": "উদ্দেশ্য", "purpose_en": "Purpose", "expires_at": "মেয়াদ", "pay_type": "পেমেন্ট টাইপ"}
                ch = {k: (c[k], v) for k, v in new.items() if (c[k] or "") != (v or "")}
                if not ch:
                    raise ReqError("কোনো পরিবর্তন করা হয়নি।")
                val = lambda k: new[k] if k in new else c[k]
                cur = db().execute("UPDATE requests SET method=?, pay_number=?, instructions=?, expires_at=?, purpose=?, purpose_en=?, pay_type=?, updated=? "
                                   "WHERE id=? AND status=?",
                                   (val("method"), val("pay_number"), val("instructions"), val("expires_at"), val("purpose"), val("purpose_en"), val("pay_type"),
                                    now(), i, c["status"]))
                if cur.rowcount != 1:
                    raise ReqError("রিকোয়েস্টটি এইমাত্র বদলে গেছে — পেজ রিলোড করে আবার চেষ্টা করুন।")
                for k, (o, n) in ch.items():  # original values stay in the immutable history
                    req_log(i, "edit", c["status"], c["status"], a["member_id"], a["id"], "%s: %s → %s | কারণ: %s" % (names[k], (o or "-")[:60], (n or "-")[:60], reason[:80]))
                audit("req_edit", "req#%d order=%s admin_id=%d reason=%s changes=%s" % (i, c["order_id"], a["id"], reason, _json.dumps({k: [o, n] for k, (o, n) in ch.items()}, ensure_ascii=False)))
                notif_read_link(c["user_id"], "/requests/%d" % i)
                what = ", ".join(names[k] for k in ch)
                notify(c["user_id"], "অনুরোধ সংশোধিত", "Order %s এর তথ্য অ্যাডমিন আপডেট করেছেন (পরিবর্তন: %s)। কারণ: %s" % (c["order_id"], what, reason), "/requests/%d" % i,
                       "Request updated", "The admin updated order %s (changed: %s). Reason: %s" % (c["order_id"], ", ".join(names[k] for k in ch), reason))
        except ReqError as ex:
            err(str(ex)); return redirect(back_to)
        flash("রিকোয়েস্ট আপডেট হয়েছে। পরিবর্তনের ইতিহাস সংরক্ষিত হয়েছে।"); return redirect(back_to)
    ux = q1("SELECT * FROM users WHERE id=?", (r["user_id"],))
    sel = 0
    if has_perm("payment_numbers"):
        m = q1("SELECT id FROM payment_numbers WHERE user_id=? AND method=? AND number=?", (r["user_id"], r["method"], r["pay_number"]))
        sel = m["id"] if m else 0
    panel = _panel_html(ux, sel, chg=False, show_pn=not wd)
    return page(RQ_STYLE + DESK_STYLE + """<div class="card"><div class="row" style="align-items:center"><h2 style="margin:0">✏️ রিকোয়েস্ট সম্পাদনা</h2>
<span class="pill {{r['status']}}" style="flex:0;white-space:nowrap">{{labels[r['status']]}}</span></div>
<div class="k" style="margin-top:6px">Order <b>{{r['order_id']}}</b> · {{r['name']}} · #{{r['member_id']}} · ৳ {{money(r['amount'])}}</div>
<div class="hl rq-lock" style="margin-top:8px">🔒 Order ID, ইউজার, ধরন, পরিমাণ ও কমিশন বদলানো যায় না (আর্থিক হিসাব অপরিবর্তিত থাকে)। এগুলো ভুল হলে রিকোয়েস্টটি বাতিল করে নতুন পাঠান।
প্রতিটি পরিবর্তন (কে, কখন, পুরনো → নতুন, কেন) ইতিহাসে সংরক্ষিত হয় এবং ইউজারকে জানানো হয়।</div></div>
<div class="card"><form method="post" id="ef" data-confirm="পরিবর্তন সংরক্ষণ করবেন? ইউজারকে জানানো হবে।"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<div id="upanel">{{panel|safe}}</div>
<div id="manual"><label>পেমেন্ট মাধ্যম</label><select name="method">{% if r['method'] not in methods %}<option value="{{r['method']}}" selected>{{r['method']}}</option>{% endif %}
{% for m in methods %}<option value="{{m}}" {{'selected' if m==r['method']}}>{{m}}</option>{% endfor %}</select>
<label>পেমেন্ট নম্বর{% if cc %} (ঐচ্ছিক){% else %} (১১ ডিজিট){% endif %}</label><input name="number" inputmode="numeric" maxlength="11" value="{{'' if r['pay_number']=='-' else r['pay_number']}}"></div>
{% if wd %}{% if r['status']=='pending' %}<label>পেমেন্ট টাইপ</label><select name="pay_type"><option value="" {{'selected' if not r['pay_type']}}>— বাছাই করুন —</option>{% for k,l in ptl.items() %}<option value="{{k}}" {{'selected' if r['pay_type']==k}}>{{l}}</option>{% endfor %}</select>
{% else %}<div class="k" style="margin-bottom:8px">পেমেন্ট টাইপ: <b>{{ptl.get(r['pay_type'], '—')}}</b> (ইউজার জমা দেওয়ার পর বদলানো যায় না)</div>{% endif %}{% endif %}
{% if r['flow'] %}<label>উদ্দেশ্য — বাংলা (ঐচ্ছিক)</label><textarea name="purpose" rows="2" maxlength="300">{{r['purpose'] or ''}}</textarea>
<label>Purpose — English (optional)</label><textarea name="purpose_en" rows="2" maxlength="300">{{r['purpose_en'] or ''}}</textarea>{% endif %}
<label>নোট / নির্দেশনা (ঐচ্ছিক)</label><textarea name="instructions" rows="3" maxlength="500">{{r['instructions'] or ''}}</textarea>
{% if r['status']=='pending' %}<label>নতুন মেয়াদ (এখন থেকে কত ঘণ্টা; ০ = মেয়াদ নেই; ফাঁকা = অপরিবর্তিত)</label><input name="hours" type="number" min="0" max="720" placeholder="{{'বর্তমান: ' ~ r['expires_at'][:16] ~ ' UTC' if r['expires_at'] else 'বর্তমানে মেয়াদ নেই'}}">{% endif %}
<label>সম্পাদনার কারণ (আবশ্যক — ইতিহাসে ও ইউজারকে দেখানো হবে)</label><input name="reason" required minlength="3" maxlength="200">
<button style="width:100%">💾 সংরক্ষণ করুন</button></form></div>
<a class="btn s" href="/admin/requests/{{r['id']}}" style="width:100%">← ফিরে যান</a>
<script>(function(){var f=document.getElementById('ef');if(!f)return;""" + PN_JS + """pnBind(f)})()</script>""",
                active="/admin/requests", r=r, cc=cc, wd=wd, methods=METHODS, labels=REQ_LABEL, panel=panel)


@app.route("/admin/requests/<int:i>/act", methods=["POST"])
@staff_required("requests")
def admin_request_act(i):
    act = request.form.get("act", "")
    reason = request.form.get("reason", "").strip()[:200]
    a = me()
    if act not in REQ_ALLOWED:
        abort(400)
    back_to = _safe_next("/admin/requests/%d" % i)
    if act in ("reject", "cancel") and len(reason) < 3:  # every reject / cancel keeps its reason in the immutable history
        err("%s কারণ লিখুন (কমপক্ষে ৩ অক্ষর)।" % ("রিজেক্টের" if act == "reject" else "বাতিলের")); return redirect(back_to)
    try:
        extra = parse_extra(request.form.get("extra_commission"))
    except ReqError as ex:
        err(str(ex)); return redirect(back_to)
    if extra > 0 and act != "approve":
        err("এক্সট্রা কমিশন শুধু অ্যাপ্রুভের সময় দেওয়া যায়।"); return redirect(back_to)
    if extra > 0 and len(reason) < 3:
        err("এক্সট্রা কমিশনের কারণ/রেফারেন্স লিখুন (কমপক্ষে ৩ অক্ষর)।"); return redirect(back_to)
    expire_requests()
    try:
        with atomic():
            r = q1("SELECT * FROM requests WHERE id=?", (i,))
            if not r:
                abort(404)
            if r["status"] not in REQ_ALLOWED[act]:
                raise ReqError("এই অনুরোধে এখন এই কাজ সম্ভব নয় (হয়তো আগেই সম্পন্ন হয়েছে)।")
            if act in ("review", "approve", "reject") and not has_perm(KIND_PERM.get(r["kind"], "-"), a):
                raise ReqError("এই ধরনের (%s) রিকোয়েস্ট প্রসেস করার অনুমতি আপনার নেই।" % ("ডিপোজিট" if r["kind"] == "deposit" else "উইথড্র"))
            if r["flow"] == "client_confirm" and act in ("review", "approve", "reject"):
                raise ReqError("এই অনুরোধ ক্লায়েন্টের সিদ্ধান্তের অপেক্ষায় — অ্যাডমিন অনুমোদন/রিজেক্ট করতে পারবে না (শুধু বাতিল করা যায়)।")
            if extra > 0:  # server-side rule: Extra Commission only for an admin-created Agent Cash Out withdrawal request
                if r["flow"] != "admin_review" or (r["pay_type"] or "") not in EXTRA_COMM_TYPES:
                    raise ReqError("এক্সট্রা কমিশন শুধু Agent Cash Out রিকোয়েস্টে দেওয়া যায় (Personal Send Money ও Merchant Payment-এ নয়)। অ্যাপ্রুভ হয়নি।")
                if extra > float(r["amount"]) + 0.004:
                    raise ReqError("এক্সট্রা কমিশন রিকোয়েস্টের মূল পরিমাণের (৳%s) বেশি হতে পারে না। অ্যাপ্রুভ হয়নি।" % money(r["amount"]))
            new, t = REQ_NEW[act], now()
            if act == "review":
                cur = db().execute("UPDATE requests SET status='review', updated=? WHERE id=? AND status='submitted'", (t, i))
            else:
                ph = ",".join("?" * len(REQ_ALLOWED[act]))
                cur = db().execute("UPDATE requests SET status=?, updated=?, decided_by_id=?, decided_by=?, decided_at=?, reject_reason=? "
                                   "WHERE id=? AND status IN (%s)" % ph,
                                   (new, t, a["id"], a["member_id"], t, reason or None, i) + REQ_ALLOWED[act])
            if cur.rowcount != 1:
                raise ReqError("এই অনুরোধে এখন এই কাজ সম্ভব নয় (হয়তো আগেই সম্পন্ন হয়েছে)।")
            if act == "cancel":  # admin cancellation: no fee, no commission, no wallet or pool movement
                db().execute("UPDATE requests SET cancel_by='admin', cancel_fee=0 WHERE id=?", (i,))
            if act == "approve":
                dep = r["kind"] == "deposit"
                if not dep:  # re-check the balance at the exact moment of approval (we hold the write lock)
                    bal = q1("SELECT balance FROM users WHERE id=?", (r["user_id"],))["balance"]
                    if round(bal - r["amount"], 2) < 0:
                        raise ReqError("ব্যালেন্স অপর্যাপ্ত: ইউজারের বর্তমান ব্যালেন্স ৳%s, কিন্তু অনুরোধের পরিমাণ ৳%s। অ্যাপ্রুভ করা যায়নি।"
                                       % (money(bal), money(r["amount"])))
                ok = post(r["user_id"], "request_deposit" if dep else "request_withdraw", r["amount"] if dep else -r["amount"],
                          "req:%d:approve" % i, "request", i, "Order %s" % r["order_id"], a["member_id"])
                if not ok:
                    raise ReqError("এই অনুরোধের লেজার এন্ট্রি আগেই আছে — অ্যাপ্রুভ বাতিল করা হয়েছে।")
                if r["flow"] == "admin_review" and float(r["commission"] or 0) > 0:  # same transaction: principal + commission, or nothing
                    pool_pay(r["user_id"], "commission", r["commission"], "req:%d:commission" % i, "request", i,
                             "Order %s commission" % r["order_id"], a["member_id"], own_req=i)
                if extra > 0:  # same transaction: pool -extra AND wallet +extra (separate ledger entry), idempotent on req:<id>:extra
                    if not pool_pay(r["user_id"], "extra_commission", extra, "req:%d:extra" % i, "request", i,
                                    "Order %s extra commission: %s" % (r["order_id"], reason[:120]), a["member_id"], own_req=i):
                        raise ReqError("এই অনুরোধের এক্সট্রা কমিশন আগেই দেওয়া হয়েছে — অ্যাপ্রুভ বাতিল করা হয়েছে।")
                    db().execute("UPDATE requests SET extra_commission=? WHERE id=?", (extra, i))
                if dep and not r["flow"]:  # plain Add Money request: first approved deposit -> one referral reward
                    referral_reward_on_deposit(r["user_id"], a, "req#%d" % i, req_id=i)
            req_log(i, act, r["status"], new, a["member_id"], a["id"], (reason + " | extra ৳%s" % money(extra)) if extra > 0 else reason)
            audit("req_" + act, "req#%d order=%s %s ৳%s user#%d trx=%s admin_id=%d at=%s" %
                  (i, r["order_id"], r["kind"], r["amount"], r["user_id"], r["norm_trx"] or "-", a["id"], t)
                  + (" fee=0 (admin cancel: no fee, no wallet or pool change)" if act == "cancel" else ""))
            if extra > 0:
                audit("req_extra_commission", "req#%d order=%s user#%d extra=৳%s type=%s admin_id=%d at=%s ref=%s" %
                      (i, r["order_id"], r["user_id"], money(extra), r["pay_type"], a["id"], t, reason[:120]))
            msgs = {"review": ("অনুরোধ যাচাইয়ে আছে", "Order %s এখন যাচাই করা হচ্ছে।" % r["order_id"]),
                    "approve": ("অনুরোধ অনুমোদিত", ("৳%s আপনার ওয়ালেটে যুক্ত হয়েছে।" if r["kind"] == "deposit" else "৳%s আপনার ওয়ালেট থেকে কাটা হয়েছে।")
                                % money(r["amount"]) + " Order %s" % r["order_id"]),
                    "reject": ("অনুরোধ রিজেক্ট", "Order %s গৃহীত হয়নি। কারণ: %s" % (r["order_id"], reason)),
                    "cancel": ("অনুরোধ বাতিল", "Order %s বাতিল করা হয়েছে।%s" % (r["order_id"], (" কারণ: " + reason) if reason else ""))}
            if act == "approve" and r["flow"] == "admin_review" and float(r["commission"] or 0) > 0:
                msgs["approve"] = ("অনুরোধ অনুমোদিত", "৳%s + কমিশন ৳%s আপনার ওয়ালেটে যুক্ত হয়েছে। Order %s" % (money(r["amount"]), money(r["commission"]), r["order_id"]))
            if act == "approve" and extra > 0:
                parts = ["মূল ৳%s" % money(r["amount"])] + (["কমিশন ৳%s" % money(r["commission"])] if float(r["commission"] or 0) > 0 else []) + ["এক্সট্রা কমিশন ৳%s" % money(extra)]
                msgs["approve"] = ("অনুরোধ অনুমোদিত", "মোট ৳%s আপনার ওয়ালেটে যুক্ত হয়েছে (%s)। Order %s" %
                                   (money(float(r["amount"]) + float(r["commission"] or 0) + extra), " + ".join(parts), r["order_id"]))
            notif_read_link(r["user_id"], "/requests/%d" % i)  # earlier notifications of this request are handled; the new status one stays unread
            if act in ("approve", "reject", "cancel"):
                alerts_done("/admin/requests/%d" % i)
            notify(r["user_id"], msgs[act][0], msgs[act][1], "/requests/%d" % i)
    except ReqError as ex:
        err(str(ex)); return redirect(back_to)
    except PoolError as ex:
        err("কমিশন পুলে পর্যাপ্ত ফান্ড নেই — অ্যাপ্রুভ হয়নি, কিছুই পরিবর্তন হয়নি: %s" % ex); return redirect(back_to)
    except LedgerError as ex:
        err("লেজার ত্রুটি, কিছুই পরিবর্তন হয়নি: %s" % ex); return redirect(back_to)
    flash("সম্পন্ন: %s" % REQ_LABEL[new])
    return redirect(back_to)


RH_PER = 30


@app.route("/admin/request-history")
@staff_required("requests")
def admin_request_history():
    """Dedicated history of admin-created requests only (no deposits/withdrawals/ledger rows mixed in). Filters: All / Pending / Success / Cancelled / Rejected."""
    expire_requests()
    f = request.args.get("f", "all")
    if f not in ("all", "pending", "success", "cancelled", "rejected"):
        f = "all"
    p = min(max(request.args.get("p", type=int) or 1, 1), 2000)
    where = {"all": "", "pending": " WHERE r.status IN ('pending','submitted','review')", "success": " WHERE r.status='approved'",
             "cancelled": " WHERE r.status='cancelled'", "rejected": " WHERE r.status='rejected'"}[f]
    rows = qa("SELECT r.id,r.order_id,r.kind,r.flow,r.amount,r.status,r.created,u.name,u.member_id FROM requests r JOIN users u ON u.id=r.user_id%s "
              "ORDER BY r.id DESC LIMIT ? OFFSET ?" % where, (RH_PER + 1, (p - 1) * RH_PER))
    by = {r["status"]: r["n"] for r in qa("SELECT status, COUNT(*) n FROM requests GROUP BY status")}
    cnt = {"all": sum(by.values()), "pending": sum(by.get(s, 0) for s in OPEN_REQ), "success": by.get("approved", 0),
           "cancelled": by.get("cancelled", 0), "rejected": by.get("rejected", 0)}
    tabs = [("all", "সব"), ("pending", "অপেক্ষমাণ"), ("success", "সফল"), ("cancelled", "বাতিল"), ("rejected", "রিজেক্ট")]
    return page("""<style>
.rh-f{display:flex;flex-wrap:wrap;gap:5px;margin:0 0 8px}
.rh-f a{display:inline-flex;align-items:center;justify-content:center;gap:4px;height:28px;padding:0 10px;border-radius:8px;border:1px solid var(--ln);background:var(--card);color:var(--mut);font-weight:600;font-size:12px;line-height:1;white-space:nowrap;text-decoration:none;touch-action:manipulation;-webkit-tap-highlight-color:transparent}
.rh-f a i{font-style:normal;font-size:10.5px;min-width:16px;padding:1px 5px;border-radius:99px;background:var(--bg);text-align:center}
.rh-f a.on{color:#fff;border-color:#1E90FF;background:#1E90FF}.rh-f a.on[data-f=pending]{border-color:#d97706;background:#d97706}.rh-f a.on[data-f=success]{border-color:#0EA371;background:#0EA371}.rh-f a.on[data-f=cancelled]{border-color:#64748b;background:#64748b}.rh-f a.on[data-f=rejected]{border-color:#dc2626;background:#dc2626}.rh-f a.on i{background:#ffffff33;color:#fff}
.rh-c{display:flex;justify-content:space-between;align-items:center;gap:8px;background:var(--card);border:1px solid var(--ln);border-radius:9px;padding:7px 10px;margin-bottom:5px;color:var(--tx);text-decoration:none}
.rh-l{min-width:0}.rh-id{display:block;font-weight:700;font-size:13px;line-height:1.3;overflow-wrap:anywhere}.rh-t{display:block;font-size:12px;color:var(--mut);line-height:1.3}
.rh-r{display:flex;flex-direction:column;align-items:flex-end;gap:2px;flex:0 0 auto}.rh-am{font-size:13px;font-weight:700;line-height:1.3}
.rh-c .pill{flex:0;white-space:nowrap;font-size:11px;padding:1px 8px;line-height:1.5}
.rh-pg{display:flex;gap:6px;margin:4px 0 8px}.rh-pg a{flex:1}
</style>
<div class="rh-f">{% for k,lb in tabs %}<a data-f="{{k}}" class="{{'on' if f==k}}" href="/admin/request-history{{'' if k=='all' else '?f='+k}}">{{lb}} <i>{{cnt[k]}}</i></a>{% endfor %}</div>
{% if not rows %}<div class="card empty">কোনো রিকোয়েস্ট নেই</div>{% endif %}
{% for r in rows %}<a class="rh-c" href="/admin/requests/{{r['id']}}"><div class="rh-l"><span class="rh-id">{{r['order_id']}}</span><span class="rh-t">{{kinds.get(rdt(r), '')}}</span></div>
<div class="rh-r"><span class="rh-am">৳ {{money(r['amount'])}}</span><span class="pill {{r['status']}}">{{labels[r['status']]}}</span></div></a>{% endfor %}
{% if p>1 or more %}<div class="rh-pg">{% if p>1 %}<a class="btn sm s" href="/admin/request-history?f={{f}}&p={{p-1}}">← আগের</a>{% endif %}{% if more %}<a class="btn sm s" href="/admin/request-history?f={{f}}&p={{p+1}}">পরের →</a>{% endif %}</div>{% endif %}""",
                active="/admin/request-history", rows=rows[:RH_PER], more=len(rows) > RH_PER, p=p, f=f, cnt=cnt, tabs=tabs, labels=REQ_LABEL, kinds=REQ_KIND)


@app.route("/admin/warnings/new", methods=["POST"])
@staff_required("requests", "notices")
def admin_warning_new():
    """Warning / notice to a user (optionally attached to one of their requests). Stored with timestamp + admin identity (immutable table),
    sent as an in-app notification and written to the audit log. It NEVER restricts anything by itself - blocking is a separate action."""
    a = me()
    uid = request.form.get("uid", type=int)
    rid = request.form.get("request_id", type=int)
    msg = request.form.get("message", "").strip()[:500]
    back_to = _safe_next(("/admin/requests/%d" % rid) if rid else (("/admin/users/%d" % uid) if uid else "/admin"))
    x = q1("SELECT id,member_id,name FROM users WHERE id=? AND is_admin=0", (uid,)) if uid else None
    if not x:
        err("ইউজার পাওয়া যায়নি।"); return redirect(back_to)
    if len(msg) < 5:
        err("সতর্কবার্তা লিখুন (কমপক্ষে ৫ অক্ষর)।"); return redirect(back_to)
    if rate_hit("warn:%d" % a["id"], 30, 3600):
        err("অনেক সতর্কবার্তা পাঠানো হয়েছে, পরে চেষ্টা করুন।"); return redirect(back_to)
    try:
        with atomic():
            rq = None
            if rid:
                rq = q1("SELECT id,order_id,status FROM requests WHERE id=? AND user_id=?", (rid, x["id"]))
                if not rq:
                    raise ReqError("এই রিকোয়েস্টটি এই ইউজারের নয়।")
            cur = db().execute("INSERT INTO user_warnings(user_id,request_id,message,admin_id,admin,created) VALUES(?,?,?,?,?,?)",
                               (x["id"], rq["id"] if rq else None, msg, a["id"], a["member_id"], now()))
            wid = cur.lastrowid
            link = ("/requests/%d" % rq["id"]) if rq else "/requests"
            notify(x["id"], "⚠ অ্যাডমিনের সতর্কবার্তা", msg, link, "⚠ Admin warning", msg)
            if rq:
                req_log(rq["id"], "warning", rq["status"], rq["status"], a["member_id"], a["id"], "warning#%s: %s" % (wid, msg[:200]))
            audit("warning_issue", "warning#%s user#%d%s admin_id=%d: %s" % (wid, x["id"], (" req#%d order=%s" % (rq["id"], rq["order_id"])) if rq else "", a["id"], msg[:300]))
    except ReqError as ex:
        err(str(ex)); return redirect(back_to)
    flash("সতর্কবার্তা ইউজারকে পাঠানো হয়েছে (ইউজারের কোনো লেনদেন সীমাবদ্ধ করা হয়নি)।")
    return redirect(back_to)


# ================================================================ Referral rewards: paid once per referred user, on their FIRST approved Add Money
# Reward money is ALWAYS taken from the funded Commission Pool (pool_pay) - never created from nothing. Registration alone never pays.
REWARD_RE = re.compile(r"\d{1,8}(\.\d{1,2})?")


def parse_reward(v):
    """Any positive amount with up to 2 decimals (no preset list, no cap other than the 8-digit column size). Returns float or None."""
    v = (v or "").replace(",", "").strip()
    if not REWARD_RE.fullmatch(v):
        return None
    d = Decimal(v).quantize(Decimal("0.01"))
    return float(d) if d > 0 else None


def referral_reward_amount():
    """The currently active reward (settings.referral_bonus; default 50 BDT)."""
    r = q1("SELECT v FROM settings WHERE k='referral_bonus'")
    return parse_reward(r["v"] if r else "50") or 50.0


def _add_money_count(uid, tx_id=0, req_id=0):
    """Approved Add Money transactions of a user, excluding the given tx / request (the one being approved right now)."""
    a = q1("SELECT COUNT(*) c FROM tx WHERE user_id=? AND kind='deposit' AND status='approved' AND id<>?", (uid, tx_id))["c"]
    b = q1("SELECT COUNT(*) c FROM requests WHERE user_id=? AND kind='deposit' AND COALESCE(flow,'')='' AND status='approved' AND id<>?", (uid, req_id))["c"]
    return int(a) + int(b)


def referral_reward_pay(r, rf, x, actor, ref, need_deposit=False, admin_note=""):
    """Pay one pending referral row exactly once. Caller holds atomic(). Returns 'paid' | 'no_deposit' | 'no_funds' | 'blocked' | 'done'.
    Writes (all in the caller's transaction): pool payout + wallet ledger credit ('referral_bonus') + referrals row -> approved with the paid amount."""
    if r["status"] != "pending":
        return "done"
    if rf["blocked"] or r["referrer_id"] == r["referred_id"] or x["referred_by"] != r["referrer_id"]:
        return "blocked"
    if need_deposit and _add_money_count(x["id"]) < 1:
        return "no_deposit"
    amt = referral_reward_amount()
    idem = "ref:%d:bonus" % r["id"]
    if q1("SELECT 1 FROM ledger WHERE idem=?", (idem,)):  # already credited earlier: never pay twice, just close the row
        db().execute("UPDATE referrals SET status='approved' WHERE id=? AND status='pending'", (r["id"],))
        return "done"
    note = "Referral reward for #%s (%s)" % (x["member_id"], ref)
    try:  # PoolError is raised BEFORE anything is written, so a short pool leaves the caller's transaction untouched
        pool_pay(rf["id"], "referral_bonus", amt, idem, "referral", r["id"], note, actor["member_id"])
    except PoolError:
        return "no_funds"
    cur = db().execute("UPDATE referrals SET status='approved', amount=?, decided_by=?, decided_by_id=?, decided_at=?, note=? WHERE id=? AND status='pending'",
                       (amt, "%s (%s)" % (actor["name"], actor["member_id"]), actor["id"], now(),
                        (ref + (" · " + admin_note if admin_note else ""))[:200], r["id"]))
    if cur.rowcount != 1:
        raise LedgerError("duplicate referral reward")  # rolls the whole transaction back
    notify(rf["id"], "রেফারেল রিওয়ার্ড পেয়েছেন", "#%s-এর প্রথম ডিপোজিটের জন্য ৳%s আপনার ওয়ালেটে যুক্ত হয়েছে।" % (x["member_id"], money(amt)), "/referral",
           "Referral reward received", "৳%s was added to your wallet for #%s's first deposit." % (money(amt), x["member_id"]))
    audit("referral_reward", "ref#%d referrer#%s referred#%s ৳%s %s" % (r["id"], rf["member_id"], x["member_id"], money(amt), ref), actor=actor)
    return "paid"


def referral_reward_on_deposit(uid, actor, ref, tx_id=0, req_id=0):
    """Called inside the deposit-approval transaction, AFTER the deposit row is approved and credited.
    Pays the referrer only if this is the referred user's first approved Add Money. Never raises for business reasons,
    so it can never block or undo the deposit approval itself."""
    r = q1("SELECT * FROM referrals WHERE referred_id=? AND status='pending'", (uid,))
    if not r or _add_money_count(uid, tx_id, req_id) > 0:
        return "skip"
    rf, x = q1("SELECT * FROM users WHERE id=?", (r["referrer_id"],)), q1("SELECT * FROM users WHERE id=?", (uid,))
    if not rf or not x:
        return "skip"
    res = referral_reward_pay(r, rf, x, actor, "first deposit " + ref)
    if res == "no_funds":  # deposit still succeeds; the reward stays pending and can be paid from /admin/referrals once the pool is funded
        alert_admins("রেফারেল রিওয়ার্ড আটকে আছে", "কমিশন পুলে ফান্ড কম — ref#%d (#%s) রিওয়ার্ড বাকি" % (r["id"], x["member_id"]), "/admin/referrals", "referrals")
    return res


@app.route("/admin/referral-rewards", methods=["GET", "POST"])
@staff_required("referrals", "settings")
def admin_referral_rewards():
    a = me()
    if request.method == "POST":
        if not has_perm("settings", a):  # only the Super Admin may change the reward
            abort(403)
        new = parse_reward(request.form.get("amount"))
        if new is None:
            err("সঠিক পরিমাণ দিন (০-এর বেশি, সর্বোচ্চ ২ দশমিক ঘর)।"); return redirect("/admin/referral-rewards")
        with atomic():
            old = referral_reward_amount()
            db().execute("INSERT OR REPLACE INTO settings VALUES(?,?)", ("referral_bonus", "%.2f" % new))
            audit("referral_reward_set", "৳%s -> ৳%s" % (money(old), money(new)))
        flash("রিওয়ার্ড সেভ হয়েছে: এখন থেকে ৳%s।" % money(new)); return redirect("/admin/referral-rewards")
    cur = referral_reward_amount()
    sm = q1("""SELECT COUNT(*) total, COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0) pend,
               COALESCE(SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END),0) paid,
               COALESCE(SUM(CASE WHEN status='approved' THEN amount END),0) paid_amt FROM referrals""")
    pg = make_pg(q1("SELECT COUNT(*) n FROM referrals WHERE status='approved'")["n"], 30)
    rows = qa("""SELECT r.*, rf.member_id rf_mid, rf.name rf_name, x.member_id x_mid, x.name x_name,
                 EXISTS(SELECT 1 FROM pool_ledger p WHERE p.ledger_idem='ref:'||r.id||':bonus') funded
                 FROM referrals r JOIN users rf ON rf.id=r.referrer_id JOIN users x ON x.id=r.referred_id
                 WHERE r.status='approved' ORDER BY r.decided_at DESC, r.id DESC LIMIT ? OFFSET ?""", (30, pg["off"]))
    chg = qa("SELECT actor,detail,created FROM audit WHERE action='referral_reward_set' ORDER BY id DESC LIMIT 15")
    return page("""<div class="row" style="margin-bottom:10px;align-items:center"><a class="btn sm s" href="/admin/referrals">📋 তালিকা</a><a class="btn sm s" href="/admin/referrals/network">🌐 নেটওয়ার্ক</a><a class="btn sm" href="/admin/referral-rewards">⚙️ রিওয়ার্ড সেটিংস</a></div>
<div class="card hero"><small>বর্তমান রিওয়ার্ড (প্রতি রেফার করা ব্যক্তির প্রথম অনুমোদিত ডিপোজিটে, একবার)</small><div class="code">৳ {{money(cur)}}</div>
{% if can('pool_view') %}<div class="k" style="color:inherit">পুলে উপলব্ধ: ৳{{money(pool_av)}}</div>{% endif %}</div>
{% if can('settings') %}<div class="card"><h3>রিওয়ার্ড সেটিংস</h3><form method="post" data-confirm="নতুন রিওয়ার্ড সেভ করবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>রিওয়ার্ডের পরিমাণ (৳)</label><input name="amount" inputmode="decimal" value="{{'%.2f'|format(cur)}}" required autocomplete="off">
<div class="k">যেকোনো পরিমাণ দিতে পারেন এবং যখন খুশি বদলাতে পারেন। নতুন পরিমাণ শুধু এরপরের রিওয়ার্ডে প্রযোজ্য; আগে দেওয়া রিওয়ার্ড বদলায় না। রিওয়ার্ড কমিশন পুল থেকে যায়, তাই পুলে ফান্ড থাকতে হবে।</div>
<button style="width:100%">রিওয়ার্ড সেভ করুন</button></form></div>{% else %}<div class="card"><div class="k">শুধু সুপার অ্যাডমিন রিওয়ার্ডের পরিমাণ বদলাতে পারেন।</div></div>{% endif %}
<div class="g2"><div class="card"><div class="k">মোট রেফারেল</div><div class="v">{{sm['total']}}</div></div>
<div class="card"><div class="k">প্রথম ডিপোজিট বাকি</div><div class="v">{{sm['pend']}}</div></div>
<div class="card"><div class="k">রিওয়ার্ড পেইড</div><div class="v">{{sm['paid']}}</div></div>
<div class="card"><div class="k">মোট পেইড</div><div class="v">৳ {{money(sm['paid_amt'])}}</div></div></div>
<div class="card"><h3>রিওয়ার্ড ইতিহাস</h3>{% if not rows %}<div class="empty">এখনো কোনো রিওয়ার্ড দেওয়া হয়নি</div>{% else %}<div class="tw"><table>
<tr><th>তারিখ</th><th>রেফারার</th><th>রেফার করা</th><th>৳</th><th>রেফারেন্স</th></tr>
{% for r in rows %}<tr><td>{{(r['decided_at'] or r['created'])|bdd}}</td><td><a href="/admin/referrals/user/{{r['referrer_id']}}">#{{r['rf_mid']}} {{r['rf_name']}}</a></td>
<td><a href="/admin/referrals/user/{{r['referred_id']}}">#{{r['x_mid']}} {{r['x_name']}}</a></td><td>{{money(r['amount'])}}</td>
<td class="k">ref#{{r['id']}} · {{r['note'] or '-'}} · {{'পুল' if r['funded'] else 'পুল-পূর্ব'}}</td></tr>{% endfor %}</table></div>{% endif %}</div>""" + PAGER + """
{% if chg %}<div class="card"><h3>পরিমাণ বদলের ইতিহাস</h3><div class="tw"><table>{% for c in chg %}<tr><td>{{c['created'][:16]}}</td><td>{{c['actor']}}</td><td>{{c['detail']}}</td></tr>{% endfor %}</table></div></div>{% endif %}""",
                active="/admin/referrals", cur=cur, sm=sm, rows=rows, pg=pg, chg=chg, pool_av=pool_available())


# ================================================================ Phase 2C: referral network, financial reports + CSV, reconciliation
# Read-only on money: nothing here creates or moves funds (referral rewards are paid by the pool engine above).

LK_LABEL = {"deposit": "ডিপোজিট", "request_deposit": "অনুরোধ-ডিপোজিট", "withdraw_hold": "উইথড্র (হোল্ড)", "withdraw_release": "উইথড্র ফেরত",
            "request_withdraw": "অনুরোধ-উইথড্র", "request_payment": "ক্লায়েন্ট পেমেন্ট", "commission": "কমিশন", "commission_reversal": "কমিশন ফেরত",
            "referral_bonus": "রেফারেল বোনাস", "admin_adjust": "ব্যালেন্স সমন্বয়",
            "extra_commission": "এক্সট্রা কমিশন", "request_cancel_fee": "রিকোয়েস্ট বাতিল ফি"}
REPORT_KINDS = {"deposits": "ডিপোজিট", "withdrawals": "উইথড্র", "commissions": "কমিশন", "referrals": "রেফারেল বোনাস",
                "payments": "ক্লায়েন্ট পেমেন্ট", "pool": "পুল"}
POOL_USE = {"request": "অ্যাডমিন-পাঠানো রিকোয়েস্টের কমিশন", "commission": "ম্যানুয়াল কমিশন", "referral": "রেফারেল বোনাস"}


# ---- time: stored timestamps are UTC; reports bucket by local (Bangladesh, UTC+6 by default) days
def rtz():
    try:
        h = float(setting("report_tz_hours", "6") or 6)
    except ValueError:
        h = 6.0
    return max(-12.0, min(14.0, h))


def _d(s):
    if not s or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError:
        return None


def local_today():
    return (datetime.utcnow() + timedelta(hours=rtz())).date()


def report_range():
    """-> (d1, d2, utc_from, utc_to_exclusive, error or None). Bad input falls back to 'this month' and reports the problem."""
    t, e = local_today(), None
    f, to = request.args.get("from", ""), request.args.get("to", "")
    d1, d2 = _d(f), _d(to)
    if (f and not d1) or (to and not d2):
        e = "তারিখ YYYY-MM-DD আকারে দিন।"
    d1, d2 = d1 or t.replace(day=1), d2 or t
    if not e and d1 > d2:
        e = "শুরুর তারিখ শেষ তারিখের পরে হতে পারে না।"
    if not e and (d2 - d1).days > 366:
        e = "সর্বোচ্চ ৩৬৬ দিনের রিপোর্ট নেওয়া যায়।"
    if e:
        d1, d2 = t.replace(day=1), t
    off = timedelta(hours=rtz())
    fmt = "%Y-%m-%d %H:%M:%S"
    u1 = (datetime.combine(d1, datetime.min.time()) - off).strftime(fmt)
    u2 = (datetime.combine(d2 + timedelta(days=1), datetime.min.time()) - off).strftime(fmt)
    return d1, d2, u1, u2, e


def _loc(ts):
    try:
        return (datetime.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S") + timedelta(hours=rtz())).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return str(ts or "")[:16]


def _bucket(ts, period):
    return _loc(ts)[:7 if period == "monthly" else 10]


def _r2(x):
    return round(float(x or 0), 2)


def _m(x):
    return Decimal(str(_r2(x))).quantize(Decimal("0.01"))


# ---- report rows (single source of truth for pages, CSV and tests). amount: deposits/withdrawals/payments/referrals positive
def report_rows(kind, u1, u2, uid=None):
    ua, uq = ((uid,), " AND {c}.user_id=?") if uid else ((), "")
    out = []
    if kind in ("deposits", "commissions", "referrals", "payments", "withdrawals"):
        kinds = {"deposits": ("deposit", "request_deposit"), "commissions": ("commission", "commission_reversal"),
                 "referrals": ("referral_bonus",), "payments": ("request_payment",), "withdrawals": ("request_withdraw",)}[kind]
        ph = ",".join("?" * len(kinds))
        for r in qa("SELECT l.id, l.created ts, l.amount, l.user_id, u.member_id, u.name, l.kind what, l.ref_type, l.ref_id, l.note, "
                    "EXISTS(SELECT 1 FROM pool_ledger p WHERE p.ledger_idem=l.idem) funded FROM ledger l JOIN users u ON u.id=l.user_id "
                    "WHERE l.kind IN (%s) AND l.created>=? AND l.created<?%s ORDER BY l.created, l.id" % (ph, uq.format(c="l")),
                    kinds + (u1, u2) + ua):
            a = float(r["amount"])
            out.append(dict(ts=r["ts"], amount=a if kind in ("commissions", "deposits", "referrals") else abs(a), uid=r["user_id"], member=r["member_id"],
                            name=r["name"], what=LK_LABEL.get(r["what"], r["what"]), ref="%s#%s" % (r["ref_type"] or "-", r["ref_id"] or "-"),
                            note=r["note"] or "", funded=bool(r["funded"])))
    if kind == "withdrawals":  # user-initiated withdrawals are counted when approved/paid (same rule as the dashboards)
        for r in qa("SELECT t.id, t.updated ts, t.amount, t.user_id, u.member_id, u.name, t.method, t.note FROM tx t JOIN users u ON u.id=t.user_id "
                    "WHERE t.kind='withdraw' AND t.status IN ('approved','paid') AND t.updated>=? AND t.updated<?%s ORDER BY t.updated, t.id" % uq.format(c="t"),
                    (u1, u2) + ua):
            out.append(dict(ts=r["ts"], amount=float(r["amount"]), uid=r["user_id"], member=r["member_id"], name=r["name"], what="উইথড্র",
                            ref="tx#%s" % r["id"], note=r["method"] or "", funded=False))
        out.sort(key=lambda d: d["ts"])
    if kind == "pool":
        for r in qa("SELECT p.*, u.member_id, u.name FROM pool_ledger p LEFT JOIN users u ON u.id=p.user_id WHERE p.created>=? AND p.created<? ORDER BY p.created, p.id", (u1, u2)):
            out.append(dict(ts=r["created"], amount=float(r["amount"]), uid=r["user_id"], member=r["member_id"] or "", name=r["name"] or "",
                            what=r["kind"], ref=r["reference"] or ("%s#%s" % (r["ref_type"] or "-", r["ref_id"] or "-")),
                            note=((POOL_SOURCES.get(r["source_type"], r["source_type"]) + " · ") if r["source_type"] else "") + (r["note"] or ""), funded=True))
    return out


SUM_COLS = (("deposits", "ডিপোজিট"), ("withdrawals", "উইথড্র"), ("commissions", "কমিশন (নিট)"), ("referrals", "রেফারেল বোনাস"), ("payments", "ক্লায়েন্ট পেমেন্ট"))


def summary_table(u1, u2, period):
    data = {}
    for col, _l in SUM_COLS:
        for r in report_rows(col, u1, u2):
            d = data.setdefault(_bucket(r["ts"], period), {c: [0.0, 0] for c, _ in SUM_COLS})
            d[col][0] += r["amount"]; d[col][1] += 1
    rows = [(b, {c: (_r2(v[0]), v[1]) for c, v in d.items()}) for b, d in sorted(data.items())]
    tot = {c: (_r2(sum(d[c][0] for _, d in rows)), sum(d[c][1] for _, d in rows)) for c, _ in SUM_COLS}
    return rows, tot


def bucket_table(rows, period):
    d = {}
    for r in rows:
        b = d.setdefault(_bucket(r["ts"], period), [0.0, 0]); b[0] += r["amount"]; b[1] += 1
    return [(k, _r2(v[0]), v[1]) for k, v in sorted(d.items())]


def _csv_cell(v):
    return "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v  # spreadsheet formula-injection guard


def csv_download(fname, header, rows, what):
    buf = io.StringIO(); w = csv.writer(buf, lineterminator="\r\n"); w.writerow(header)
    for r in rows:
        w.writerow([_csv_cell(x) for x in r])
    audit("report_export", "%s file=%s rows=%d" % (what, fname, len(rows)))
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % fname, "Cache-Control": "no-store"})


def _want_csv():
    return request.args.get("fmt") == "csv"


def _rtabs(d1, d2, period, cur):
    qs = urlencode({"from": d1, "to": d2, "period": period})
    tabs = [("summary", "সারাংশ", "/admin/reports?" + qs)] + [(k, l, "/admin/reports/%s?%s" % (k, qs)) for k, l in REPORT_KINDS.items()]
    return tabs + [("wallets", "মোট ওয়ালেট", "/admin/reports/wallets")], cur


REPORT_HEAD = """<div class="row" style="margin-bottom:8px;flex-wrap:wrap;gap:6px">{% for k,l,u in rtabs %}<a class="btn sm {{'' if k==cur else 's'}}" href="{{u}}">{{l}}</a>{% endfor %}
<a class="btn sm s" href="/admin/reconcile">🧮 মিলানো</a></div>
{% if rerr %}<div class="msg error">{{rerr}}</div>{% endif %}
{% if filt %}<form method="get" class="card"><div class="row"><div><label>থেকে</label><input type="date" name="from" value="{{d1}}"></div><div><label>পর্যন্ত</label><input type="date" name="to" value="{{d2}}"></div></div>
<label>ভাগ</label><select name="period"><option value="daily" {{'selected' if period=='daily'}}>দৈনিক</option><option value="monthly" {{'selected' if period=='monthly'}}>মাসিক</option></select>
<p class="k">সময় বাংলাদেশ সময় (UTC+{{tz}}) অনুযায়ী।</p><button style="width:100%">দেখান</button></form>{% endif %}"""


@app.route("/admin/reports")
@staff_required("reports")
def admin_reports():
    d1, d2, u1, u2, e = report_range()
    if e and _want_csv():
        abort(400)  # never export a file for a filter the person did not actually ask for
    period = "monthly" if request.args.get("period") == "monthly" else "daily"
    rows, tot = summary_table(u1, u2, period)
    if _want_csv():
        hdr = ["period"] + [x for c, l in SUM_COLS for x in (c + "_count", c + "_amount")]
        body = [[b] + [x for c, _l in SUM_COLS for x in (d[c][1], _m(d[c][0]))] for b, d in rows]
        body.append(["TOTAL"] + [x for c, _l in SUM_COLS for x in (tot[c][1], _m(tot[c][0]))])
        return csv_download("summary_%s_%s_%s.csv" % (d1, d2, period), hdr, body, "summary")
    tabs, cur = _rtabs(d1, d2, period, "summary")
    return page(REPORT_HEAD + """<div class="g2">{% for c,l in cols %}<div class="card"><div class="k">{{l}}</div><div class="v">৳ {{money(tot[c][0])}}</div><div class="k">{{tot[c][1]}}টি</div></div>{% endfor %}</div>
<div class="card"><h3>{{'মাসিক' if period=='monthly' else 'দৈনিক'}} সারাংশ ({{d1}} → {{d2}})</h3>
<div class="tw"><table><tr><th>{{'মাস' if period=='monthly' else 'তারিখ'}}</th>{% for c,l in cols %}<th>{{l}}</th>{% endfor %}</tr>
{% for b,d in rows %}<tr><td>{{b}}</td>{% for c,l in cols %}<td>{{money(d[c][0])}} <span class="k">({{d[c][1]}})</span></td>{% endfor %}</tr>{% endfor %}
{% if not rows %}<tr><td colspan="6" class="k">এই সময়ে কোনো লেনদেন নেই</td></tr>{% endif %}
<tr><th>মোট</th>{% for c,l in cols %}<th>{{money(tot[c][0])}}</th>{% endfor %}</tr></table></div>
<a class="btn sm s" href="?from={{d1}}&to={{d2}}&period={{period}}&fmt=csv">⬇ CSV</a></div>
<p class="k">কমিশন (নিট) = কমিশন − কমিশন ফেরত। ক্লায়েন্ট পেমেন্ট উইথড্র হিসেবে গণ্য হয় না।</p>""",
                active="/admin/reports", rtabs=tabs, cur=cur, rerr=e, filt=True, d1=d1, d2=d2, period=period, tz=("%g" % rtz()), rows=rows, tot=tot, cols=SUM_COLS)


@app.route("/admin/reports/<kind>")
@staff_required("reports")
def admin_report_kind(kind):
    if kind not in REPORT_KINDS:
        abort(404)
    d1, d2, u1, u2, e = report_range()
    if e and _want_csv():
        abort(400)  # never export a file for a filter the person did not actually ask for
    period = "monthly" if request.args.get("period") == "monthly" else "daily"
    rows = report_rows(kind, u1, u2)
    if _want_csv():
        if request.args.get("detail") == "1":
            return csv_download("%s_detail_%s_%s.csv" % (kind, d1, d2),
                                ["time_local", "member_id", "name", "type", "amount", "reference", "pool_funded", "note"],
                                [[_loc(r["ts"]), r["member"], r["name"], r["what"], _m(r["amount"]), r["ref"], "yes" if r["funded"] else "no", r["note"]] for r in rows],
                                "detail:" + kind)
        return csv_download("%s_%s_%s_%s.csv" % (kind, period, d1, d2), ["period", "count", "amount"],
                            [[b, n, _m(a)] for b, a, n in bucket_table(rows, period)] + [["TOTAL", len(rows), _m(sum(r["amount"] for r in rows))]], "bucket:" + kind)
    buckets = bucket_table(rows, period)
    total = _r2(sum(r["amount"] for r in rows))
    pg = make_pg(len(rows), 30)
    show = list(reversed(rows))[pg["off"]:pg["off"] + 30]
    tabs, cur = _rtabs(d1, d2, period, kind)
    return page(REPORT_HEAD + """<div class="card"><h3>{{title}} — {{'মাসিক' if period=='monthly' else 'দৈনিক'}}</h3><div class="v">৳ {{money(total)}} <span class="k">({{n}}টি)</span></div>
<div class="tw"><table><tr><th>{{'মাস' if period=='monthly' else 'তারিখ'}}</th><th>সংখ্যা</th><th>৳</th></tr>
{% for b,a,c in buckets %}<tr><td>{{b}}</td><td>{{c}}</td><td>{{money(a)}}</td></tr>{% endfor %}{% if not buckets %}<tr><td colspan="3" class="k">এই সময়ে কোনো লেনদেন নেই</td></tr>{% endif %}</table></div>
<a class="btn sm s" href="?from={{d1}}&to={{d2}}&period={{period}}&fmt=csv">⬇ সারাংশ CSV</a> <a class="btn sm s" href="?from={{d1}}&to={{d2}}&fmt=csv&detail=1">⬇ বিস্তারিত CSV</a></div>
<div class="card"><h3>লেনদেনের তালিকা (নতুন আগে)</h3><div class="tw"><table><tr><th>সময়</th><th>ইউজার</th><th>ধরন</th><th>৳</th><th>রেফারেন্স</th></tr>
{% for r in show %}<tr><td>{{loc(r['ts'])}}</td><td>{% if r['uid'] %}<a href="/admin/reports/user/{{r['uid']}}?from={{d1}}&to={{d2}}">#{{r['member']}}</a>{% endif %}</td><td>{{r['what']}}{% if kind in ('commissions','referrals') %} <span class="k">{{'পুল' if r['funded'] else 'পুল-পূর্ব'}}</span>{% endif %}</td><td>{{money(r['amount'])}}</td><td class="k">{{r['ref']}}</td></tr>{% endfor %}</table></div></div>""" + PAGER,
                active="/admin/reports", rtabs=tabs, cur=cur, rerr=e, filt=True, d1=d1, d2=d2, period=period, tz=("%g" % rtz()), title=REPORT_KINDS[kind], kind=kind,
                total=total, n=len(rows), buckets=buckets, show=show, pg=pg, loc=lambda t: _MARK + _loc(t))


@app.route("/admin/reports/user/<int:i>")
@staff_required("reports")
def admin_report_user(i):
    x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (i,))
    if not x:
        abort(404)
    d1, d2, u1, u2, e = report_range()
    if e and _want_csv():
        abort(400)  # never export a file for a filter the person did not actually ask for
    opening = _r2(q1("SELECT COALESCE(SUM(amount),0) s FROM ledger WHERE user_id=? AND created<?", (i, u1))["s"])
    led = qa("SELECT * FROM ledger WHERE user_id=? AND created>=? AND created<? ORDER BY created, id", (i, u1, u2))
    run, lines, sums = opening, [], {}
    for r in led:
        run = _r2(run + float(r["amount"]))
        lines.append((r, run))
        sums[r["kind"]] = _r2(sums.get(r["kind"], 0) + float(r["amount"]))
    net = _r2(sum(sums.values()))
    if _want_csv():
        return csv_download("user_%s_%s_%s.csv" % (x["member_id"], d1, d2), ["time_local", "type", "amount", "balance_after", "reference", "note", "by"],
                            [[_loc(r["created"]), r["kind"], _m(r["amount"]), _m(b), "%s#%s" % (r["ref_type"] or "-", r["ref_id"] or "-"), r["note"] or "", r["actor"] or ""] for r, b in lines],
                            "user#%d" % i)
    pg = make_pg(len(lines), 40)
    tabs, cur = _rtabs(d1, d2, "daily", "")
    return page(REPORT_HEAD + """<div class="card"><h2>#{{x['member_id']}} {{x['name']}}</h2><p class="k">📱 {{x['phone']}} · বর্তমান ব্যালেন্স ৳{{money(x['balance'])}} · মোট কমিশন ৳{{money(x['commission'])}} · <a href="/admin/users/{{x['id']}}">প্রোফাইল</a></p></div>
<div class="g2"><div class="card"><div class="k">শুরুর ব্যালেন্স</div><div class="v">৳ {{money(opening)}}</div></div><div class="card"><div class="k">নিট পরিবর্তন</div><div class="v">৳ {{money(net)}}</div></div>
<div class="card"><div class="k">শেষ ব্যালেন্স</div><div class="v">৳ {{money(opening+net)}}</div></div></div>
<div class="card"><h3>ধরন অনুযায়ী</h3>{% for k,v in sums.items() %}<div class="row" style="justify-content:space-between"><span>{{lk.get(k,k)}}</span><b>{{money(v)}}</b></div>{% endfor %}{% if not sums %}<div class="k">এই সময়ে কোনো এন্ট্রি নেই</div>{% endif %}</div>
<div class="card"><h3>স্টেটমেন্ট</h3><div class="tw"><table><tr><th>সময়</th><th>ধরন</th><th>৳</th><th>ব্যালেন্স</th><th>কারণ/রেফারেন্স</th></tr>
{% for r,b in lines %}<tr><td>{{loc(r['created'])}}</td><td>{{lk.get(r['kind'],r['kind'])}}</td><td>{{money(r['amount'])}}</td><td>{{money(b)}}</td><td class="k">{{r['note'] or ''}}</td></tr>{% endfor %}</table></div>
<a class="btn sm s" href="?from={{d1}}&to={{d2}}&fmt=csv">⬇ CSV</a></div>""" + PAGER,
                active="/admin/reports", rtabs=tabs, cur=cur, rerr=e, filt=True, d1=d1, d2=d2, period="daily", tz=("%g" % rtz()), x=x, opening=opening, net=net, sums=sums,
                lines=lines[pg["off"]:pg["off"] + 40], pg=pg, loc=lambda t: _MARK + _loc(t), lk=LK_LABEL)


@app.route("/admin/reports/wallets")
@staff_required("reports")
def admin_report_wallets():
    one = lambda sql, a=(): q1(sql, a)["s"]
    t = dict(users=one("SELECT COUNT(*) s FROM users WHERE is_admin=0"), funded=one("SELECT COUNT(*) s FROM users WHERE is_admin=0 AND balance>0"),
             wallet=_r2(one("SELECT COALESCE(SUM(balance),0) s FROM users WHERE is_admin=0")), comm=_r2(one("SELECT COALESCE(SUM(commission),0) s FROM users WHERE is_admin=0")),
             held=_r2(one("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE kind='withdraw' AND status IN ('pending','processing')")), pool=pool_balance(), res=pool_reserved())
    q = request.args.get("q", "").strip()[:40]
    w, a = ("", [])
    if q:
        w, a = " AND (member_id LIKE ? OR name LIKE ? OR phone LIKE ?)", ["%%%s%%" % q] * 3
    if _want_csv():
        rows = qa("SELECT member_id,name,phone,balance,commission,blocked FROM users WHERE is_admin=0" + w + " ORDER BY id", a)
        return csv_download("wallets_%s.csv" % local_today(), ["member_id", "name", "phone", "balance", "commission_total", "blocked"],
                            [[r["member_id"], r["name"], r["phone"], _m(r["balance"]), _m(r["commission"]), "yes" if r["blocked"] else "no"] for r in rows] +
                            [["TOTAL", "", "", _m(t["wallet"]), _m(t["comm"]), ""]], "wallets")
    pg = make_pg(q1("SELECT COUNT(*) n FROM users WHERE is_admin=0" + w, a)["n"], 25)
    rows = qa("SELECT id,member_id,name,phone,balance,commission,blocked FROM users WHERE is_admin=0" + w + " ORDER BY balance DESC, id LIMIT ? OFFSET ?", a + [25, pg["off"]])
    tabs, cur = _rtabs(local_today(), local_today(), "daily", "wallets")
    return page(REPORT_HEAD + """<div class="g2"><div class="card"><div class="k">মোট ওয়ালেট ব্যালেন্স (ক্লায়েন্টদের কাছে আমাদের দায়)</div><div class="v">৳ {{money(t.wallet)}}</div><div class="k">{{t.users}} ইউজার · ব্যালেন্সসহ {{t.funded}}</div></div>
<div class="card"><div class="k">মোট কমিশন (জমা)</div><div class="v">৳ {{money(t.comm)}}</div></div>
<div class="card"><div class="k">উইথড্রের জন্য আটকে আছে</div><div class="v">৳ {{money(t.held)}}</div></div>
<div class="card"><div class="k">কমিশন পুল</div><div class="v">৳ {{money(t.pool)}}</div><div class="k">প্রতিশ্রুত ৳{{money(t.res)}}</div></div></div>
<form method="get" class="card"><input name="q" value="{{q}}" placeholder="নাম / ফোন / মেম্বার আইডি"><button style="width:100%">খুঁজুন</button></form>
<div class="card"><div class="tw"><table><tr><th>ইউজার</th><th>ব্যালেন্স</th><th>কমিশন</th></tr>{% for r in rows %}<tr><td><a href="/admin/reports/user/{{r['id']}}">#{{r['member_id']}} {{r['name']}}</a>{% if r['blocked'] %} 🔒{% endif %}</td><td>{{money(r['balance'])}}</td><td>{{money(r['commission'])}}</td></tr>{% endfor %}</table></div>
<a class="btn sm s" href="?q={{q}}&fmt=csv">⬇ CSV</a></div>""" + PAGER,
                active="/admin/reports", rtabs=tabs, cur=cur, rerr=None, filt=False, tz=("%g" % rtz()), t=t, q=q, rows=rows, pg=pg)


# ---- reconciliation: every figure re-derived from the immutable ledgers
def recon_checks():
    c = []  # (level, title, detail)   level: ok | warn | fail
    add = lambda lv, t, d="": c.append((lv, t, d))
    n_users = q1("SELECT COUNT(*) n FROM users")["n"]
    bad = reconcile()
    add("fail" if bad else "ok", "ওয়ালেট ব্যালেন্স = ব্যবহারকারীর লেজারের যোগফল", ("%d জনের গরমিল: %s" % (len(bad), ", ".join("#" + b["member_id"] for b in bad[:5]))) if bad else "%d জন ইউজার মিলেছে" % n_users)
    neg = q1("SELECT COUNT(*) n FROM users WHERE balance<-0.004")["n"]
    add("fail" if neg else "ok", "কোনো ওয়ালেট ঋণাত্মক নয়", "%d জন ঋণাত্মক" % neg if neg else "")
    cb = qa("SELECT u.member_id FROM users u LEFT JOIN ledger l ON l.user_id=u.id AND l.kind IN ('commission','commission_reversal') "
            "GROUP BY u.id, u.member_id, u.commission HAVING ABS(u.commission-COALESCE(SUM(l.amount),0))>0.005")
    add("fail" if cb else "ok", "ইউজারের কমিশন-মোট = লেজারের কমিশন এন্ট্রি", ("গরমিল: " + ", ".join("#" + b["member_id"] for b in cb[:5])) if cb else "")
    bal = pool_balance()
    ls = _r2(q1("SELECT COALESCE(SUM(amount),0) s FROM pool_ledger")["s"])
    add("fail" if (abs(bal - ls) > 0.005 or bal < 0) else "ok", "পুল ব্যালেন্স = পুল-লেজারের যোগফল (এবং ০-এর নিচে নয়)", "ব্যালেন্স ৳%s · লেজার ৳%s" % (money(bal), money(ls)))
    f = q1("SELECT COALESCE(SUM(CASE WHEN kind='fund' THEN amount END),0) f, COALESCE(SUM(CASE WHEN kind='payout' THEN -amount END),0) p, "
           "COALESCE(SUM(CASE WHEN kind='reversal' THEN amount END),0) r, COALESCE(SUM(CASE WHEN kind='withdraw' THEN -amount END),0) w FROM pool_ledger")
    ident = _r2(f["f"] - f["p"] + f["r"] - f["w"])
    add("fail" if abs(ident - bal) > 0.005 else "ok", "পুল সমীকরণ: যোগ − প্রদত্ত + ফেরত − তোলা = ব্যালেন্স",
        "৳%s − ৳%s + ৳%s − ৳%s = ৳%s" % (money(f["f"]), money(f["p"]), money(f["r"]), money(f["w"]), money(ident)))
    link = q1("SELECT COUNT(*) n FROM pool_ledger p LEFT JOIN ledger l ON l.idem=p.ledger_idem WHERE p.kind IN ('payout','reversal') AND (l.id IS NULL OR ABS(l.amount+p.amount)>0.005)")["n"]
    add("fail" if link else "ok", "প্রতিটি পুল-প্রদান/ফেরত ঠিক একটি ইউজার-লেজার এন্ট্রির সঙ্গে মেলে", "%d টি মেলেনি" % link if link else "")
    ps = q1("SELECT v FROM meta WHERE k='pool_since'")
    since = ps["v"] if ps else now()
    unb = q1("SELECT COUNT(*) n, COALESCE(SUM(l.amount),0) s FROM ledger l WHERE l.kind IN ('commission','referral_bonus') AND l.amount>0 AND l.created>=? "
             "AND NOT EXISTS (SELECT 1 FROM pool_ledger p WHERE p.ledger_idem=l.idem)", (since,))
    add("fail" if unb["n"] else "ok", "পুল চালুর পর কোনো কমিশন/রেফারেল বোনাস পুল ছাড়া দেওয়া হয়নি", "%d টি, ৳%s পুল-ছাড়া" % (unb["n"], money(unb["s"])) if unb["n"] else "সব পুল-ভিত্তিক")
    co = _r2(q1("SELECT COALESCE(SUM(amount),0) s FROM company_ledger")["s"])
    cp = _r2(q1("SELECT COALESCE(SUM(amount),0) s FROM requests WHERE flow='client_confirm' AND status='approved'")["s"])
    add("fail" if abs(co - cp) > 0.005 else "ok", "কোম্পানি-লেজার = অনুমোদিত ক্লায়েন্ট-পেমেন্টের মূল টাকা", "৳%s / ৳%s" % (money(co), money(cp)))
    res = pool_reserved()
    add("warn" if res > bal + 0.005 else "ok", "প্রতিশ্রুত কমিশন পুলের মধ্যে আছে", "প্রতিশ্রুত ৳%s · পুল ৳%s" % (money(res), money(bal)))
    att = q1("SELECT * FROM pool_attestations ORDER BY id DESC LIMIT 1")
    if not att:
        add("warn", "বাস্তব ফান্ড মিলানো", "এখনো কোনো রেকর্ড নেই — আলাদা অ্যাকাউন্টের আসল ব্যালেন্স রেকর্ড করুন (পুল পেজ)")
    elif abs(float(att["difference"])) > 0.005:
        add("fail", "বাস্তব ফান্ড মিলানো", "সর্বশেষ (%s): ঘোষিত ৳%s, লেজার ৳%s — পার্থক্য ৳%s" % (att["created"][:16], money(att["declared_balance"]), money(att["ledger_balance"]), money(att["difference"])))
    else:
        age = (datetime.utcnow() - datetime.strptime(att["created"][:19], "%Y-%m-%d %H:%M:%S")).days
        stale = abs(float(att["ledger_balance"]) - bal) > 0.005 or age > 7
        add("warn" if stale else "ok", "বাস্তব ফান্ড মিলানো", "সর্বশেষ %s — মিলেছে%s" % (att["created"][:16], " (পুল বদলেছে/৭ দিনের বেশি পুরনো — আবার মিলিয়ে নিন)" if stale else ""))
    lg = q1("SELECT COUNT(*) n, COALESCE(SUM(l.amount),0) s FROM ledger l WHERE l.kind IN ('commission','referral_bonus') AND l.amount>0 AND l.created<? "
            "AND NOT EXISTS (SELECT 1 FROM pool_ledger p WHERE p.ledger_idem=l.idem)", (since,))
    add("warn" if lg["n"] else "ok", "পুল-পূর্ব (legacy) কমিশন/বোনাস", ("%d টি, মোট ৳%s — পুল চালুর আগে দেওয়া, পুল দ্বারা সমর্থিত নয় (ইতিহাস অপরিবর্তিত)" % (lg["n"], money(lg["s"]))) if lg["n"] else "নেই")
    ad = q1("SELECT COALESCE(SUM(CASE WHEN amount>0 THEN amount END),0) p, COALESCE(SUM(CASE WHEN amount<0 THEN -amount END),0) m, COUNT(*) n FROM ledger WHERE kind='admin_adjust'")
    add("ok", "ম্যানুয়াল ব্যালেন্স সমন্বয় (তথ্য)", "%d টি · যোগ ৳%s · বিয়োগ ৳%s (প্রতিটির রেফারেন্স সংরক্ষিত)" % (ad["n"], money(ad["p"]), money(ad["m"])))
    return c


def recon_overall(checks):
    lv = [x[0] for x in checks]
    return "fail" if "fail" in lv else ("warn" if "warn" in lv else "ok")


@app.route("/admin/reconcile")
@staff_required("reports")
def admin_reconcile():
    ch = recon_checks()
    ov = recon_overall(ch)
    return page("""<div class="msg {{'ok' if ov=='ok' else 'error'}}">{% if ov=='ok' %}✅ সব হিসাব মিলছে{% elif ov=='warn' %}⚠ হিসাব মিলছে, তবে কিছু বিষয় দেখা দরকার{% else %}❌ গরমিল পাওয়া গেছে — আর্থিক কাজ থামিয়ে অডিট করুন{% endif %}</div>
<div class="card"><h3>মিলানো-ড্যাশবোর্ড</h3><p class="k">প্রতিটি সংখ্যা অপরিবর্তনীয় লেজার থেকে নতুন করে হিসাব করা হয়। এই পেজ শুধু দেখায়, কিছু বদলায় না।</p>
{% for lv,t,d in ch %}<div class="card" style="margin:8px 0"><b>{{'✅' if lv=='ok' else ('⚠' if lv=='warn' else '❌')}} {{t}}</b>{% if d %}<div class="k">{{d}}</div>{% endif %}</div>{% endfor %}
<p class="k">পরীক্ষার সময়: {{ts[:16]}} (UTC)</p>{% if can('pool_view') %}<a class="btn sm s" href="/admin/pool">কমিশন পুল</a>{% endif %} <a class="btn sm s" href="/admin/reports">রিপোর্ট</a></div>""",
                active="/admin/reconcile", ch=ch, ov=ov, ts=now())


# ---- referral network (who referred whom, dates, totals, reward history)
@app.route("/admin/referrals/network")
@staff_required("referrals")
def admin_ref_network():
    q = request.args.get("q", "").strip()[:40]
    w, a = ("", [])
    if q:
        w, a = " WHERE (u.member_id LIKE ? OR u.name LIKE ? OR u.phone LIKE ?)", ["%%%s%%" % q] * 3
    pg = make_pg(q1("SELECT COUNT(*) n FROM (SELECT u.id FROM users u JOIN referrals r ON r.referrer_id=u.id" + w + " GROUP BY u.id) t", a)["n"], 25)
    rows = qa("SELECT u.id, u.member_id, u.name, u.phone, COUNT(r.id) total, COALESCE(SUM(CASE WHEN r.status='pending' THEN 1 ELSE 0 END),0) pend, "
              "COALESCE(SUM(CASE WHEN r.status='approved' THEN 1 ELSE 0 END),0) appr, COALESCE(SUM(CASE WHEN r.status='rejected' THEN 1 ELSE 0 END),0) rej, "
              "COALESCE(SUM(CASE WHEN r.status='approved' THEN r.amount END),0) paid FROM users u JOIN referrals r ON r.referrer_id=u.id" + w +
              " GROUP BY u.id, u.member_id, u.name, u.phone ORDER BY total DESC, u.id LIMIT ? OFFSET ?", a + [25, pg["off"]])
    t = q1("SELECT COUNT(*) n, COUNT(DISTINCT referrer_id) ref, COALESCE(SUM(CASE WHEN status='approved' THEN amount END),0) paid FROM referrals")
    return page("""<div class="row" style="margin-bottom:10px"><a class="btn sm s" href="/admin/referrals">📋 তালিকা</a><a class="btn sm" href="/admin/referrals/network">🌐 নেটওয়ার্ক</a></div>
<div class="g2"><div class="card"><div class="k">মোট রেফারেল</div><div class="v">{{t['n']}}</div></div><div class="card"><div class="k">রেফারার সংখ্যা</div><div class="v">{{t['ref']}}</div></div>
<div class="card"><div class="k">মোট পরিশোধিত বোনাস (পুল থেকে)</div><div class="v">৳ {{money(t['paid'])}}</div></div></div>
<form method="get" class="card"><input name="q" value="{{q}}" placeholder="রেফারারের নাম / ফোন / মেম্বার আইডি"><button style="width:100%">খুঁজুন</button></form>
{% if not rows %}<div class="card empty">কোনো রেফারার নেই</div>{% endif %}
{% for r in rows %}<div class="card"><a href="/admin/referrals/user/{{r['id']}}"><b>#{{r['member_id']}} {{r['name']}}</b></a> <span class="k">{{r['phone']}}</span>
<div class="k">মোট {{r['total']}} · অনুমোদিত {{r['appr']}} · পেন্ডিং {{r['pend']}} · বাতিল {{r['rej']}} · বোনাস ৳{{money(r['paid'])}}</div></div>{% endfor %}""" + PAGER,
                active="/admin/referrals", rows=rows, t=t, q=q, pg=pg)


@app.route("/admin/referrals/user/<int:i>")
@staff_required("referrals")
def admin_ref_user(i):
    x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (i,))
    if not x:
        abort(404)
    by = q1("SELECT r.*, rf.member_id mid, rf.name nm FROM referrals r JOIN users rf ON rf.id=r.referrer_id WHERE r.referred_id=?", (i,))
    kids = qa("SELECT r.*, y.member_id mid, y.name nm, y.phone ph, y.created joined FROM referrals r JOIN users y ON y.id=r.referred_id WHERE r.referrer_id=? ORDER BY r.id DESC", (i,))
    paid = qa("SELECT l.*, EXISTS(SELECT 1 FROM pool_ledger p WHERE p.ledger_idem=l.idem) funded FROM ledger l WHERE l.user_id=? AND l.kind='referral_bonus' ORDER BY l.id DESC LIMIT 50", (i,))
    st = {k: sum(1 for r in kids if r["status"] == k) for k in ("pending", "approved", "rejected")}
    return page("""<div class="row" style="margin-bottom:10px"><a class="btn sm s" href="/admin/referrals">📋 তালিকা</a><a class="btn sm s" href="/admin/referrals/network">🌐 নেটওয়ার্ক</a></div>
<div class="card"><h2>#{{x['member_id']}} {{x['name']}}</h2><p class="k">📱 {{x['phone']}} · কোড: {{x['referral_code']}} · <a href="/admin/users/{{x['id']}}">প্রোফাইল</a>{% if can('reports') %} · <a href="/admin/reports/user/{{x['id']}}">রিপোর্ট</a>{% endif %}</p>
<div class="k">রেফার করেছেন: <b>{{kids|length}}</b> · অনুমোদিত {{st['approved']}} · পেন্ডিং {{st['pending']}} · বাতিল {{st['rejected']}}</div></div>
<div class="card"><h3>কে একে রেফার করেছেন</h3>{% if by %}<a href="/admin/referrals/user/{{by['referrer_id']}}">#{{by['mid']}} {{by['nm']}}</a> <span class="k">· {{by['created'][:16]}} · {{by['status']}} · ৳{{money(by['amount'])}}</span>{% else %}<span class="k">কেউ নয় (সরাসরি যোগদান)</span>{% endif %}</div>
<div class="card"><h3>যাদের রেফার করেছেন</h3>{% for r in kids %}<div class="row" style="justify-content:space-between;align-items:center"><span><a href="/admin/referrals/user/{{r['referred_id']}}">#{{r['mid']}} {{r['nm']}}</a> <span class="k">{{r['joined']|bdd if r['joined'] else ''}}</span></span><span class="k">{{r['status']}} · ৳{{money(r['amount'])}}{% if r['decided_at'] %} · {{r['decided_at']|bdd}}{% endif %}</span></div>{% endfor %}{% if not kids %}<div class="k">কাউকে রেফার করেননি</div>{% endif %}</div>
<div class="card"><h3>রেফারেল বোনাসের ইতিহাস (ওয়ালেটে জমা)</h3>{% for l in paid %}<div class="row" style="justify-content:space-between"><span class="k">{{l['created'][:16]}} · {{l['note'] or ''}}</span><b>৳{{money(l['amount'])}} <span class="k">{{'পুল' if l['funded'] else 'পুল-পূর্ব'}}</span></b></div>{% endfor %}{% if not paid %}<div class="k">কোনো বোনাস পাননি</div>{% endif %}</div>""",
                active="/admin/referrals", x=x, by=by, kids=kids, paid=paid, st=st)




# ---------------------------------------------------------------- KYC (NID front/back). Stored in the existing `meta` table (key kyc:<user id>, JSON) - no schema change.
KYC_LABEL = {"none": "যাচাই করা হয়নি", "pending": "অপেক্ষমাণ", "approved": "অনুমোদিত", "rejected": "রিজেক্ট"}


def kyc_get(uid):
    r = q1("SELECT v FROM meta WHERE k=?", ("kyc:%d" % uid,))
    if not r:
        return None
    try:
        d = _json.loads(r["v"])
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


def kyc_put(uid, d):
    db().execute("INSERT OR REPLACE INTO meta VALUES(?,?)", ("kyc:%d" % uid, _json.dumps(d, ensure_ascii=False)))


def kyc_status(uid):
    d = kyc_get(uid)
    return d["status"] if d and d.get("status") in KYC_LABEL else "none"


def _kyc_all():
    out = []
    for r in qa("SELECT k,v FROM meta WHERE k LIKE ?", ("kyc:%",)):
        try:
            d, uid = _json.loads(r["v"]), int(r["k"].split(":", 1)[1])
        except (ValueError, IndexError):
            continue
        if isinstance(d, dict):
            d["uid"] = uid
            out.append(d)
    return out


@app.route("/kyc", methods=["GET", "POST"])
@customer_required
def kyc_page():
    u = me()
    if request.method == "POST":
        if (kyc_get(u["id"]) or {}).get("status") in ("pending", "approved"):
            err("আপনার KYC এখন আর জমা দেওয়া যাবে না।"); return redirect("/kyc")
        if rate_hit("kyc:%d" % u["id"], 6, 3600):
            err("অনেক চেষ্টা হয়েছে, পরে আবার চেষ্টা করুন।"); return redirect("/kyc")
        f_name, e1 = save_shot(request.files.get("front"))
        if e1 or not f_name:
            err(e1 or "NID-এর সামনের পাশের ছবি দিন।"); return redirect("/kyc")
        b_name, e2 = save_shot(request.files.get("back"))
        if e2 or not b_name:
            store_delete(f_name)
            err(e2 or "NID-এর পেছনের পাশের ছবি দিন।"); return redirect("/kyc")
        old = []
        try:
            with atomic():
                cur = kyc_get(u["id"]) or {}
                if cur.get("status") in ("pending", "approved"):
                    raise ReqError("আপনার KYC এখন আর জমা দেওয়া যাবে না।")
                old = [cur.get("front"), cur.get("back")]
                hist = list(cur.get("hist") or [])[-9:]
                if cur.get("status") == "rejected":
                    hist.append({"status": "rejected", "reason": cur.get("reason", ""), "at": cur.get("decided", "")})
                kyc_put(u["id"], {"status": "pending", "front": f_name, "back": b_name, "submitted": now(), "hist": hist})
                alert_admins("নতুন KYC আবেদন", "#%s %s" % (u["member_id"], u["name"]), "/admin/kyc/%d" % u["id"], "kyc")
                audit("kyc_submit", "user#%d" % u["id"])
        except ReqError as ex:
            store_delete(f_name); store_delete(b_name)
            err(str(ex)); return redirect("/kyc")
        except Exception:
            store_delete(f_name); store_delete(b_name)
            raise
        for n in old:
            store_delete(n)  # replaced (rejected) documents are not kept
        flash("KYC জমা হয়েছে। যাচাইয়ের পর জানানো হবে।"); return redirect("/kyc")
    notif_read_link(u["id"], "/kyc")
    d = kyc_get(u["id"]) or {}
    st = d.get("status") if d.get("status") in KYC_LABEL else "none"
    return page("""<div class="card"><h2>🪪 KYC যাচাই</h2>
<div class="row" style="align-items:center"><span>বর্তমান অবস্থা</span><span class="pill {{st if st!='none' else ''}}" style="flex:0;white-space:nowrap">{{lab[st]}}</span></div>
{% if st=='rejected' %}<div class="msg error" style="margin-top:10px">রিজেক্টের কারণ: {{d.get('reason') or '-'}}<br>নিচে সঠিক ছবি দিয়ে আবার জমা দিন।</div>{% endif %}
{% if st=='pending' %}<p class="k">আপনার NID কার্ডের ছবি জমা হয়েছে। যাচাই শেষ হলে জানানো হবে।</p>{% endif %}
{% if st=='approved' %}<p class="k">✅ আপনার KYC যাচাই সম্পন্ন হয়েছে।</p>{% endif %}</div>
{% if st in ('none','rejected') %}<div class="card"><h3>NID কার্ডের ছবি জমা দিন</h3>
<form method="post" enctype="multipart/form-data" id="kf" data-confirm="ছবি দুটি ঠিক আছে? জমা দেবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>NID — সামনের পাশ (Front)</label><input type="file" name="front" accept="image/*" required>
<label>NID — পেছনের পাশ (Back)</label><input type="file" name="back" accept="image/*" required>
<p class="k">JPG/PNG/WEBP, প্রতিটি ≤২MB। ছবি পরিষ্কার ও সম্পূর্ণ হতে হবে। শুধু অনুমোদিত অ্যাডমিন এটি দেখতে পারবেন।</p>
<button style="width:100%">জমা দিন</button></form></div>
<script>(function(){function shrink(inp){inp.addEventListener('change',function(){var f=inp.files&&inp.files[0];if(!f||f.size<1500000||f.type.indexOf('image/')!==0||!window.DataTransfer)return;
 var img=new Image(),url=URL.createObjectURL(f);img.onload=function(){var s=Math.min(1,1600/Math.max(img.width,img.height)),c=document.createElement('canvas');c.width=Math.round(img.width*s);c.height=Math.round(img.height*s);
 c.getContext('2d').drawImage(img,0,0,c.width,c.height);c.toBlob(function(b){URL.revokeObjectURL(url);if(!b)return;var dt=new DataTransfer();dt.items.add(new File([b],'nid.jpg',{type:'image/jpeg'}));inp.files=dt.files},'image/jpeg',.85)};img.src=url})}
 document.querySelectorAll('#kf input[type=file]').forEach(shrink)})()</script>{% endif %}
<a class="btn s" href="/account" style="width:100%">← অ্যাকাউন্টে ফিরুন</a>""", active="/account", st=st, d=d, lab=KYC_LABEL)


@app.route("/kyc/img/<int:uid>/<side>")
@login_required
def kyc_img(uid, side):
    """NID image: only the owner or staff holding the 'kyc' permission (never public)."""
    u = me()
    if side not in ("front", "back") or not (u["id"] == uid or has_perm("kyc", u)):
        abort(404)
    d = kyc_get(uid)
    name = d.get(side) if d else None
    if not name or not SHOT_RE.fullmatch(name):
        abort(404)
    try:
        data = store_get(name)
    except StorageError:
        abort(503)
    if data is None:
        abort(404)
    if u["id"] != uid:
        audit("kyc_view", "user#%d %s" % (uid, side))
    resp = send_file(io.BytesIO(data), mimetype=MIME[name.rsplit(".", 1)[1]])
    resp.headers["Cache-Control"] = "private, no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/admin/kyc")
@staff_required("kyc")
def admin_kyc():
    st = request.args.get("status", "pending")
    if st not in ("pending", "approved", "rejected", "all"):
        st = "pending"
    items = _kyc_all()
    cnt = {k: sum(1 for d in items if d.get("status") == k) for k in ("pending", "approved", "rejected")}
    cnt["all"] = len(items)
    if st != "all":
        items = [d for d in items if d.get("status") == st]
    items.sort(key=lambda d: str(d.get("submitted") or ""), reverse=True)
    pg = make_pg(len(items), 20)
    items = items[pg["off"]:pg["off"] + 20]
    users = {}
    if items:
        for r in qa("SELECT id,name,phone,member_id FROM users WHERE id IN (%s)" % ",".join("?" * len(items)), [d["uid"] for d in items]):
            users[r["id"]] = r
    shown = {"/admin/kyc/%d" % d["uid"] for d in items}
    alerts_seen(lambda link, ts: link in shown)
    tabs = [("pending", "অপেক্ষমাণ"), ("approved", "অনুমোদিত"), ("rejected", "রিজেক্ট"), ("all", "সব")]
    return page("""<div class="row" style="margin-bottom:10px;flex-wrap:wrap;gap:6px">{% for k,l in tabs %}<a class="btn sm {{'' if k==st else 's'}}" href="?status={{k}}">{{l}} ({{cnt[k]}})</a>{% endfor %}</div>
{% if not items %}<div class="card empty">কোনো KYC আবেদন নেই</div>{% endif %}
{% for d in items %}{% set x = users.get(d['uid']) %}<a href="/admin/kyc/{{d['uid']}}"><div class="card"><div class="row" style="align-items:center"><b>{% if x %}#{{x['member_id']}} {{x['name']}}{% else %}ইউজার #{{d['uid']}}{% endif %}</b>
<span class="pill {{d['status']}}" style="flex:0;white-space:nowrap">{{kycl.get(d['status'], d['status'])}}</span></div>
<div class="k">{% if x %}{{x['phone']}} · {% endif %}জমা: {{(d.get('submitted') or '')[:16]}}</div></div></a>{% endfor %}""" + PAGER,
                active="/admin/kyc", tabs=tabs, st=st, cnt=cnt, items=items, users=users, pg=pg)


@app.route("/admin/kyc/<int:uid>")
@staff_required("kyc")
def admin_kyc_view(uid):
    x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (uid,))
    d = kyc_get(uid)
    if not x or not d:
        abort(404)
    alerts_seen(lambda link, ts: link == "/admin/kyc/%d" % uid)
    return page("""<div class="card"><div class="row" style="align-items:center"><h2 style="margin:0">🪪 KYC</h2>
<span class="pill {{d.get('status')}}" style="flex:0;white-space:nowrap">{{kycl.get(d.get('status'), d.get('status'))}}</span></div>
<div class="k" style="margin-top:8px"><a href="/admin/users/{{x['id']}}"><b>#{{x['member_id']}} {{x['name']}}</b></a> · {{x['phone']}}</div>
<div class="k">জমা: {{(d.get('submitted') or '')[:16]}}{% if d.get('decided') %} · সিদ্ধান্ত: {{d.get('decided')[:16]}} ({{d.get('by')}}){% endif %}</div>
{% if d.get('status')=='rejected' and d.get('reason') %}<div class="msg error" style="margin-top:8px">রিজেক্টের কারণ: {{d.get('reason')}}</div>{% endif %}
<h3>NID — সামনের পাশ</h3><a href="/kyc/img/{{x['id']}}/front" target="_blank"><img class="shot" src="/kyc/img/{{x['id']}}/front" alt="NID front"></a>
<h3>NID — পেছনের পাশ</h3><a href="/kyc/img/{{x['id']}}/back" target="_blank"><img class="shot" src="/kyc/img/{{x['id']}}/back" alt="NID back"></a></div>
{% if d.get('status')=='pending' %}<div class="card"><h3>সিদ্ধান্ত</h3>
<form method="post" action="/admin/kyc/{{x['id']}}/act" data-confirm="নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<input name="reason" placeholder="রিজেক্টের কারণ (রিজেক্টে আবশ্যক)" maxlength="200"><div class="row"><button name="act" value="approve" class="btn sm g">✅ অনুমোদন</button><button name="act" value="reject" class="btn sm r">❌ রিজেক্ট</button></div></form></div>{% endif %}
{% if d.get('hist') %}<div class="card"><h3>আগের রিজেক্ট</h3>{% for h in d.get('hist') %}<div class="k">{{(h.get('at') or '')[:16]}} · {{h.get('reason') or '-'}}</div>{% endfor %}</div>{% endif %}
<a class="btn s" href="/admin/kyc" style="width:100%">← সব KYC</a>""", active="/admin/kyc", x=x, d=d)


@app.route("/admin/kyc/<int:uid>/act", methods=["POST"])
@staff_required("kyc")
def admin_kyc_act(uid):
    act = request.form.get("act", "")
    reason = request.form.get("reason", "").strip()[:200]
    back_to = "/admin/kyc/%d" % uid
    if act not in ("approve", "reject"):
        abort(400)
    if act == "reject" and len(reason) < 3:
        err("রিজেক্টের কারণ লিখুন (কমপক্ষে ৩ অক্ষর)।"); return redirect(back_to)
    a = me()
    with atomic():
        d = kyc_get(uid)
        if not q1("SELECT 1 FROM users WHERE id=? AND is_admin=0", (uid,)) or not d:
            abort(404)
        if d.get("status") != "pending":
            err("এই আবেদনে এখন আর সিদ্ধান্ত নেওয়া যাবে না (হয়তো আগেই সম্পন্ন)।"); return redirect(back_to)
        ok = act == "approve"
        d.update(status="approved" if ok else "rejected", decided=now(), by=a["member_id"], reason="" if ok else reason)
        kyc_put(uid, d)
        if ok:
            notify(uid, "KYC অনুমোদিত", "আপনার KYC যাচাই সম্পন্ন হয়েছে।", "/kyc", "KYC approved", "Your KYC verification is complete.")
        else:
            notify(uid, "KYC রিজেক্ট", "আপনার KYC গৃহীত হয়নি। কারণ: %s। সঠিক ছবি দিয়ে আবার জমা দিন।" % reason, "/kyc",
                   "KYC rejected", "Your KYC was not accepted. Reason: %s. Please resubmit clear photos." % reason)
        audit("kyc_" + act, "user#%d %s" % (uid, reason))
        alerts_done("/admin/kyc/%d" % uid)
    flash("KYC অনুমোদিত হয়েছে।" if ok else "KYC রিজেক্ট করা হয়েছে।")
    return redirect(back_to)


# ---------------------------------------------------------------- PWA (installable app; only a static shell is ever cached - no private/financial data)
PWA_DIR = os.path.join(app.root_path, "static")


@app.route("/manifest.json")
def pwa_manifest():
    r = send_from_directory(PWA_DIR, "manifest.json", mimetype="application/manifest+json")
    r.headers["Cache-Control"] = "public, max-age=600"
    return r


SW_NOTIFY_JS = """
/* ---- browser notifications (appended by app.py) ---- */
self.addEventListener('install',function(){self.skipWaiting()});
self.addEventListener('activate',function(e){e.waitUntil(self.clients.claim())});
self.addEventListener('notificationclick',function(e){
  e.notification.close();
  var d=e.notification.data||{},url=new URL(d.url||'/',self.location.origin).href;
  e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(function(list){
    for(var i=0;i<list.length;i++){var c=list[i];
      if(new URL(c.url).origin===self.location.origin&&'focus' in c){
        return c.focus().then(function(w){return(w&&'navigate' in w)?w.navigate(url):null}).catch(function(){return self.clients.openWindow(url)})}}
    return self.clients.openWindow(url)}))});
"""


@app.route("/service-worker.js")
def pwa_service_worker():
    try:  # the existing static/service-worker.js is served unchanged, with the notification handlers appended
        with open(os.path.join(PWA_DIR, "service-worker.js"), "r", encoding="utf-8") as fh:
            base_js = fh.read()
    except OSError:
        base_js = ""
    r = Response(base_js + "\n" + SW_NOTIFY_JS, mimetype="application/javascript")
    r.headers["Cache-Control"] = "no-cache"
    r.headers["Service-Worker-Allowed"] = "/"
    return r


@app.route("/healthz")
def healthz():
    try:  # also keeps a free Supabase project from being paused when an uptime pinger calls this URL
        q1("SELECT 1")
    except DBERR:
        return "db unavailable", 503
    return "ok"


if not os.environ.get("EWALLET_SKIP_MIGRATE"):  # dbtool sets this to control the first import itself
    migrate()
# ---------------------------------------------------------------- VIP levels (permanent once approved by an authorised admin)
VIP_LEVELS = {"standard": dict(name="Standard", rate=5.0, n=0, dep=0, bal=0, rank=0),
              "gold": dict(name="Gold", rate=7.5, n=3, dep=10000, bal=30000, rank=1),
              "diamond": dict(name="Diamond", rate=10.0, n=3, dep=20000, bal=60000, rank=2)}


def vip_level_of(u):
    try:
        l = u["vip_level"]
    except (KeyError, IndexError):
        l = None
    return l if l in ("gold", "diamond") else "standard"


def _vip_free_deposits(uid, level):
    """Approved deposits that qualify for `level` and were never counted for another application (oldest first)."""
    L = VIP_LEVELS[level]
    return qa("SELECT id,amount FROM tx WHERE user_id=? AND kind='deposit' AND status='approved' AND amount>=? "
              "AND id NOT IN (SELECT tx_id FROM vip_deposit_use) ORDER BY id", (uid, L["dep"]))


def _vip_pending(uid):
    return q1("SELECT * FROM vip_applications WHERE user_id=? AND status='pending'", (uid,))


@app.route("/vip")
@customer_required
def vip_page():
    u = me()
    cur = vip_level_of(u)
    pend = _vip_pending(u["id"])
    bal = float(u["balance"] or 0)
    cards = []
    for key, L in VIP_LEVELS.items():
        free = len(_vip_free_deposits(u["id"], key)) if L["n"] else 0
        dep_ok, bal_ok = free >= L["n"], bal >= L["bal"]
        if L["rank"] < VIP_LEVELS[cur]["rank"] or key == cur:
            st = "current" if key == cur else "done"
        elif pend and pend["level"] == key:
            st = "pending"
        elif pend:
            st = "locked"
        else:
            st = "eligible" if (dep_ok and bal_ok) else "locked"
        cards.append(dict(key=key, L=L, free=min(free, L["n"]), dep_ok=dep_ok, bal_ok=bal_ok, st=st))
    hist = qa("SELECT * FROM vip_applications WHERE user_id=? ORDER BY id DESC LIMIT 5", (u["id"],))
    start = [c["key"] for c in cards].index(cur)
    return page("""<style>
.vp{display:flex;gap:14px;overflow-x:auto;scroll-snap-type:x mandatory;padding:4px 2px 12px;margin:0 -4px;-webkit-overflow-scrolling:touch;scrollbar-width:none}.vp::-webkit-scrollbar{display:none}
.vc{flex:0 0 100%;max-width:100%;scroll-snap-align:center;box-sizing:border-box}
.vcard{position:relative;border-radius:22px;padding:20px 20px 18px;color:#3b2a00;overflow:hidden;min-height:196px;box-shadow:0 10px 26px #b8860b59,inset 0 1px 0 #fff9;background:radial-gradient(120% 90% at 100% 0%,#fff6c455 0,#fff6c400 55%),linear-gradient(135deg,#f7e08a 0%,#e0aa2c 38%,#fbe9a0 62%,#c8901a 100%)}
.vcard.gold{background:radial-gradient(120% 90% at 100% 0%,#fff2b855 0,#fff2b800 55%),linear-gradient(135deg,#f3d36b 0%,#d49a1c 40%,#f6dc84 65%,#b97f10 100%)}
.vcard.diamond{color:#2a1e00;background:radial-gradient(120% 90% at 100% 0%,#ffffffaa 0,#fff0 55%),linear-gradient(135deg,#fff1b0 0%,#f0c040 30%,#fff7cf 55%,#d9a21f 80%,#b8860b 100%)}
.vcard::after{content:"";position:absolute;inset:0;background:repeating-linear-gradient(115deg,#ffffff14 0 2px,#fff0 2px 14px);pointer-events:none}
.vtop{display:flex;justify-content:space-between;align-items:center;position:relative;z-index:1}
.vnet{font-weight:800;font-style:italic;font-size:22px;letter-spacing:.5px;color:#4a3300}
.vchip{width:42px;height:32px;border-radius:7px;background:linear-gradient(135deg,#fdf0b5,#b98a1f);border:1px solid #8a620f66;margin:14px 0 8px;position:relative;z-index:1}
.vlv{font-size:26px;font-weight:800;position:relative;z-index:1;letter-spacing:.3px}
.vrate{font-size:15px;font-weight:700;position:relative;z-index:1}
.vnum{font-family:ui-monospace,monospace;letter-spacing:3px;font-size:14px;margin-top:10px;position:relative;z-index:1;opacity:.85}
.vbd{display:inline-block;padding:3px 10px;border-radius:99px;font-size:11.5px;font-weight:700;background:#3b2a00;color:#ffe9a3}
.vreq{margin-top:10px;font-size:13.5px;line-height:1.6}.vreq .ok{color:#0B7A4B;font-weight:700}.vreq .no{color:#b45309;font-weight:700}
.vdots{display:flex;justify-content:center;gap:7px;margin:0 0 12px}.vdots i{width:7px;height:7px;border-radius:50%;background:var(--ln)}.vdots i.on{background:#d49a1c;width:20px;border-radius:6px}
</style>
<div class="cc-h">👑 VIP Membership</div><div class="cc-sub">Swipe to compare levels. Once approved, your VIP level and commission rate stay permanent.</div>
<div class="vdots" id="vd">{% for c in cards %}<i></i>{% endfor %}</div>
<div class="vp" id="vp">{% for c in cards %}<div class="vc"><div class="vcard {{c.key}}">
<div class="vtop"><span class="vbd">{% if c.st=='current' %}{{'✓ CURRENT MEMBERSHIP' if c.key=='standard' else '✓ CURRENT'}}{% elif c.st=='pending' %}⏳ PENDING{% elif c.key=='standard' %}STANDARD{% else %}VIP{% endif %}</span><span class="vnet">{% if c.key!='standard' %}VIP{% endif %}</span></div>
<div class="vchip"></div><div class="vlv">{{c.L.name}}</div><div class="vrate">{{c.L.rate|pct}}% commission</div>
<div class="vnum">{{u['member_id']}} · {{c.L.name|upper}}</div></div>
<div class="card" style="margin-top:10px">{% if c.key=='standard' %}<div class="vreq"><div>সবার জন্য প্রযোজ্য।</div><div>কোনো শর্ত নেই।</div><div>কমিশন ৫%।</div></div>
{% else %}<div class="vreq"><div class="{{'ok' if c.dep_ok else 'no'}}">{{'✓' if c.dep_ok else '○'}} {{'কমপক্ষে ১০,০০০ টাকা করে ৩টি সফল ডিপোজিট করতে হবে।' if c.key=='gold' else 'কমপক্ষে ২০,০০০ টাকা করে ৩টি সফল ডিপোজিট করতে হবে।'}}</div>
<div class="{{'ok' if c.bal_ok else 'no'}}">{{'✓' if c.bal_ok else '○'}} {{'অ্যাকাউন্টে কমপক্ষে ৩০,০০০ টাকা ব্যালেন্স থাকতে হবে।' if c.key=='gold' else 'অ্যাকাউন্টে কমপক্ষে ৬০,০০০ টাকা ব্যালেন্স থাকতে হবে।'}}</div>
<div class="k" style="margin-top:4px">{{'শর্ত পূরণ হলে VIP পাওয়ার জন্য আবেদন করতে হবে। Admin অনুমোদন দিলে ৭.৫% কমিশন কার্যকর হবে।' if c.key=='gold' else 'শর্ত পূরণ হলে VIP পাওয়ার জন্য আবেদন করতে হবে। Admin অনুমোদন দিলে ১০% কমিশন কার্যকর হবে।'}}</div></div>
{% if c.st=='eligible' %}<form method="post" action="/vip/apply" data-confirm="Apply for {{c.L.name}} VIP?"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="level" value="{{c.key}}"><button style="width:100%;margin-top:10px">Apply for {{c.L.name}}</button></form>
{% elif c.st=='pending' %}<div class="hl" style="margin-top:10px">⏳ Your application is waiting for Admin review.</div>
{% elif c.st in ('current','done') %}<div class="hl" style="margin-top:10px">✓ {{'This is your permanent level.' if c.st=='current' else 'Included in your current level.'}}</div>
{% else %}<button disabled style="width:100%;margin-top:10px;opacity:.55">{{'Another application is pending' if pend else 'Requirements not met yet'}}</button>{% endif %}{% endif %}
</div></div>{% endfor %}</div>
{% if hist %}<div class="card"><h3>Your applications</h3>{% for h in hist %}<div class="row" style="margin-bottom:6px"><span>{{h['level']|title}} · {{h['created'][:10]}}</span><span class="pill {{'approved' if h['status']=='approved' else ('rejected' if h['status']=='rejected' else 'pending')}}">{{h['status']}}</span></div>{% endfor %}</div>{% endif %}
<script>(function(){var p=document.getElementById('vp'),d=document.querySelectorAll('#vd i');if(!p)return;function m(){var i=Math.round(p.scrollLeft/(p.clientWidth||1));d.forEach(function(e,k){e.className=k===i?'on':''})}
p.addEventListener('scroll',m,{passive:true});p.scrollLeft={{start}}*p.clientWidth;m()})()</script>""", active="/vip", cards=cards, hist=hist, pend=pend, start=start)


@app.route("/vip/apply", methods=["POST"])
@customer_required
def vip_apply():
    u = me()
    level = request.form.get("level", "")
    if level not in ("gold", "diamond"):
        abort(400)
    if rate_hit("vip:%d" % u["id"], 5, 3600):
        err("Too many attempts. Please try later."); return redirect("/vip")
    L = VIP_LEVELS[level]
    try:
        with atomic():
            x = q1("SELECT * FROM users WHERE id=?", (u["id"],))
            if VIP_LEVELS[vip_level_of(x)]["rank"] >= L["rank"]:
                err("You already hold this VIP level or higher."); return redirect("/vip")
            if _vip_pending(u["id"]):
                err("You already have a VIP application pending."); return redirect("/vip")
            free = _vip_free_deposits(u["id"], level)[:L["n"]]
            if len(free) < L["n"] or float(x["balance"] or 0) < L["bal"]:
                err("You do not meet the requirements for %s yet." % L["name"]); return redirect("/vip")
            cur = db().execute("INSERT INTO vip_applications(user_id,level,rate,status,balance_at,deposit_ids,created) VALUES(?,?,?,?,?,?,?)",
                               (u["id"], level, L["rate"], "pending", float(x["balance"] or 0), ",".join(str(r["id"]) for r in free), now()))
            for r in free:  # each deposit can be counted for one application only (UNIQUE tx_id)
                db().execute("INSERT INTO vip_deposit_use(tx_id,app_id,user_id,created) VALUES(?,?,?,?)", (r["id"], cur.lastrowid, u["id"], now()))
            alert_admins("নতুন VIP আবেদন", "#%s %s — %s" % (u["member_id"], u["name"], L["name"]), "/admin/vip", "vip")
    except INTEGRITY:
        err("You already have a VIP application pending."); return redirect("/vip")
    flash("VIP application submitted. Admin will review it."); return redirect("/vip")


@app.route("/admin/vip")
@staff_required("vip")
def admin_vip():
    pend = qa("SELECT a.*,u.name,u.phone,u.member_id,u.balance,u.vip_level FROM vip_applications a JOIN users u ON u.id=a.user_id "
              "WHERE a.status='pending' ORDER BY a.id")
    done = qa("SELECT a.*,u.name,u.member_id FROM vip_applications a JOIN users u ON u.id=a.user_id WHERE a.status<>'pending' ORDER BY a.id DESC LIMIT 15")
    holders = qa("SELECT id,name,phone,member_id,balance,vip_level,vip_rate FROM users WHERE is_admin=0 AND vip_level IN ('gold','diamond') ORDER BY id DESC LIMIT 60")
    q = _clean_q(request.args.get("q", ""))
    found = qa("SELECT id,name,phone,member_id,vip_level FROM users WHERE is_admin=0 AND (name LIKE ? OR phone LIKE ? OR member_id LIKE ?) ORDER BY id DESC LIMIT 10",
               ("%" + q + "%",) * 3) if q else []
    return page("""<h2>👑 VIP আবেদন</h2>
{% if not pend %}<div class="card empty">কোনো পেন্ডিং আবেদন নেই</div>{% endif %}
{% for a in pend %}<div class="card"><b>{{a['level']|title}} VIP · {{a['rate']|pct}}%</b> <span class="pill pending">pending</span>
<div class="k">#{{a['member_id']}} {{a['name']}} · {{a['phone']}} · {{a['created'][:16]}}</div>
<div>আবেদনের সময় ব্যালেন্স: <b>৳ {{money(a['balance_at'])}}</b> · এখন: ৳ {{money(a['balance'])}}</div><div class="k">গণনাকৃত ডিপোজিট tx#: {{a['deposit_ids']}}</div>
<form method="post" action="/admin/vip/{{a['id']}}" style="margin-top:8px" data-confirm="নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<input name="note" placeholder="নোট (ঐচ্ছিক)" maxlength="200"><div class="row"><button name="act" value="approve" class="btn sm g">Approve</button><button name="act" value="reject" class="btn sm r">Reject</button></div></form></div>{% endfor %}
<div class="card"><h3>VIP পরিবর্তন / বাতিল</h3><p class="k">শুধু অনুমোদিত অ্যাডমিন VIP লেভেল বদলাতে বা বাতিল করতে পারেন। ইউজার খুঁজুন:</p>
<form method="get"><input name="q" value="{{q}}" placeholder="নাম / ফোন / মেম্বার আইডি" maxlength="40"><button class="s" style="width:100%">খুঁজুন</button></form>
{% for f in found %}<form method="post" action="/admin/vip/user/{{f['id']}}" class="card" style="margin-top:8px" data-confirm="VIP পরিবর্তন করবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<b>#{{f['member_id']}} {{f['name']}}</b> <span class="k">({{(f['vip_level'] or 'standard')|title}})</span>
<select name="level"><option value="standard">Standard (বাতিল)</option><option value="gold">Gold 7.5%</option><option value="diamond">Diamond 10%</option></select>
<input name="reason" placeholder="কারণ" required minlength="3" maxlength="200"><button style="width:100%">আপডেট</button></form>{% endfor %}</div>
{% if holders %}<div class="card"><h3>বর্তমান VIP সদস্য</h3>{% for h in holders %}<div class="row" style="margin-bottom:6px"><span>#{{h['member_id']}} {{h['name']}}</span><b>{{h['vip_level']|title}} · {{h['vip_rate']|pct}}%</b></div>{% endfor %}</div>{% endif %}
{% if done %}<div class="card"><h3>সাম্প্রতিক সিদ্ধান্ত</h3>{% for d in done %}<div class="row" style="margin-bottom:6px"><span>#{{d['member_id']}} {{d['name']}} · {{d['level']|title}}</span><span class="pill {{d['status']}}">{{d['status']}}</span></div>{% endfor %}</div>{% endif %}""",
                active="/admin/vip", pend=pend, done=done, holders=holders, q=q, found=found)


def _vip_set(x, level, reason, a, kind):
    """Single place that changes a user's VIP level + rate (inside an atomic block). Logged, audited, user notified."""
    old = vip_level_of(x)
    rate_old = effective_rate(x)
    L = VIP_LEVELS[level]
    db().execute("UPDATE users SET vip_level=?, vip_rate=? WHERE id=?", (level if level != "standard" else None, L["rate"] if level != "standard" else None, x["id"]))
    new_rate = effective_rate({"comm_rate": x["comm_rate"], "vip_rate": L["rate"] if level != "standard" else None})
    db().execute("INSERT INTO vip_log(user_id,action,old_level,new_level,rate,reason,actor,actor_id,created) VALUES(?,?,?,?,?,?,?,?,?)",
                 (x["id"], kind, old, level, L["rate"], reason, a["member_id"], a["id"], now()))
    db().execute("INSERT INTO commission_rate_log(scope,user_id,old_rate,new_rate,reason,idem,actor,actor_id,created) VALUES(?,?,?,?,?,?,?,?,?)",
                 ("vip", x["id"], rate_old, new_rate, "VIP %s → %s: %s" % (old, level, reason or kind), "vip:%s:%s" % (x["id"], secrets.token_hex(6)), a["member_id"], a["id"], now()))
    audit("vip_" + kind, "user#%s %s -> %s (%s)" % (x["id"], old, level, reason))
    return L


@app.route("/admin/vip/<int:i>", methods=["POST"])
@staff_required("vip")
def admin_vip_decide(i):
    act, note, a = request.form.get("act"), request.form.get("note", "").strip()[:200], me()
    if act not in ("approve", "reject"):
        abort(400)
    with atomic():
        ap = q1("SELECT * FROM vip_applications WHERE id=?", (i,))
        if not ap:
            abort(404)
        if ap["status"] != "pending":  # no double decision
            err("এই আবেদনের সিদ্ধান্ত আগেই হয়ে গেছে।"); return back("/admin/vip")
        x = q1("SELECT * FROM users WHERE id=?", (ap["user_id"],))
        L = VIP_LEVELS[ap["level"]]
        if act == "approve":
            if VIP_LEVELS[vip_level_of(x)]["rank"] >= L["rank"]:
                err("ইউজার আগেই এই বা উচ্চতর লেভেলে আছে।"); return back("/admin/vip")
            _vip_set(x, ap["level"], note or "application #%d approved" % i, a, "approve")
            notify(x["id"], "VIP অনুমোদিত", "অভিনন্দন! আপনি এখন %s VIP — কমিশন %g%%। এটি স্থায়ী।" % (L["name"], L["rate"]), "/vip",
                   "VIP approved", "Congratulations! You are now %s VIP — %g%% commission. This level is permanent." % (L["name"], L["rate"]))
        else:
            db().execute("DELETE FROM vip_deposit_use WHERE app_id=?", (i,))  # deposits become countable again
            notify(x["id"], "VIP আবেদন বাতিল", "আপনার %s VIP আবেদন গৃহীত হয়নি।%s" % (L["name"], (" কারণ: " + note) if note else ""), "/vip",
                   "VIP application rejected", "Your %s VIP application was not approved.%s" % (L["name"], (" Reason: " + note) if note else ""))
            audit("vip_reject", "app#%d user#%s %s" % (i, x["id"], ap["level"]))
        db().execute("UPDATE vip_applications SET status=?, note=?, admin=?, admin_id=?, decided=? WHERE id=?",
                     ("approved" if act == "approve" else "rejected", note, a["member_id"], a["id"], now(), i))
        if not q1("SELECT 1 FROM vip_applications WHERE status='pending'"):
            alerts_done("/admin/vip")
    flash("সম্পন্ন।"); return back("/admin/vip")


@app.route("/admin/vip/user/<int:uid>", methods=["POST"])
@staff_required("vip")
def admin_vip_user(uid):
    level, reason, a = request.form.get("level", ""), request.form.get("reason", "").strip()[:200], me()
    if level not in VIP_LEVELS or len(reason) < 3:
        err("সঠিক লেভেল ও কারণ (কমপক্ষে ৩ অক্ষর) দিন।"); return back("/admin/vip")
    with atomic():
        x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (uid,))
        if not x:
            abort(404)
        if vip_level_of(x) == level:
            err("ইউজার আগেই এই লেভেলে আছে।"); return back("/admin/vip")
        L = _vip_set(x, level, reason, a, "revoke" if level == "standard" else "change")
        notify(x["id"], "VIP আপডেট", "আপনার VIP লেভেল এখন %s (%g%%)।" % (L["name"], L["rate"]), "/vip",
               "VIP updated", "Your VIP level is now %s (%g%%)." % (L["name"], L["rate"]))
    flash("VIP আপডেট হয়েছে।"); return back("/admin/vip")




if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
