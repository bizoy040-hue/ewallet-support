"""E-Wallet Support v5 - single file app (Flask + SQLite by default, PostgreSQL/Supabase when DATABASE_URL is set).
Env: SECRET_KEY, ADMIN_PHONE, ADMIN_PASSWORD, DATABASE_PATH, UPLOAD_DIR, BASE_URL (optional)
     DATABASE_URL (PostgreSQL), SUPABASE_URL, SUPABASE_SERVICE_KEY, SUPABASE_BUCKET (screenshot storage)
"""
import os, re, sqlite3, secrets, hashlib, time, csv, io, tempfile, zipfile
from datetime import datetime, timedelta
from functools import wraps, lru_cache
from flask import (Flask, request, redirect, session, render_template_string, g, flash,
                   abort, send_file, jsonify, after_this_request, send_from_directory)
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
SCHEMA_VERSION = 6
CODE_ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

# ---------------------------------------------------------------- roles & permissions (enforced server-side)
ROLES = {"super_admin": "সুপার অ্যাডমিন", "admin": "অ্যাডমিন", "finance": "ফাইন্যান্স স্টাফ", "support": "সাপোর্ট স্টাফ"}
PERM_LABELS = {
    "dashboard_fin": "আর্থিক পরিসংখ্যান দেখা", "deposits": "ডিপোজিট প্রসেস", "withdrawals": "উইথড্র প্রসেস",
    "users_view": "ইউজার/লেনদেন দেখা", "users_manage": "ইউজার ব্লক ও রিসেট কোড", "adjust": "ব্যালেন্স সমন্বয়",
    "referrals": "রেফারেল অনুমোদন", "commissions": "কমিশন প্রদান", "tickets": "সাপোর্ট টিকিট",
    "notices": "নোটিশ প্রকাশ", "audit": "অডিট লগ দেখা"}
PERM_LABELS.update({"requests": "ম্যানুয়াল রিকোয়েস্ট", "payment_numbers": "পেমেন্ট নম্বর দেখা", "pool_view": "কমিশন পুল দেখা",
                    "reports": "আর্থিক রিপোর্ট দেখা", "rates": "ইউজার কমিশন রেট বদলানো"})
ADMIN_ASSIGNABLE = tuple(PERM_LABELS)                       # what a Super Admin can grant to an "admin"
ADMIN_DEFAULT = tuple(p for p in ADMIN_ASSIGNABLE if p != "adjust")
ROLE_FIXED = {"finance": frozenset({"dashboard_fin", "deposits", "withdrawals", "users_view", "referrals", "commissions"}),
              "support": frozenset({"tickets", "users_view"})}
ROLE_FIXED["finance"] = ROLE_FIXED["finance"] | frozenset({"requests", "payment_numbers", "pool_view", "reports"})
SUPER_ONLY = frozenset({"staff", "settings", "backup", "pool_fund", "rates_global"})

WELCOME_DEFAULT = ("আসসালামু আলাইকুম!\n\nআমাদের E-Wallet Support প্ল্যাটফর্মে আপনাকে স্বাগতম।\n\n"
                   "আপনার সময়, দক্ষতা ও প্রচেষ্টাকে কাজে লাগিয়ে আমাদের সঙ্গে কাজ করার সুযোগ গ্রহণ করুন।\n\n"
                   "আপনার যাত্রা শুরু হোক আজ থেকেই!")


def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


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
        try:
            self.c.close()
        except Exception:
            pass


def _pg_connect():
    last = None
    for _ in range(2):
        try:
            return psycopg.connect(DATABASE_URL, autocommit=True, prepare_threshold=None, connect_timeout=10)
        except psycopg.OperationalError as e:
            last = e
            time.sleep(0.5)
    raise last


def db():
    if "db" not in g:
        if PG:
            g.db = PGConn(_pg_connect())
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
    # @@TABLES
]
V5_INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_users_member ON users(member_id)",
    "CREATE INDEX IF NOT EXISTS ix_ledger_created ON ledger(created)",
    "CREATE INDEX IF NOT EXISTS ix_ledger_kind ON ledger(kind)",
    "CREATE INDEX IF NOT EXISTS ix_tx_created ON tx(created)",
    "CREATE INDEX IF NOT EXISTS ix_notif_user ON notifications(user_id)",
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
                "comm_rate_default": "5", "comm_rate_max": "10", "report_tz_hours": "6"}
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
    unread = 0
    if u:
        unread = admin_unread(u) if u["is_admin"] else q1("SELECT COUNT(*) c FROM notifications WHERE is_read=0 AND user_id=?", (u["id"],))["c"]
    return dict(csrf_token=csrf(), u=u, site=(setting("site_name") or SITE)[:60], unread=unread, money=money, can=has_perm,
                role_name=ROLES.get(u["role"], "") if u else "", tg=tg_url_active(), tg_label=tg_label(), lang=cur_lang(), rk=req_label)


CSS = """
:root{--b:#1d4ed8;--g:#16a34a;--bg:#f2f5fb;--card:#fff;--tx:#0f172a;--mut:#64748b;--ln:#e2e8f0;--rd:#dc2626}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0b1220;--card:#111a2e;--tx:#e5eaf5;--mut:#94a3b8;--ln:#1f2b45}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font-family:'Hind Siliguri',system-ui,sans-serif;padding-bottom:84px}
a{color:inherit;text-decoration:none}
.lgsw{background:#ffffff33;border-radius:99px;padding:3px 11px;font-size:13px;margin-right:12px}.top b{flex:1}
.top{background:linear-gradient(100deg,#1d4ed8,#16a34a);color:#fff;padding:14px 16px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:5}
.top .pwa-dl{background:#ffffff33;padding:0;width:30px;height:30px;border-radius:99px;font-size:15px;line-height:1;margin-right:10px;display:inline-flex;align-items:center;justify-content:center}@media(display-mode:standalone){.top .pwa-dl{display:none}}
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
:root[data-theme=dark]{--bg:#0b1220;--card:#111a2e;--tx:#e5eaf5;--mut:#94a3b8;--ln:#1f2b45}
.dot[hidden]{display:none}
.pill.submitted{background:#dbeafe;color:#1e3a8a}.pill.expired,.pill.cancelled{background:#e2e8f0;color:#475569}
.hxt{display:flex;gap:6px;background:var(--card);border:1px solid var(--ln);border-radius:14px;padding:4px;margin-bottom:12px}
.hxt a{flex:1;text-align:center;padding:9px 4px;border-radius:11px;font-weight:600;font-size:14px;color:var(--mut)}
.hxt a.on{background:var(--b);color:#fff}
.hxc{background:var(--card);border:1px solid var(--ln);border-radius:14px;padding:2px 12px;margin-bottom:9px;box-shadow:0 2px 8px #0f172a12}
.hxr{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:5px 0;border-bottom:1px solid var(--ln);font-size:13px;line-height:1.35}
.hxr:last-child{border-bottom:0}
.hxr>span:first-child{color:var(--mut);flex-shrink:0;white-space:nowrap}
.hxr>b{font-weight:600;text-align:right;min-width:0;overflow-wrap:anywhere}
.hxr .neg{color:#dc2626}.hxr .pos{color:#16a34a}.hxr .na{color:var(--mut);font-weight:400}
.hxr .gft{font-size:14px;margin-right:5px}
.hxr .cmv{display:inline-block;color:#166534;background:#dcfce7;border:1px solid #86efac;border-radius:99px;padding:1px 10px;font-weight:700}
:root[data-theme=dark] .hxr .cmv{color:#86efac;background:#14532d55;border-color:#166534}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]) .hxr .cmv{color:#86efac;background:#14532d55;border-color:#166534}}
.hxc{cursor:pointer;-webkit-tap-highlight-color:transparent;transition:box-shadow .28s ease,border-color .28s ease,transform .12s ease}
.hxc:active{transform:scale(.994)}.hxc:focus-visible{outline:2px solid var(--b);outline-offset:2px}
.hxr{transition:padding .28s ease,font-size .28s ease}
.hxc.open{border-color:var(--b);box-shadow:0 6px 18px #0f172a24}.hxc.open>.hxr{padding:8px 0;font-size:14px}
.hxc:not(.open)>.hxr:nth-child(8){border-bottom:0}
.hxd{display:grid;grid-template-rows:0fr;opacity:0;transition:grid-template-rows .3s ease,opacity .3s ease}
.hxd>div{overflow:hidden;min-height:0}.hxc.open .hxd{grid-template-rows:1fr;opacity:1}
body.hx1 .hxc:not(.open),body.hx1 .hxl{display:none}
@media(prefers-reduced-motion:reduce){.hxc,.hxr,.hxd{transition:none}}
.hxr .pill{padding:1px 9px;font-size:12px;font-weight:600;line-height:1.5;white-space:nowrap}
.hxc .pill.pending,.hxc .pill.review,.hxc .pill.processing,.hxc .pill.submitted{background:#ffedd5;color:#c2410c}
.hxc .pill.approved::before,.hxc .pill.approved::after{content:"✓";color:#16a34a;font-weight:800}
.hxc .pill.approved::before{margin-right:5px}.hxc .pill.approved::after{margin-left:5px}
.hero2{background:linear-gradient(125deg,#1e40af,#0f766e 60%,#16a34a);color:#fff;border-radius:22px;padding:20px;margin-bottom:14px;box-shadow:0 8px 22px #0f172a2e}
.menu{padding:6px 8px}
.li{display:flex;align-items:center;gap:14px;width:100%;padding:12px 8px;background:transparent;color:var(--tx);border:0;border-radius:0;font:inherit;text-align:left;cursor:pointer}
.li+.li,form+.li,.li+form{border-top:1px solid var(--ln)}
.li .ic{width:38px;height:38px;flex:0 0 38px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:19px;background:linear-gradient(135deg,#dbeafe,#dcfce7)}
.li .lt{flex:1}.li .ch{color:var(--mut);font-size:22px}.li .bd{background:#ef4444;color:#fff;border-radius:99px;font-size:11px;padding:1px 8px}
.li.out{color:var(--rd)}
.fab{position:fixed;right:16px;bottom:88px;width:54px;height:54px;border-radius:50%;background:linear-gradient(135deg,#1d4ed8,#16a34a);color:#fff;display:flex;align-items:center;justify-content:center;font-size:25px;box-shadow:0 6px 18px #0f172a55;z-index:7}
details.set{padding:0}details.set summary{padding:14px 16px;font-weight:600;cursor:pointer;list-style:none}
details.set summary::-webkit-details-marker{display:none}details.set>form,details.set>div{padding:0 16px 16px}
.new{border-left:4px solid var(--g)}
.hl{white-space:pre-line}
img.shot{max-width:100%;border-radius:12px;margin:8px 0;border:1px solid var(--ln)}
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
function lsGet(k){try{return localStorage.getItem(k)}catch(e){return null}}
function lsSet(k,v){try{localStorage.setItem(k,v)}catch(e){}}
function curTheme(){var t=document.documentElement.getAttribute('data-theme');if(t)return t;
 return(window.matchMedia&&matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light'}
function paintToggles(){var a=document.getElementById('thv');if(a)a.textContent=curTheme()==='dark'?'চালু':'বন্ধ';
 var b=document.getElementById('sndv');if(b)b.textContent=sndOn()?'চালু':'বন্ধ'}
function toggleTheme(){var n=curTheme()==='dark'?'light':'dark';document.documentElement.setAttribute('data-theme',n);lsSet('theme',n);paintToggles()}
var _ac=null;
function sndOn(){var v=lsGet('snd');if(v===null)v=(document.body&&document.body.dataset.snd)||'1';return v==='1'}
function beep(){try{var C=window.AudioContext||window.webkitAudioContext;if(!C)return;_ac=_ac||new C();var o=_ac.createOscillator(),g=_ac.createGain();
 o.connect(g);g.connect(_ac.destination);o.frequency.value=880;g.gain.value=.08;o.start();o.stop(_ac.currentTime+.18)}catch(e){}}
function setSnd(v){lsSet('snd',v?'1':'0');paintToggles();if(v)beep()}
var _last=null;
function pollNotif(){if(document.hidden)return;
 fetch('/api/notif',{credentials:'same-origin',cache:'no-store'}).then(function(r){return r.ok?r.json():null}).then(function(j){
  if(!j)return;var d=document.getElementById('nd');if(d){d.textContent=j.unread;d.hidden=!j.unread}
  if(_last!==null&&j.latest>_last&&sndOn())beep();_last=j.latest}).catch(function(){})}
paintToggles();
if(document.body&&document.body.dataset.poll){pollNotif();setInterval(pollNotif,20000)}
"""

BASE = """<!doctype html><html lang="{{lang}}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{site}}</title>
<link rel="manifest" href="/manifest.json"><meta name="theme-color" content="#1d4ed8"><meta name="mobile-web-app-capable" content="yes">
<link rel="icon" type="image/png" href="/static/icons/icon-192.png"><link rel="apple-touch-icon" href="/static/icons/apple-touch-icon.png">
<script>(function(){var dp=null,w=window;
w.addEventListener('beforeinstallprompt',function(e){e.preventDefault();dp=e});
w.addEventListener('appinstalled',function(){dp=null;var b=document.getElementById('pwa-install');if(b)b.style.display='none'});
document.addEventListener('DOMContentLoaded',function(){var b=document.getElementById('pwa-install');if(!b)return;
if(navigator.standalone===true){b.style.display='none';return}
b.addEventListener('click',function(){if(dp){var p=dp;dp=null;p.prompt();return}
alert(document.documentElement.lang==='en'?'To install: open the Chrome menu (\u22EE) and tap "Install app" or "Add to Home screen".':'ইনস্টল করতে: Chrome মেনু (\u22EE) খুলে "Install app" বা "Add to Home screen" চাপুন।')})});
if('serviceWorker' in navigator)w.addEventListener('load',function(){navigator.serviceWorker.register('/service-worker.js',{scope:'/'}).catch(function(){})})})();</script>
<link href="https://fonts.googleapis.com/css2?family=Hind+Siliguri:wght@400;600;700&display=swap" rel="stylesheet">
<style>{{css|safe}}</style>
<script>try{var t=localStorage.getItem('theme')||'{{dtheme}}';if(t==='dark'||t==='light')document.documentElement.setAttribute('data-theme',t)}catch(e){}</script></head>
<body{% if u %} data-poll="1" data-snd="{{snd}}"{% endif %}>
<div class="top"><b>{{site}}</b><button type="button" id="pwa-install" class="pwa-dl" aria-label="Download App" title="Download App">📲</button><a class="lgsw" href="/lang/{{'bn' if lang=='en' else 'en'}}?next={{nxt|urlencode}}">{{'বাংলা' if lang=='en' else 'English'}}</a>
{% if u and not u['is_admin'] %}<span><a class="bell" href="/notifications">🔔<span class="dot" id="nd"{% if not unread %} hidden{% endif %}>{{unread}}</span></a></span>
{% elif u %}<span><span style="font-size:13px;margin-right:14px">{{role_name}}</span><a class="bell" href="/admin/alerts">🔔<span class="dot" id="nd"{% if not unread %} hidden{% endif %}>{{unread}}</span></a></span>
{% else %}<span><a href="/login">সাইন ইন</a> · <a href="/signup">সাইন আপ</a></span>{% endif %}</div>
<main>{% for c,m in msgs %}<div class="msg {{c}}">{{m}}</div>{% endfor %}
{% if u and u['is_admin'] %}<div class="adm">{% for p,t in tabs %}<a class="t {{'on' if p==active}}" href="{{p}}">{{t}}</a>{% endfor %}</div>{% endif %}
{{body|safe}}
{% if foot %}<div class="foot">{{foot}}</div>{% endif %}</main>
{% if u and not u['is_admin'] %}<div class="nav">
<a class="{{'on' if active=='/'}}" href="/"><i>🏠</i>হোম</a><a class="{{'on' if active=='/history'}}" href="/history"><i>🧾</i>হিস্ট্রি</a>
<a class="{{'on' if active=='/requests'}}" href="/requests"><i>📨</i>অনুরোধ</a><a class="{{'on' if active=='/insight'}}" href="/insight"><i>📊</i>ইনসাইট</a>
<a class="{{'on' if active=='/account'}}" href="/account"><i>👤</i>অ্যাকাউন্ট</a></div>{% endif %}
{% if fab %}<a class="fab" href="{{fab_href}}"{% if fab_tg %} target="_blank" rel="noopener"{% endif %} aria-label="{{fab_label}}" title="{{fab_label}}">💬</a>{% endif %}
<script>{{js|safe}}</script></body></html>"""

# (path, label, permission or None = any staff)
ADMIN_TABS = [("/admin", "ড্যাশবোর্ড", None), ("/admin/alerts", "🔔 নোটিফিকেশন", None),
              ("/admin/requests", "রিকোয়েস্ট", "requests"), ("/admin/deposits", "ডিপোজিট", "deposits"),
              ("/admin/withdrawals", "উইথড্র", "withdrawals"), ("/admin/users", "ইউজার", "users_view"),
              ("/admin/payment-numbers", "পেমেন্ট নম্বর", "payment_numbers"),
              ("/admin/referrals", "রেফারেল", "referrals"), ("/admin/commission", "কমিশন", "commissions"), ("/admin/pool", "কমিশন পুল", "pool_view"),
              ("/admin/reports", "রিপোর্ট", "reports"), ("/admin/reconcile", "মিলানো", "reports"),
              ("/admin/staff", "স্টাফ", "staff"), ("/admin/tickets", "টিকিট", "tickets"),
              ("/admin/notices", "নোটিশ", "notices"), ("/admin/content", "কনটেন্ট", "notices"), ("/admin/settings", "সেটিংস", "settings"),
              ("/admin/audit", "অডিট লগ", "audit"), ("/admin/profile", "প্রোফাইল", None)]


def page(tpl, active="", foot="", **ctx):
    from flask import get_flashed_messages
    body = render_template_string(tpl, **ctx)
    msgs = get_flashed_messages(with_categories=True)
    msgs = [(("error" if c == "error" else ""), m) for c, m in msgs]
    u = me()
    tabs = [(p, t) for p, t, perm in ADMIN_TABS if u and u["is_admin"] and (perm is None or has_perm(perm, u))]
    lang, tgu = cur_lang(), tg_url_active()
    html = render_template_string(BASE, body=body, css=CSS, js=JS, msgs=msgs, active=active, foot=foot, tabs=tabs,
                                  fab=bool(u and not u["is_admin"] and active == "/"), lang=lang, nxt=request.path,
                                  fab_href=tgu or "/support", fab_tg=bool(tgu), fab_label=tg_label() if tgu else ("Support" if lang == "en" else "সাপোর্ট"),
                                  dtheme=setting("default_theme", "auto"), snd=setting("notif_sound", "1"))
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
    "ডার্ক মোড": "Dark mode", "নোটিফিকেশন সাউন্ড": "Notification sound", "সেটিংস": "Settings",
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
}
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
        r = q1("SELECT v FROM settings WHERE k=?", ("ulang:%d" % u["id"],))
        lang = r["v"] if r else None
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
        {"bn": "রেফারেল বোনাস অনুমোদনের পরই ওয়ালেটে যুক্ত হয়; ভুয়া/স্ব-রেফারেল বাতিল হবে।",
         "en": "A referral bonus is added only after approval; fake or self-referrals are cancelled."},
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
                    bonus = parse_amount(setting("referral_bonus", "50")) or 50.0
                    db().execute("INSERT INTO referrals(referrer_id,referred_id,code,amount,status,created) VALUES(?,?,?,?,?,?)",
                                 (referrer["id"], uid, code, bonus, "pending", now()))
                    notify(referrer["id"], "নতুন রেফারেল", "আপনার কোডে #%d সাইন আপ করেছেন। ৳%s বোনাস অনুমোদনের অপেক্ষায়।" % (last + 1, money(bonus)))
                    db().execute("INSERT INTO audit(actor,action,detail,created,actor_id,ip) VALUES(?,?,?,?,?,?)",
                                 ("system", "referral_request", "referral for user#%d by user#%d" % (uid, referrer["id"]), now(), None, ip))
        except INTEGRITY:
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
    s["deposit"] = one("SELECT (SELECT COALESCE(SUM(amount),0) FROM tx WHERE user_id=? AND kind='deposit' AND status='approved')"
                       "+(SELECT COALESCE(SUM(amount),0) FROM requests WHERE user_id=? AND kind='deposit' AND status='approved') s", (uid, uid))
    s["withdraw"] = one("SELECT (SELECT COALESCE(SUM(amount),0) FROM tx WHERE user_id=? AND kind='withdraw' AND status IN('approved','paid'))"
                        "+(SELECT COALESCE(SUM(amount),0) FROM requests WHERE user_id=? AND kind='withdraw' AND COALESCE(flow,'')<>'client_confirm' AND status='approved') s", (uid, uid))
    s["pending"] = one("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE user_id=? AND kind='withdraw' AND status IN('pending','processing')", (uid,))
    s["today"] = one("SELECT COALESCE(SUM(amount),0) s FROM ledger WHERE user_id=? AND kind IN('commission','referral_bonus') AND date(created)=date('now')", (uid,))
    return s


@app.route("/")
@login_required
def home():
    u = me()
    if u["is_admin"]:
        return redirect("/admin")
    expire_requests()
    req_open = q1("SELECT COUNT(*) c FROM requests WHERE user_id=? AND status='pending'", (u["id"],))["c"]
    return page("""<div class="card hero"><small>উপলব্ধ ব্যালেন্স</small><div class="bal">৳ {{money(u['balance'])}}</div>
<div class="row"><a class="btn w" href="/deposit">➕ Add Money</a><a class="btn w" href="/withdraw">⬆ উইথড্র</a></div>
<div class="row" style="margin-top:10px"><a class="btn w" href="/requests">📨 অনুরোধ{% if req_open %} <span style="background:#ef4444;border-radius:99px;font-size:12px;padding:1px 8px;margin-left:4px">{{req_open}}</span>{% endif %}</a><a class="btn w" href="/payment-numbers">💳 Payment Methods</a></div></div>
<div class="g2"><div class="card"><div class="k">পেন্ডিং উইথড্র</div><div class="v">৳ {{money(s.pending)}}</div></div>
<div class="card"><div class="k">মোট ডিপোজিট</div><div class="v">৳ {{money(s.deposit)}}</div></div>
<div class="card"><div class="k">মোট উইথড্র</div><div class="v">৳ {{money(s.withdraw)}}</div></div>
<div class="card"><div class="k">মোট কমিশন</div><div class="v">৳ {{money(u['commission'])}}</div><div class="k">আপনার রেট: {{rate|pct}}%</div></div>
<div class="card"><div class="k">আজকের আয়</div><div class="v">৳ {{money(s.today)}}</div></div>
<div class="card"><div class="k">মেম্বার আইডি</div><div class="v">#{{u['member_id']}}</div></div></div>
{% if notices %}{% for n in notices %}<div class="card"><b>📢 {{n['title']}}</b><div class="k">{{n['body']}}</div></div>{% endfor %}{% endif %}
<div class="card welcome">{{welcome}}</div>""", active="/", s=stats(u["id"]), req_open=req_open, rate=effective_rate(u),
                notices=qa("SELECT * FROM notifications WHERE user_id IS NULL ORDER BY id DESC LIMIT 3"),
                welcome=setting("welcome", WELCOME_DEFAULT))


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
                alert_admins("নতুন উইথড্র রিকোয়েস্ট", "#%s %s — ৳%s (%s)" % (u["member_id"], u["name"], money(amt), m), "/admin/withdrawals", "withdrawals")
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
             _x(("trx", t["trx"]), ("upd", t["updated"] if t["status"] != "pending" and t["updated"] != t["created"] else None)), t["kind"]) for t in txs] + \
           [(r["created"], r["kind"], r["order_id"], r["method"], r["pay_number"], r["amount"], r["status"], r["commission"],
             _x(("trx", r["trx"]), ("sub", r["submitted_at"]), ("upd", r["decided_at"]),
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
        items.append(dict(order=order or "", method=method or "", number=number or "", kind=REQ_KIND.get(dkind, dkind),
                          amt=amt, tone=tone, status=slabel,
                          cls="pending" if status in ("submitted", "review") else status,
                          comm=("৳ " + money(comm)) if comm is not None else "", when=str(created or "")[:16], extra=extra))
    led = qa("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 100", (u["id"],))
    L = (dict(order="Order ID", method="Method", number="Number", kind="Type", amount="Amount", status="Status",
              comm="Commission", when="Date & Time", trx="TrxID", sub="Submitted", upd="Updated", why="Rejection reason", ins="Instructions") if en else
         dict(order="অর্ডার আইডি", method="মাধ্যম", number="নম্বর", kind="ধরন", amount="পরিমাণ", status="অবস্থা",
              comm="কমিশন", when="তারিখ ও সময়", trx="ট্রানজেকশন আইডি", sub="জমার সময়", upd="আপডেট", why="রিজেক্টের কারণ", ins="নির্দেশনা"))
    tabs = [("all", "All" if en else "সব"), ("deposit", "Deposit" if en else "ডিপোজিট"), ("withdraw", "Withdraw" if en else "উইথড্র")]
    return page("""<div class="hxt">{% for k,lb in tabs %}<a class="{{'on' if f==k}}" href="/history{{'' if k=='all' else '?f='+k}}">{{lb}}</a>{% endfor %}</div>
{% if not items %}<div class="card"><div class="empty">কোনো লেনদেন নেই</div></div>{% endif %}
{% for it in items %}<div class="hxc" role="button" tabindex="0" aria-expanded="false">
<div class="hxr"><span>{{L.order}}</span><b>{% if it.order %}{{it.order}}{% else %}<span class="na">—</span>{% endif %}</b></div>
<div class="hxr"><span>{{L.method}}</span><b>{{it.method or '—'}}</b></div>
<div class="hxr"><span>{{L.number}}</span><b>{{it.number or '—'}}</b></div>
<div class="hxr"><span>{{L.kind}}</span><b>{{it.kind}}</b></div>
<div class="hxr"><span>{{L.amount}}</span><b class="{{it.tone}}">{{it.amt}}</b></div>
<div class="hxr"><span>{{L.status}}</span><span class="pill {{it.cls}}">{{it.status}}</span></div>
<div class="hxr"><span><span class="gft">🎁</span>{{L.comm}}</span><b>{% if it.comm %}<span class="cmv">{{it.comm}}</span>{% else %}<span class="na">—</span>{% endif %}</b></div>
<div class="hxr"><span>{{L.when}}</span><b>{{it.when or '—'}}</b></div>
{% if it.extra %}<div class="hxd"><div>{% for k,v in it.extra %}<div class="hxr"><span>{{L[k]}}</span><b{% if k in ('why','ins') %} style="white-space:pre-line;font-weight:500"{% endif %}>{{v}}</b></div>{% endfor %}</div></div>{% endif %}</div>{% endfor %}
<script>(function(){function t(c){var o=!c.classList.contains('open');c.classList.toggle('open',o);c.setAttribute('aria-expanded',o?'true':'false');document.body.classList.toggle('hx1',o);if(o){window.scrollTo(0,0)}else{c.scrollIntoView({block:'center'})}}
document.addEventListener('click',function(e){var c=e.target.closest&&e.target.closest('.hxc');if(c)t(c)});
document.addEventListener('keydown',function(e){if((e.key==='Enter'||e.key===' ')&&e.target.classList&&e.target.classList.contains('hxc')){e.preventDefault();t(e.target)}})})();</script>
<div class="card hxl"><h2>ওয়ালেট লেজার</h2><div class="tw"><table><tr><th>ধরন</th><th>৳</th><th>নোট</th><th>সময়</th></tr>
{% for l in led %}<tr><td>{{l['kind']}}</td><td style="color:{{'#16a34a' if l['amount']>=0 else '#dc2626'}}">{{money(l['amount'])}}</td><td>{{l['note'] or ''}}</td><td>{{l['created'][:16]}}</td></tr>{% endfor %}</table></div></div>""",
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
    db().execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (u["id"],))
    return page("""<h2>নোটিফিকেশন</h2>{% if not rows %}<div class="card empty">কোনো নোটিফিকেশন নেই</div>{% endif %}
{% for n in rows %}<div class="card"><b>{{(n['title_en'] if lang=='en' and n['title_en'] else n['title'])}}</b><div>{{(n['body_en'] if lang=='en' and n['body_en'] else n['body'])}}</div><div class="k">{{n['created'][:16]}}</div>
{% if n['link'] %}<a class="btn sm" href="{{n['link']}}" style="margin-top:8px">খুলুন</a>{% endif %}</div>{% endfor %}""", rows=rows)


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
        dep.append(round(f("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE %skind='deposit' AND status='approved' AND date(updated)=?" % w)
                         + f("SELECT COALESCE(SUM(amount),0) s FROM requests WHERE %skind='deposit' AND status='approved' AND date(decided_at)=?" % w), 2))
        wd.append(round(f("SELECT COALESCE(SUM(amount),0) s FROM tx WHERE %skind='withdraw' AND status IN('approved','paid') AND date(updated)=?" % w)
                        + f("SELECT COALESCE(SUM(amount),0) s FROM requests WHERE %skind='withdraw' AND COALESCE(flow,'')<>'client_confirm' AND status='approved' AND date(decided_at)=?" % w), 2))
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
<a class="li" href="/account/soon/kyc"><span class="ic">🪪</span><span class="lt">KYC যাচাই</span><span class="ch">›</span></a>
<a class="li" href="/account/soon/vip"><span class="ic">👑</span><span class="lt">VIP লেভেল</span><span class="ch">›</span></a>
<a class="li" href="/referral"><span class="ic">🎁</span><span class="lt">ইনভাইট ও আর্ন</span><span class="ch">›</span></a>
<button type="button" class="li" onclick="toggleTheme()"><span class="ic">🌙</span><span class="lt">ডার্ক মোড</span><span class="k" id="thv"></span></button>
<a class="li" href="/notifications"><span class="ic">🔔</span><span class="lt">নোটিফিকেশন</span>{% if unread %}<span class="bd">{{unread}}</span>{% endif %}<span class="ch">›</span></a>
<button type="button" class="li" onclick="setSnd(!sndOn())"><span class="ic">🔊</span><span class="lt">নোটিফিকেশন সাউন্ড</span><span class="k" id="sndv"></span></button>
<a class="li" href="/lang/{{'bn' if lang=='en' else 'en'}}?next=/account"><span class="ic">🌐</span><span class="lt">ভাষা</span><span class="k">{{'বাংলা (Bangla)' if lang=='en' else 'English'}}</span><span class="ch">›</span></a>
<a class="li" href="/account/settings"><span class="ic">⚙️</span><span class="lt">সেটিংস</span><span class="ch">›</span></a>
<a class="li" href="/payment-numbers"><span class="ic">💳</span><span class="lt">পেমেন্ট নম্বর ব্যবস্থাপনা</span><span class="ch">›</span></a>
<a class="li" href="/support"><span class="ic">💬</span><span class="lt">সাপোর্ট</span><span class="ch">›</span></a>
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
 (COALESCE(x.signup_ip,'')<>'' AND (x.signup_ip=rf.signup_ip OR EXISTS(SELECT 1 FROM login_history h WHERE h.user_id=rf.id AND h.ip=x.signup_ip))) same_ip
 FROM referrals r JOIN users rf ON rf.id=r.referrer_id JOIN users x ON x.id=r.referred_id"""

REF_LIST = """{% if not rows %}<div class="card empty">কোনো রেফারেল রিকোয়েস্ট নেই</div>{% endif %}
{% for r in rows %}<div class="card"><div class="row" style="align-items:center"><b>৳ {{money(r['amount'])}}</b><span class="pill {{r['status']}}" style="flex:0">{{r['status']}}</span></div>
<div class="k">রেফারার: <a href="/admin/referrals/user/{{r['referrer_id']}}"><b>#{{r['rf_mid']}} {{r['rf_name']}}</b></a> · {{r['rf_phone']}}</div>
<div class="k">নতুন ইউজার: <a href="/admin/referrals/user/{{r['referred_id']}}"><b>#{{r['x_mid']}} {{r['x_name']}}</b></a> · {{r['x_phone']}} · {{r['created'][:16]}}</div>
{% if r['same_ip'] and r['status']=='pending' %}<div class="msg error" style="margin:6px 0">⚠ একই আইপি থেকে সাইন আপ/লগইন — যাচাই করুন</div>{% endif %}
{% if r['status']!='pending' %}<div class="k">সিদ্ধান্ত: {{r['decided_by']}} · {{(r['decided_at'] or '')[:16]}}{% if r['note'] %} · {{r['note']}}{% endif %}</div>
{% elif can('referrals') %}<form method="post" action="/admin/referrals/{{r['id']}}" style="margin-top:8px" data-confirm="নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<input name="note" placeholder="নোট (ঐচ্ছিক)" maxlength="200"><div class="row"><button name="act" value="approve" class="btn sm g">✅ অনুমোদন</button><button name="act" value="reject" class="btn sm r">❌ বাতিল</button></div></form>{% endif %}</div>{% endfor %}"""


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
        bad = reconcile()
        s.update(pool=pool_balance(), pool_res=pool_reserved())
        if has_perm("reports", u):
            rc = recon_overall(recon_checks())
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
{% if fin %}<div class="card"><b>লেজার রিকনসিলিয়েশন:</b>
{% if bad %}<span class="pill rejected">{{bad|length}}টি অমিল</span>{% for b in bad %}<div class="k">#{{b['member_id']}}: ব্যালেন্স {{b['balance']}} ≠ লেজার {{b['ledger_sum']}}</div>{% endfor %}
{% else %}<span class="pill approved">সব মিলেছে ✅</span>{% endif %}</div>
{% if rc %}<a class="card" href="/admin/reconcile" style="display:block"><b>🧮 পূর্ণ মিলানো (ওয়ালেট · পুল · কোম্পানি-লেজার):</b> <span class="pill {{'approved' if rc=='ok' else 'rejected'}}">{{'সব মিলেছে ✅' if rc=='ok' else ('দেখা দরকার ⚠' if rc=='warn' else 'গরমিল ❌')}}</span></a>{% endif %}
<div class="card"><h3>গত ১৪ দিন</h3><canvas id="ch"></canvas></div>
<script>fetch('/insight/data?days=14').then(r=>r.json()).then(j=>bars('ch',j.labels,[j.deposit,j.withdraw,j.commission],['#3b82f6','#ef4444','#22c55e']))</script>{% endif %}""",
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


@app.route("/admin/users")
@staff_required("users_view")
def admin_users():
    s = request.args.get("q", "").strip().lstrip("#")[:40]
    f = request.args.get("f", "all")
    like = "%" + s + "%"
    cond = {"active": " AND blocked=0", "blocked": " AND blocked=1", "funded": " AND balance>0",
            "new": " AND created>=datetime('now','-7 days')"}.get(f, "")
    where = "is_admin=0 AND (?='' OR name LIKE ? OR phone LIKE ? OR member_id LIKE ? OR referral_code LIKE ?)" + cond
    args = (s, like, like, like, like)
    total = q1("SELECT COUNT(*) n FROM users WHERE " + where, args)["n"]
    pg = make_pg(total)
    rows = qa("SELECT u.*, (SELECT COUNT(*) FROM referrals r WHERE r.referrer_id=u.id) refn FROM users u WHERE " + where +
              " ORDER BY u.id ASC LIMIT ? OFFSET ?", args + (pg["per"], pg["off"]))
    return page("""<div class="card"><form><input name="q" value="{{s}}" placeholder="নাম / ফোন / মেম্বার আইডি / রেফারেল কোড">
<select name="f"><option value="all" {{'selected' if f=='all'}}>সব ইউজার</option><option value="active" {{'selected' if f=='active'}}>ব্লক নয়</option>
<option value="blocked" {{'selected' if f=='blocked'}}>ব্লকড</option><option value="funded" {{'selected' if f=='funded'}}>ব্যালেন্স আছে</option>
<option value="new" {{'selected' if f=='new'}}>গত ৭ দিনের নতুন</option></select><button style="width:100%">খুঁজুন</button></form></div>
{% if not rows %}<div class="card empty">কোনো ইউজার নেই</div>{% endif %}
{% for x in rows %}<a href="/admin/users/{{x['id']}}"><div class="card"><b>{{pg.off+loop.index}}. #{{x['member_id']}} {{x['name']}}</b> {% if x['blocked'] %}<span class="pill rejected">blocked</span>{% endif %}
<div class="k">{{x['phone']}} · ৳ {{money(x['balance'])}} · কমিশন ৳ {{money(x['commission'])}} · রেফার {{x['refn']}} · {{(x['created'] or '')[:10]}}</div></div></a>{% endfor %}"""
                + PAGER, active="/admin/users", rows=rows, s=s, f=f, pg=pg)


def user_summary(i):
    r = q1("""SELECT
      COALESCE(SUM(CASE WHEN kind IN ('deposit','request_deposit') AND amount>0 THEN amount END),0) dep,
      COALESCE(SUM(CASE WHEN kind IN ('commission','commission_reversal') THEN amount END),0) com,
      COALESCE(SUM(CASE WHEN kind='referral_bonus' THEN amount END),0) refb,
      COALESCE(SUM(CASE WHEN kind='admin_adjust' THEN amount END),0) adj FROM ledger WHERE user_id=?""", (i,))
    s = stats(i)
    return {"dep": s["deposit"], "wd": s["withdraw"], "pending": s["pending"], "com": r["com"], "refb": r["refb"], "adj": r["adj"]}


@app.route("/admin/users/<int:i>")
@staff_required("users_view")
def admin_user(i):
    x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (i,))
    if not x:
        abort(404)
    full = has_perm("dashboard_fin") or has_perm("users_manage")
    pg = make_pg(q1("SELECT COUNT(*) n FROM ledger WHERE user_id=?", (i,))["n"], 30) if full else None
    led = qa("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT ? OFFSET ?", (i, 30, pg["off"])) if full else []
    comm = qa("SELECT * FROM ledger WHERE user_id=? AND kind IN ('commission','commission_reversal','referral_bonus') ORDER BY id DESC LIMIT 30", (i,)) if full else []
    adjs = qa("SELECT * FROM balance_adjustments WHERE user_id=? ORDER BY id DESC LIMIT 15", (i,)) if full else []
    logs = qa("SELECT * FROM login_history WHERE user_id=? ORDER BY id DESC LIMIT 10", (i,)) if has_perm("users_manage") else []
    txs = qa("SELECT * FROM tx WHERE user_id=? ORDER BY id DESC LIMIT 30", (i,))
    reqs = qa("SELECT id,order_id,kind,amount,status,created FROM requests WHERE user_id=? ORDER BY id DESC LIMIT 15", (i,)) if has_perm("requests") else []
    reffed = qa("SELECT r.*, x.member_id mid, x.name nm FROM referrals r JOIN users x ON x.id=r.referred_id WHERE r.referrer_id=? ORDER BY r.id DESC LIMIT 50", (i,))
    refs = q1("SELECT COUNT(*) n, COALESCE(SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END),0) a FROM referrals WHERE referrer_id=?", (i,))
    by = q1("SELECT member_id,name FROM users WHERE id=?", (x["referred_by"],)) if x["referred_by"] else None
    byrow = q1("SELECT created,status FROM referrals WHERE referred_id=?", (i,)) if x["referred_by"] else None
    return page("""<div class="card"><h2>#{{x['member_id']}} {{x['name']}} {% if x['blocked'] %}<span class="pill rejected">blocked</span>{% else %}<span class="pill approved">active</span>{% endif %}</h2>
<p>📱 {{x['phone']}} · ব্যালেন্স <b>৳ {{money(x['balance'])}}</b> · কমিশন ৳ {{money(x['commission'])}}<br>
<span class="k">যোগদান: {{(x['created'] or '-')[:16]}} · সর্বশেষ লগইন: {{x['last_login'] or '-'}} · রেফারেল কোড: {{x['referral_code']}}</span></p>
{% if x['blocked'] and x['blocked_reason'] %}<div class="msg error">ব্লকের কারণ: {{x['blocked_reason']}} ({{(x['blocked_at'] or '')[:16]}})</div>{% endif %}
<div class="g2"><div class="card"><div class="k">মোট ডিপোজিট</div><div class="v">৳ {{money(sm.dep)}}</div></div><div class="card"><div class="k">মোট উইথড্র</div><div class="v">৳ {{money(sm.wd)}}</div></div>
<div class="card"><div class="k">পেন্ডিং উইথড্র</div><div class="v">৳ {{money(sm.pending)}}</div></div><div class="card"><div class="k">কমিশন (লেজার)</div><div class="v">৳ {{money(sm.com)}}</div></div></div>
{% if can('rates') %}<form method="post" action="/admin/commission/rate" data-confirm="কমিশন রেট বদলাবেন?" style="margin-bottom:8px"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="idem" value="{{ridem}}"><input type="hidden" name="scope" value="user"><input type="hidden" name="uid" value="{{x['id']}}">
<h4>কমিশন রেট</h4><div class="k">কার্যকর রেট: <b>{{eff}}%</b> {% if x['comm_rate'] is not none %}(ইউজার-নির্দিষ্ট){% else %}(গ্লোবাল){% endif %} · সর্বোচ্চ {{rmax}}%</div>
<select name="op"><option value="set">সেট করুন</option><option value="inc">বাড়ান (+)</option><option value="dec">কমান (−)</option><option value="reset">গ্লোবালে ফিরুন</option></select>
<input name="value" type="number" step="0.01" min="0" max="10" placeholder="% মান" value="0"><input name="reason" placeholder="কারণ" required minlength="3" maxlength="200"><button class="s" style="width:100%">রেট আপডেট</button></form>{% endif %}
{% if can('users_manage') %}<form method="post" action="/admin/users/{{x['id']}}/block" data-confirm="নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<input type="hidden" name="act" value="{{'unblock' if x['blocked'] else 'block'}}"><label>{{'আনব্লকের নোট (ঐচ্ছিক)' if x['blocked'] else 'ব্লকের কারণ (আবশ্যক)'}}</label><input name="reason" maxlength="200" {{'' if x['blocked'] else 'required'}}>
<button class="btn {{'g' if x['blocked'] else 'r'}}" style="width:100%">{{'🔓 আনব্লক' if x['blocked'] else '🔒 ব্লক'}}</button></form>
<form method="post" action="/admin/users/{{x['id']}}/resetcode" data-confirm="নতুন রিসেট কোড তৈরি করবেন?" style="margin-top:8px"><input type="hidden" name="_csrf" value="{{csrf_token}}"><button class="btn s" style="width:100%">পাসওয়ার্ড রিসেট কোড</button></form>{% endif %}
{% if can('requests') %}<a class="btn s" style="width:100%;margin-top:8px" href="/admin/requests/new?uid={{x['id']}}">📨 এই ইউজারের জন্য রিকোয়েস্ট তৈরি</a>{% endif %}{% if can('reports') %}<a class="btn s" style="width:100%;margin-top:8px" href="/admin/reports/user/{{x['id']}}">📊 ইউজার রিপোর্ট</a>{% endif %}</div>
{% if can('adjust') %}<div class="card"><h3>ব্যালেন্স সমন্বয় (কারণ আবশ্যক)</h3><p class="k">যোগ করতে বৈধ রেফারেন্স (TrxID / অনুরোধ নম্বর / রসিদ নম্বর) লাগবে এবং একই রেফারেন্স দুবার ব্যবহার করা যায় না। সীমা: ৳{{money(adj_cap)}}।</p>
<form method="post" action="/admin/users/{{x['id']}}/adjust" data-confirm="লেজারে স্থায়ীভাবে রেকর্ড হবে। নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="idem" value="{{idem}}">
<label>ধরন</label><select name="direction"><option value="credit">➕ ব্যালেন্স যোগ</option><option value="debit">➖ ব্যালেন্স বিয়োগ</option></select>
<label>পরিমাণ (৳)</label><input name="amount" type="number" step="0.01" min="0.01" required><label>রেফারেন্স (যোগের জন্য আবশ্যক)</label><input name="reference" maxlength="40">
<label>কারণ (কমপক্ষে ৫ অক্ষর)</label><input name="reason" required minlength="5" maxlength="200"><button style="width:100%">সমন্বয় করুন</button></form></div>{% endif %}
{% if can('notices') %}<div class="card"><h3>ব্যক্তিগত নোটিশ / নির্দেশনা</h3><form method="post" action="/admin/users/{{x['id']}}/notice" data-confirm="ইউজারকে পাঠাবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<select name="kind"><option value="notice">📌 নোটিশ</option><option value="instruction">📋 নির্দেশনা</option></select>
<label>শিরোনাম (বাংলা)</label><input name="title_bn" required maxlength="80"><label>বার্তা (বাংলা)</label><textarea name="body_bn" required rows="3" maxlength="1000"></textarea>
<label>Title (English, optional)</label><input name="title_en" maxlength="80"><label>Message (English, optional)</label><textarea name="body_en" rows="3" maxlength="1000"></textarea>
<button style="width:100%">পাঠান</button></form></div>{% endif %}
<div class="card"><h3>রেফারেল তথ্য {% if can('referrals') %}<a class="k" href="/admin/referrals/user/{{x['id']}}">বিস্তারিত →</a>{% endif %}</h3><p class="k">রেফার করেছেন: {{refs['n']}} (অনুমোদিত {{refs['a']}}){% if by %} · রেফারার: <a href="/admin/users/{{x['referred_by']}}">#{{by['member_id']}} {{by['name']}}</a> ({{(byrow['created'] or '')[:10]}}, {{byrow['status']}}){% else %} · কারও রেফারে আসেননি{% endif %}</p>
{% if reffed %}<div class="tw"><table><tr><th>সদস্য</th><th>তারিখ</th><th>বোনাস</th><th>অবস্থা</th></tr>{% for r in reffed %}<tr><td><a href="/admin/users/{{r['referred_id']}}">#{{r['mid']}} {{r['nm']}}</a></td><td>{{r['created'][:10]}}</td><td>{{money(r['amount'])}}</td><td>{{r['status']}}</td></tr>{% endfor %}</table></div>{% endif %}</div>
{% if comm %}<div class="card"><h3>কমিশন / বোনাস ইতিহাস</h3><div class="tw"><table><tr><th>ধরন</th><th>৳</th><th>নোট</th><th>সময়</th></tr>
{% for l in comm %}<tr><td>{{l['kind']}}</td><td>{{money(l['amount'])}}</td><td>{{l['note'] or ''}}</td><td>{{l['created'][:16]}}</td></tr>{% endfor %}</table></div></div>{% endif %}
{% if adjs %}<div class="card"><h3>ব্যালেন্স সমন্বয়ের ইতিহাস</h3><div class="tw"><table><tr><th>ধরন</th><th>৳</th><th>রেফারেন্স</th><th>কারণ</th><th>কে</th><th>সময়</th></tr>
{% for a in adjs %}<tr><td>{{a['direction']}}</td><td>{{money(a['amount'])}}</td><td>{{a['reference'] or '-'}} {{'✔' if a['verified']}}</td><td>{{a['reason']}}</td><td>{{a['actor']}}</td><td>{{a['created'][:16]}}</td></tr>{% endfor %}</table></div></div>{% endif %}
{% if led %}<div class="card"><h3>ওয়ালেট লেজার</h3><div class="tw"><table><tr><th>ধরন</th><th>৳</th><th>নোট</th><th>কে</th><th>সময়</th></tr>
{% for l in led %}<tr><td>{{l['kind']}}</td><td>{{money(l['amount'])}}</td><td>{{l['note'] or ''}}</td><td>{{l['actor']}}</td><td>{{l['created'][:16]}}</td></tr>{% endfor %}</table></div>""" + PAGER + """</div>{% endif %}
<div class="card"><h3>লেনদেন</h3><div class="tw"><table>{% for t in txs %}<tr><td>{{t['kind']}}</td><td>{{money(t['amount'])}}</td><td>{{t['status']}}</td><td>{{(t['trx'] or t['number'] or '')}}</td><td>{{(t['created'] or '')[:16]}}</td></tr>{% endfor %}</table></div></div>
{% if reqs %}<div class="card"><h3>রিকোয়েস্ট</h3><div class="tw"><table>{% for r in reqs %}<tr><td><a href="/admin/requests/{{r['id']}}">{{r['order_id']}}</a></td><td>{{r['kind']}}</td><td>{{money(r['amount'])}}</td><td>{{r['status']}}</td></tr>{% endfor %}</table></div></div>{% endif %}
{% if pns %}<div class="card"><h3>পেমেন্ট নম্বর</h3><div class="tw"><table><tr><th>মাধ্যম</th><th>ধরন</th><th>নম্বর</th><th>জমা</th><th>আপডেট</th></tr>{% for p in pns %}<tr><td>{{p['method']}}</td><td>{{p['account_type']}}</td><td>{{p['number']}}</td><td>{{(p['created'] or '')[:16]}}</td><td>{{(p['updated'] or '')[:16]}}</td></tr>{% endfor %}</table></div></div>{% endif %}
{% if logs %}<div class="card"><h3>লগইন ইতিহাস</h3><div class="tw"><table>{% for h in logs %}<tr><td>{{h['created'][:16]}}</td><td>{{h['ip']}}</td><td>{{'✅' if h['ok'] else '❌'}}</td></tr>{% endfor %}</table></div></div>{% endif %}""",
                active="/admin/users", x=x, led=led, logs=logs, txs=txs, reqs=reqs, refs=refs, by=by, byrow=byrow, reffed=reffed, comm=comm, adjs=adjs,
                sm=user_summary(i), pg=pg, idem=secrets.token_hex(8), adj_cap=adjust_cap(me()),
                pns=qa("SELECT * FROM payment_numbers WHERE user_id=? ORDER BY id", (i,)) if has_perm("payment_numbers") else []
                , eff=effective_rate(x), rmax=rate_cfg()[1], ridem=secrets.token_hex(8)
                )


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
    return page("""<div class="row" style="margin-bottom:10px;align-items:center"><a class="btn sm" href="/admin/referrals">📋 তালিকা</a><a class="btn sm s" href="/admin/referrals/network">🌐 নেটওয়ার্ক</a>{% if can('pool_view') %}<span class="k">পুলে উপলব্ধ: ৳{{money(pool_av)}}</span>{% endif %}</div>
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
            if act == "approve" and rf["blocked"]:
                err("রেফারার ব্লকড। আনব্লক করুন অথবা বাতিল করুন।"); return back("/admin/referrals")
            new = "approved" if act == "approve" else "rejected"
            cur = db().execute("UPDATE referrals SET status=?, decided_by=?, decided_by_id=?, decided_at=?, note=? WHERE id=? AND status='pending'",
                               (new, who, a["id"], now(), note, i))
            if cur.rowcount != 1:
                raise LedgerError("duplicate decision")
            if act == "approve":
                if float(r["amount"]) > 0 and not pool_pay(rf["id"], "referral_bonus", r["amount"], "ref:%d:bonus" % i, "referral", i,
                                                            "Referral bonus for #%s" % x["member_id"], a["member_id"]):
                    raise LedgerError("duplicate credit")  # referral rewards are paid ONLY from the funded Commission Pool
                notify(rf["id"], "রেফারেল বোনাস অনুমোদিত", "#%s-এর রেফারেলের জন্য ৳%s আপনার ওয়ালেটে যুক্ত হয়েছে।" % (x["member_id"], money(r["amount"])))
            else:
                notify(rf["id"], "রেফারেল বাতিল", "#%s-এর রেফারেল বোনাস অনুমোদিত হয়নি।%s" % (x["member_id"], (" কারণ: " + note) if note else ""))
            audit("referral_" + act, "ref#%d referrer#%s referred#%s ৳%s" % (i, rf["member_id"], x["member_id"], r["amount"]))
    except (LedgerError, PoolError) as e:
        err("ব্যর্থ (কিছুই পরিবর্তন হয়নি): " + str(e)); return back("/admin/referrals")
    flash("রেফারেল %s।" % ("অনুমোদিত হয়েছে" if act == "approve" else "বাতিল হয়েছে"))
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
        base = effective_rate(x)
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
                shown = effective_rate({"comm_rate": new}) if new is not None else d
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
    kd = request.args.get("kind", "")
    where, args = "1=1", []
    if kd in ("fund", "payout", "reversal", "withdraw"):
        where, args = "kind=?", [kd]
    pg = make_pg(q1("SELECT COUNT(*) n FROM pool_ledger WHERE " + where, args)["n"], 30)
    rows = qa("SELECT * FROM pool_ledger WHERE " + where + " ORDER BY id DESC LIMIT ? OFFSET ?", args + [30, pg["off"]])
    t = q1("SELECT COALESCE(SUM(CASE WHEN kind='fund' THEN amount END),0) f, COALESCE(SUM(CASE WHEN kind='payout' THEN -amount END),0) p, "
           "COALESCE(SUM(CASE WHEN kind='reversal' THEN amount END),0) r, COALESCE(SUM(CASE WHEN kind='withdraw' THEN -amount END),0) w FROM pool_ledger")
    bal, res = pool_balance(), pool_reserved()
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
    return page("""<div class="card"><h2>নোটিশ প্রকাশ</h2><form method="post"><input type="hidden" name="_csrf" value="{{csrf_token}}"><label>শিরোনাম</label><input name="title" required maxlength="100">
<label>বিস্তারিত</label><textarea name="body" rows="3" maxlength="500"></textarea><button style="width:100%">প্রকাশ করুন</button></form></div>
{% for n in rows %}<div class="card"><b>{{(n['title_en'] if lang=='en' and n['title_en'] else n['title'])}}</b><div>{{(n['body_en'] if lang=='en' and n['body_en'] else n['body'])}}</div><div class="k">{{n['created'][:16]}}</div></div>{% endfor %}""", active="/admin/notices", rows=rows)


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


ONOFF = [("1", "চালু"), ("0", "বন্ধ")]
# (id, title, fields, info) - field = (key, type, label[, options]); every field listed here is actually used by the app
SET_SECTIONS = [
    ("general", "⚙️ জেনারেল সেটিংস",
     [("welcome", "textarea", "স্বাগত বার্তা (হোম পেজে দেখায়)"),
      ("req_expiry_hours", "int", "ম্যানুয়াল রিকোয়েস্টের ডিফল্ট মেয়াদ (ঘণ্টা, ০ = মেয়াদ নেই)")], ""),
    ("payment", "💳 পেমেন্ট সেটিংস",
     [("bkash", "text", "bKash নম্বর"), ("nagad", "text", "Nagad নম্বর"), ("rocket", "text", "Rocket নম্বর")], ""),
    ("deposit", "➕ ডিপোজিট সেটিংস", [("min_deposit", "money", "ন্যূনতম ডিপোজিট (৳)")], ""),
    ("withdraw", "⬆ উইথড্র সেটিংস", [("min_withdraw", "money", "ন্যূনতম উইথড্র (৳)")], ""),
    ("commission", "💰 কমিশন সেটিংস", [],
     "এই সিস্টেমে কমিশন স্বয়ংক্রিয় নয়। অ্যাডমিন কাজের কারণসহ ম্যানুয়ালি কমিশন দেন (কমিশন ট্যাব)। তাই এখানে কোনো হার সেট করার নেই।"),
    ("referral", "🎁 রেফারেল সেটিংস", [("referral_bonus", "money", "রেফারেল বোনাস (৳, প্রতি সফল রেফার)")], ""),
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
    for k in ("min_deposit", "min_withdraw", "referral_bonus"):
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
        flash("সেভ হয়েছে।" + (" (রেফারেল বোনাসের নতুন পরিমাণ শুধু নতুন রিকোয়েস্টে প্রযোজ্য।)" if sec == "referral" else ""))
        return redirect("/admin/settings?open=" + sec)
    st = {k: setting(k) for k in SET_KEYS}
    st.setdefault("default_theme", "auto")
    for k, d in (("default_theme", "auto"), ("signup_open", "1"), ("notif_sound", "1"), ("req_expiry_hours", "24"), ("site_name", SITE)):
        st[k] = st[k] or d
    op = request.args.get("open", "general")
    return page("""{% for sec in secs %}<details class="card set" {{'open' if op==sec[0]}} id="{{sec[0]}}"><summary>{{sec[1]}}</summary>
{% if sec[3] %}<div class="k">{{sec[3]}}</div>{% endif %}
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


@app.route("/api/notif")
@login_required
def api_notif():
    u = me()
    if u["is_admin"]:
        f, pa = _alert_filter(u)
        latest = q1("SELECT COALESCE(MAX(a.id),0) m FROM admin_alerts a WHERE %s AND a.created>=?" % f, pa + [u["created"] or ""])["m"]
        return jsonify(unread=admin_unread(u), latest=latest)
    r = q1("SELECT COUNT(CASE WHEN is_read=0 THEN 1 END) c, COALESCE(MAX(id),0) m FROM notifications WHERE user_id=?", (u["id"],))
    return jsonify(unread=r["c"], latest=r["m"])


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
<button type="button" class="btn sm s" onclick="setSnd(!sndOn())">🔊 সাউন্ড: <span id="sndv"></span></button></div></div>
{% if not rows %}<div class="card empty">কোনো নোটিফিকেশন নেই</div>{% endif %}
{% for a in rows %}<div class="card {{'' if a['rd'] else 'new'}}"><b>{{a['title']}}</b>{% if not a['rd'] %} <span class="pill pending">নতুন</span>{% endif %}
<div>{{a['body']}}</div><div class="k">{{a['created'][:16]}}</div>
<form method="post" action="/admin/alerts/{{a['id']}}/open" style="margin-top:8px"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<button class="btn sm">{{'খুলুন' if a['link'] else 'পঠিত করুন'}}</button></form></div>{% endfor %}""", active="/admin/alerts", rows=rows)


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
    rows = qa("SELECT p.*,u.name,u.phone,u.member_id FROM payment_numbers p JOIN users u ON u.id=p.user_id WHERE %s "
              "ORDER BY p.updated DESC LIMIT 200" % " AND ".join(where), args)
    logs = qa("SELECT l.*,u.name,u.member_id FROM payment_number_log l LEFT JOIN users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 20")
    return page("""<div class="card"><form><input name="q" value="{{q}}" placeholder="নাম / ফোন / মেম্বার আইডি / নম্বর">
<select name="method"><option value="">সব মাধ্যম</option>{% for x in methods %}<option {{'selected' if x==m}}>{{x}}</option>{% endfor %}</select>
<select name="type"><option value="">সব ধরন</option>{% for x in types %}<option value="{{x}}" {{'selected' if x==t}}>{{tl[x]}} ({{x}})</option>{% endfor %}</select>
<button style="width:100%">খুঁজুন</button></form></div>
{% if not rows %}<div class="card empty">কোনো নম্বর নেই</div>{% endif %}
{% for r in rows %}<div class="card"><div class="row" style="align-items:center"><b>{{r['method']}} · {{tl[r['account_type']]}}</b></div>
<div style="font-size:18px;margin:4px 0">{{r['number']}}</div>
<div class="k"><a href="/admin/users/{{r['user_id']}}">#{{r['member_id']}} {{r['name']}}</a> · {{r['phone']}}</div>
<div class="k">জমা: {{r['created'][:16]}} · আপডেট: {{r['updated'][:16]}}</div></div>{% endfor %}
{% if logs %}<div class="card"><h3>সাম্প্রতিক পরিবর্তন</h3><div class="tw"><table>{% for l in logs %}<tr><td>{{(l['created'] or '')[:16]}}</td><td>#{{l['member_id']}} {{l['name']}}</td>
<td>{{l['action']}}</td><td>{{l['method']}}/{{l['account_type']}}/{{l['number']}}{% if l['old'] %} ← {{l['old']}}{% endif %}</td></tr>{% endfor %}</table></div></div>{% endif %}""",
                active="/admin/payment-numbers", rows=rows, logs=logs, q=q, m=m, t=t, tl=ACCT_LABEL, methods=METHODS, types=ACCT_TYPES)


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


def _confirm_view(r, u):
    lang = cur_lang()
    pur = (r["purpose_en"] if lang == "en" and r["purpose_en"] else r["purpose"]) or ""
    principal, com = round(float(r["amount"]), 2), round(float(r["commission"] or 0), 2)
    bal = round(float(u["balance"]), 2)
    return page("""<div class="card"><div class="row" style="align-items:center"><h2 style="margin:0">ডিপোজিট রিকোয়েস্ট</h2>
<span class="pill {{r['status']}}" style="flex:0;white-space:nowrap">{{labels[r['status']]}}</span></div>
<div class="k" style="margin-top:10px">Order ID</div><div class="copybox">{{r['order_id']}}</div>
<div class="k" style="margin-top:8px">উদ্দেশ্য (Purpose)</div><div class="hl" style="white-space:pre-line">{{pur}}</div>
{% if r['instructions'] %}<div class="k" style="margin-top:8px">নির্দেশনা</div><div class="hl" style="white-space:pre-line">{{r['instructions']}}</div>{% endif %}
<div class="tw" style="margin-top:10px"><table>
<tr><td>মূল পরিমাণ (আপনার ওয়ালেট থেকে কাটা হবে)</td><td><b>− ৳ {{money(principal)}}</b></td></tr>
<tr><td>কমিশন ({{'%g'|format(r['commission_rate'] or 0)}}%) — কোম্পানির প্রচারণা পুল থেকে যুক্ত হবে</td><td><b>+ ৳ {{money(com)}}</b></td></tr>
<tr><td>নিট ওয়ালেট পরিবর্তন</td><td><b>− ৳ {{money(principal-com)}}</b></td></tr>
<tr><td>বর্তমান ব্যালেন্স</td><td>৳ {{money(bal)}}</td></tr>
<tr><td>অনুমোদনের পর ব্যালেন্স</td><td>৳ {{money(bal-principal+com)}}</td></tr></table></div>
{% if r['expires_at'] and r['status']=='pending' %}<div class="k" style="margin-top:8px">⏳ মেয়াদ: {{r['expires_at'][:16]}} (UTC)</div>{% endif %}
<div class="k" style="margin-top:8px">অনুমোদন করলে সঙ্গে সঙ্গে সম্পন্ন হবে; আর কোনো অ্যাডমিন অনুমোদন লাগবে না। বাতিল করলে আপনার ব্যালেন্স অপরিবর্তিত থাকবে।</div></div>
{% if r['status']=='pending' %}<div class="card">{% if bal < principal %}<div class="msg error">আপনার ব্যালেন্স এই অনুরোধের জন্য পর্যাপ্ত নয়।</div>{% endif %}
<form method="post" action="/requests/{{r['id']}}/decide" data-confirm="উদ্দেশ্য, মূল পরিমাণ ও কমিশন দেখে নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<div class="row"><button name="act" value="approve" class="btn g" {{'disabled' if bal < principal}}>✅ অনুমোদন করুন</button><button name="act" value="reject" class="btn r">❌ বাতিল করুন</button></div></form></div>{% endif %}
<a class="btn s" href="/requests" style="width:100%">← সব অনুরোধ</a>""", active="/requests", r=r, pur=pur, principal=principal, com=com, bal=bal, labels=REQ_LABEL)


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
    return page("""<div class="card"><h2>অনুরোধ</h2><p class="k">অ্যাডমিনের পাঠানো ডিপোজিট/উইথড্র অনুরোধ এখানে দেখা যায়।</p></div>
{% if not rows %}<div class="card empty">কোনো অনুরোধ নেই</div>{% endif %}
{% for r in rows %}<a href="/requests/{{r['id']}}"><div class="card {{'new' if r['status']=='pending' else ''}}">
<div class="row" style="align-items:center"><b>{{rk(r)}} · ৳ {{money(r['amount'])}}</b><span class="pill {{r['status']}}" style="flex:0;white-space:nowrap">{{labels[r['status']]}}</span></div>
<div class="k">Order: {{r['order_id']}} · {{r['method']}} · {{r['created'][:16]}}</div></div></a>{% endfor %}""",
                active="/requests", rows=rows, kinds=REQ_KIND, labels=REQ_LABEL)


@app.route("/requests/<int:i>", methods=["GET", "POST"])
@customer_required
def request_view(i):
    u = me()
    expire_requests()
    r = q1("SELECT * FROM requests WHERE id=? AND user_id=?", (i, u["id"]))
    if not r:
        abort(404)
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
        alert_admins("অনুরোধ জমা", "#%s %s — Order %s (%s ৳%s)" % (u["member_id"], u["name"], r["order_id"], REQ_KIND[r["kind"]], money(r["amount"])),
                     "/admin/requests/%d" % i, "requests")
        alert_admins("ট্রানজেকশন স্ক্রিনশট আপলোড", "#%s Order %s" % (u["member_id"], r["order_id"]), "/admin/requests/%d" % i, "requests")
        flash("জমা হয়েছে। অ্যাডমিন যাচাই করবেন।"); return redirect(back_to)
    return page("""<div class="card"><div class="row" style="align-items:center"><h2 style="margin:0">{{rk(r)}} অনুরোধ</h2>
<span class="pill {{r['status']}}" style="flex:0;white-space:nowrap">{{labels[r['status']]}}</span></div>
<div class="k" style="margin-top:10px">Order ID</div><div class="copybox">{{r['order_id']}}</div>
<div class="k">পরিমাণ</div><div class="v">৳ {{money(r['amount'])}}</div>
<div class="k" style="margin-top:8px">পেমেন্ট মাধ্যম</div><div><b>{{r['method']}}</b></div>
<div class="k" style="margin-top:8px">পেমেন্ট নম্বর</div><div class="row" style="align-items:center"><div class="copybox" style="margin:6px 0">{{r['pay_number']}}</div>
<button type="button" class="btn sm" style="flex:0" data-copy="{{r['pay_number']}}">📋 কপি</button></div>
{% if r['instructions'] %}<div class="k" style="margin-top:8px">নির্দেশনা</div><div class="hl">{{r['instructions']}}</div>{% endif %}
{% if r['expires_at'] and r['status']=='pending' %}<div class="k" style="margin-top:8px">⏳ মেয়াদ: {{r['expires_at'][:16]}} (UTC)</div>{% endif %}
{% if r['flow']=='admin_review' and r['commission'] %}<div class="hl" style="margin-top:8px">🎁 কমিশন ({{'%g'|format(r['commission_rate'] or 0)}}%): ৳{{money(r['commission'])}} — কোম্পানির প্রচারণা পুল থেকে। অনুমোদনের পর মোট ৳{{money(r['amount']+r['commission'])}} ওয়ালেটে যুক্ত হবে (মূল ৳{{money(r['amount'])}} + কমিশন ৳{{money(r['commission'])}})।</div>{% endif %}
<div class="k" style="margin-top:8px">{% if r['kind']=='deposit' %}অ্যাডমিন অনুমোদন করলে ৳{{money(r['amount'])}} আপনার ওয়ালেটে যুক্ত হবে।
{% else %}অ্যাডমিন অনুমোদন করলে ৳{{money(r['amount'])}} আপনার ওয়ালেট থেকে কাটা হবে।{% endif %} জমা দিলে ব্যালেন্স নিজে থেকে বদলায় না।</div></div>
{% if r['status']=='pending' %}<div class="card"><h3>পেমেন্টের তথ্য জমা দিন</h3>
<form method="post" enctype="multipart/form-data" data-confirm="তথ্য ঠিক আছে? জমা দেবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<label>Transaction ID (TrxID)</label><input name="trx" required autocomplete="off" maxlength="40">
<label>ট্রানজেকশনের স্ক্রিনশট (JPG/PNG/WEBP, ≤২MB)</label><input type="file" name="shot" accept="image/*" required>
<button style="width:100%">যাচাইয়ের জন্য জমা দিন</button></form></div>
{% elif r['trx'] %}<div class="card"><h3>আপনার জমা দেওয়া তথ্য</h3><div>TrxID: <b>{{r['trx']}}</b></div><div class="k">জমা: {{(r['submitted_at'] or '')[:16]}}</div>
{% if r['screenshot'] %}<a href="/shot/{{r['screenshot']}}" target="_blank"><img class="shot" src="/shot/{{r['screenshot']}}" alt="screenshot"></a>{% endif %}</div>{% endif %}
{% if r['status']=='rejected' and r['reject_reason'] %}<div class="card"><b>রিজেক্টের কারণ</b><div>{{r['reject_reason']}}</div></div>{% endif %}
<a class="btn s" href="/requests" style="width:100%">← সব অনুরোধ</a>""", active="/requests", r=r, kinds=REQ_KIND, labels=REQ_LABEL)


# ---- admin side
def _find_users(q):
    like = "%" + q + "%"
    return qa("SELECT id,name,phone,member_id,balance,blocked FROM users WHERE is_admin=0 AND "
              "(name LIKE ? OR phone LIKE ? OR member_id LIKE ?) ORDER BY id DESC LIMIT 20", (like, like, like))


@app.route("/admin/requests/new", methods=["GET", "POST"])
@staff_required("requests")
def admin_request_new():
    a = me()
    if request.method == "POST":
        uid = request.form.get("uid", type=int)
        x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (uid,)) if uid else None
        if not x or x["blocked"]:
            err("সঠিক (ব্লক নয় এমন) ইউজার নির্বাচন করুন।"); return redirect("/admin/requests/new")
        back_to = "/admin/requests/new?uid=%d" % uid
        rtype = request.form.get("type") or request.form.get("kind") or ""
        if rtype not in REQ_TYPES:
            err("অনুরোধের ধরন বাছাই করুন।"); return redirect(back_to)
        kind, flow = REQ_TYPES[rtype]
        method = request.form.get("method", "")
        order = re.sub(r"[^A-Z0-9_-]", "", request.form.get("order_id", "").upper())[:32]
        amt = parse_amount(request.form.get("amount"))
        num = request.form.get("number", "").strip()
        ins = request.form.get("instructions", "").strip()[:500]
        purpose = request.form.get("purpose", "").strip()[:300]
        purpose_en = request.form.get("purpose_en", "").strip()[:300]
        hrs_raw = request.form.get("hours", "").strip() or "0"
        if flow == "client_confirm":
            method, num = "Wallet", "-"
        bad = len(order) < 4 or amt <= 0 or amt > 100_000_000 or not re.fullmatch(r"\d{1,3}", hrs_raw) or int(hrs_raw) > 720
        if flow != "client_confirm" and (method not in METHODS or not PHONE_RE.fullmatch(num)):
            bad = True
        if flow == "client_confirm" and len(purpose) < 5:
            err("উদ্দেশ্য (Purpose) লিখুন — ক্লায়েন্টকে অনুমোদনের আগে এটি দেখানো হবে।"); return redirect(back_to)
        if bad:
            err("ধরন, ৪+ অক্ষরের Order ID (A-Z, 0-9, -, _), সঠিক পরিমাণ, মাধ্যম, ১১ ডিজিটের নম্বর (ক্লায়েন্ট-কনফার্ম ছাড়া) ও ০–৭২০ ঘণ্টার মেয়াদ দিন।")
            return redirect(back_to)
        hrs = int(hrs_raw)
        exp = (datetime.utcnow() + timedelta(hours=hrs)).strftime("%Y-%m-%d %H:%M:%S") if hrs else None
        rate = effective_rate(x) if flow else None
        com = commission_for(amt, rate) if flow else None
        if rate_hit("rqc:%d" % a["id"], 60, 3600):
            err("অনেক রিকোয়েস্ট হয়েছে।"); return redirect(back_to)
        try:
            with atomic():
                if flow == "client_confirm" and float(q1("SELECT balance FROM users WHERE id=?", (x["id"],))["balance"]) + 1e-9 < amt:
                    raise ReqError("ইউজারের বর্তমান ব্যালেন্স অনুরোধের পরিমাণের চেয়ে কম।")
                if flow and com > 0 and pool_available() + 0.004 < com:
                    raise PoolError("কমিশন পুলে পর্যাপ্ত ফান্ড নেই (উপলব্ধ ৳%s, দরকার ৳%s)। আগে পুলে ফান্ড যোগ করুন।" % (money(max(pool_available(), 0)), money(com)))
                cur = db().execute("INSERT INTO requests(order_id,user_id,kind,amount,method,pay_number,instructions,expires_at,status,"
                                   "created_by_id,created_by,created,updated,flow,commission,commission_rate,purpose,purpose_en) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                   (order, x["id"], kind, amt, method, num, ins, exp, "pending", a["id"], a["member_id"], now(), now(),
                                    flow, com, rate, purpose or None, purpose_en or None))
                rid = cur.lastrowid
                req_log(rid, "create", None, "pending", a["member_id"], a["id"], "%s/%s ৳%s commission ৳%s" % (kind, flow or "-", amt, com or 0))
                if flow == "client_confirm":
                    notify(x["id"], "নতুন ডিপোজিট রিকোয়েস্ট", "৳%s কাটা হবে, কমিশন ৳%s। উদ্দেশ্য: %s। Order: %s" % (money(amt), money(com), purpose, order), "/requests/%d" % rid,
                           "New deposit request", "৳%s will be deducted, commission ৳%s. Purpose: %s. Order: %s" % (money(amt), money(com), purpose_en or purpose, order))
                else:
                    notify(x["id"], "নতুন অনুরোধ", "%s অনুরোধ — ৳%s (%s)%s। Order: %s" % (REQ_KIND[kind], money(amt), method, (" + কমিশন ৳%s" % money(com)) if com else "", order),
                           "/requests/%d" % rid)
                audit("req_create", "req#%d order=%s %s/%s ৳%s commission ৳%s user#%d admin_id=%d" % (rid, order, kind, flow or "-", amt, com or 0, x["id"], a["id"]))
        except (ReqError, PoolError) as ex:
            err(str(ex)); return redirect(back_to)
        except INTEGRITY:
            err("এই Order ID আগেই ব্যবহার করা হয়েছে।"); return redirect(back_to)
        flash("অনুরোধ পাঠানো হয়েছে।"); return redirect("/admin/requests/%d" % rid)
    q = request.args.get("q", "").strip().lstrip("#")[:40]
    uid = request.args.get("uid", type=int)
    x = q1("SELECT * FROM users WHERE id=? AND is_admin=0", (uid,)) if uid else None
    found = _find_users(q) if (q and not x) else []
    try:
        dh = int(setting("req_expiry_hours", "24") or 0)
    except ValueError:
        dh = 24
    return page("""{% if not x %}<div class="card"><h2>নতুন অনুরোধ — ইউজার বাছাই</h2><form><input name="q" value="{{q}}" placeholder="নাম / ফোন / মেম্বার আইডি" autofocus>
<button style="width:100%">খুঁজুন</button></form></div>
{% if q and not found %}<div class="card empty">কোনো ইউজার পাওয়া যায়নি</div>{% endif %}
{% for f in found %}<a href="/admin/requests/new?uid={{f['id']}}"><div class="card"><b>#{{f['member_id']}} {{f['name']}}</b>{% if f['blocked'] %} <span class="pill rejected">blocked</span>{% endif %}
<div class="k">{{f['phone']}} · ৳ {{money(f['balance'])}}</div></div></a>{% endfor %}
{% else %}<div class="card"><h2>নতুন অনুরোধ</h2><div class="k">ইউজার: <b>#{{x['member_id']}} {{x['name']}}</b> · {{x['phone']}} · ব্যালেন্স ৳ {{money(x['balance'])}}</div>
<a class="k" href="/admin/requests/new">← অন্য ইউজার বাছাই</a>
<form method="post" data-confirm="অনুরোধটি ইউজারকে পাঠাবেন?"><input type="hidden" name="_csrf" value="{{csrf_token}}"><input type="hidden" name="uid" value="{{x['id']}}">
<label>ধরন</label><select name="type"><option value="client_confirm">ডিপোজিট রিকোয়েস্ট — ক্লায়েন্ট নিজে কনফার্ম করবে (মূল টাকা ওয়ালেট থেকে কাটা + কমিশন পুল থেকে)</option><option value="admin_review">উইথড্র/পেমেন্ট রিকোয়েস্ট — ক্লায়েন্ট পেমেন্ট জমা দেবে, অ্যাডমিন যাচাই করবে (মূল টাকা + কমিশন ওয়ালেটে যোগ)</option><option value="deposit">সাধারণ ডিপোজিট (কমিশন ছাড়া)</option><option value="withdraw">সাধারণ উইথড্র (কমিশন ছাড়া)</option></select>
<div class="k">এই ইউজারের কমিশন রেট: <b>{{rate|pct}}%</b> · পুলে উপলব্ধ ফান্ড: <b>৳{{money(avail)}}</b> (কমিশন শুধু পুল থেকে যায়)</div>
<label>উদ্দেশ্য — বাংলা (ক্লায়েন্ট-কনফার্মে আবশ্যক; ক্লায়েন্টকে অনুমোদনের আগে দেখানো হবে)</label><textarea name="purpose" rows="2" maxlength="300"></textarea>
<label>Purpose — English (optional)</label><textarea name="purpose_en" rows="2" maxlength="300"></textarea>
<label>Order ID</label><input name="order_id" required maxlength="32" value="{{oid}}" autocapitalize="characters">
<label>পরিমাণ (৳ BDT)</label><input name="amount" type="number" step="0.01" min="0.01" required>
<label>পেমেন্ট মাধ্যম</label><select name="method">{% for m in methods %}<option>{{m}}</option>{% endfor %}</select>
<label>পেমেন্ট নম্বর (১১ ডিজিট; ক্লায়েন্ট-কনফার্মে লাগবে না)</label><input name="number" inputmode="numeric" maxlength="11">
<label>নির্দেশনা (ঐচ্ছিক)</label><textarea name="instructions" rows="3" maxlength="500"></textarea>
<label>মেয়াদ (ঘণ্টা, ঐচ্ছিক; ০ = মেয়াদ নেই)</label><input name="hours" type="number" min="0" max="720" value="{{dh}}">
<button style="width:100%">📨 ইউজারকে পাঠান</button></form></div>{% endif %}""",
                active="/admin/requests", x=x, q=q, found=found, methods=METHODS, dh=dh, oid="ORD" + secrets.token_hex(4).upper(), rate=effective_rate(x) if x else 0, avail=pool_available())


@app.route("/admin/requests")
@staff_required("requests")
def admin_requests():
    expire_requests()
    st, kd = request.args.get("status", "open"), request.args.get("kind", "")
    q = request.args.get("q", "").strip().lstrip("#")[:40]
    like = "%" + q + "%"
    where, args = [], []
    if st == "open":
        where.append("r.status IN ('submitted','review')")
    elif st in REQ_LABEL:
        where.append("r.status=?"); args.append(st)
    else:
        st = "all"
    if kd in REQ_KIND:
        where.append("r.kind=?"); args.append(kd)
    if q:
        where.append("(r.order_id LIKE ? OR u.name LIKE ? OR u.phone LIKE ? OR u.member_id LIKE ? OR r.trx LIKE ?)"); args += [like] * 5
    rows = qa("SELECT r.*,u.name,u.phone,u.member_id FROM requests r JOIN users u ON u.id=r.user_id%s ORDER BY r.id DESC LIMIT 100"
              % ((" WHERE " + " AND ".join(where)) if where else ""), args)
    return page("""<div class="card"><div class="row" style="align-items:center"><h2 style="margin:0">রিকোয়েস্ট</h2><a class="btn sm g" href="/admin/requests/new" style="flex:0;white-space:nowrap">➕ নতুন</a></div>
<form style="margin-top:10px"><input name="q" value="{{q}}" placeholder="Order ID / নাম / ফোন / আইডি / TrxID">
<select name="status"><option value="open" {{'selected' if st=='open'}}>যাচাইয়ের অপেক্ষায় (জমা + যাচাইয়ে)</option><option value="all" {{'selected' if st=='all'}}>সব</option>
{% for k,l in labels.items() %}<option value="{{k}}" {{'selected' if st==k}}>{{l}}</option>{% endfor %}</select>
<select name="kind"><option value="">ডিপোজিট + উইথড্র</option>{% for k,l in kinds.items() %}<option value="{{k}}" {{'selected' if kd==k}}>{{l}}</option>{% endfor %}</select>
<button style="width:100%">ফিল্টার</button></form></div>
{% if not rows %}<div class="card empty">কোনো রিকোয়েস্ট নেই</div>{% endif %}
{% for r in rows %}<a href="/admin/requests/{{r['id']}}"><div class="card"><div class="row" style="align-items:center"><b>{{rk(r)}} · ৳ {{money(r['amount'])}}</b>
<span class="pill {{r['status']}}" style="flex:0;white-space:nowrap">{{labels[r['status']]}}</span></div>
<div class="k">Order {{r['order_id']}} · {{r['method']}} · #{{r['member_id']}} {{r['name']}}</div>
<div class="k">{{r['created'][:16]}}{% if r['trx'] %} · TrxID: {{r['trx']}}{% endif %}{% if r['screenshot'] %} · 🖼{% endif %}</div></div></a>{% endfor %}""",
                active="/admin/requests", rows=rows, st=st, kd=kd, q=q, labels=REQ_LABEL, kinds=REQ_KIND)


@app.route("/admin/requests/<int:i>")
@staff_required("requests")
def admin_request_view(i):
    expire_requests()
    r = q1("SELECT r.*,u.name,u.phone,u.member_id,u.balance FROM requests r JOIN users u ON u.id=r.user_id WHERE r.id=?", (i,))
    if not r:
        abort(404)
    log = qa("SELECT * FROM request_log WHERE request_id=? ORDER BY id", (i,))
    return page("""<div class="card"><div class="row" style="align-items:center"><h2 style="margin:0">{{rk(r)}} · ৳ {{money(r['amount'])}}</h2>
<span class="pill {{r['status']}}" style="flex:0;white-space:nowrap">{{labels[r['status']]}}</span></div>
<div class="k" style="margin-top:8px">Order ID: <b>{{r['order_id']}}</b> · {{r['method']}} · {{r['pay_number']}}</div>
<div class="k"><a href="/admin/users/{{r['user_id']}}">#{{r['member_id']}} {{r['name']}}</a> · {{r['phone']}} · ব্যালেন্স ৳ {{money(r['balance'])}}</div>
<div class="k">তৈরি: {{r['created'][:16]}} ({{r['created_by']}}){% if r['expires_at'] %} · মেয়াদ: {{r['expires_at'][:16]}} UTC{% endif %}</div>
{% if r['flow'] %}<div class="hl" style="margin-top:6px"><b>{{rk(r)}}</b> · মূল ৳{{money(r['amount'])}} · কমিশন ({{'%g'|format(r['commission_rate'] or 0)}}%) ৳{{money(r['commission'] or 0)}}{% if r['purpose'] %}<br>উদ্দেশ্য: {{r['purpose']}}{% endif %}{% if r['purpose_en'] %}<br>Purpose: {{r['purpose_en']}}{% endif %}<br>
{% if r['flow']=='client_confirm' %}ক্লায়েন্টের সিদ্ধান্তের অপেক্ষা — অ্যাডমিন অ্যাপ্রুভ/রিজেক্ট করতে পারবে না (শুধু বাতিল)।{% else %}অ্যাপ্রুভ করলে ওয়ালেটে যোগ: ৳{{money(r['amount']+(r['commission'] or 0))}}{% endif %}</div>
{% if r['flow']=='admin_review' and r['status'] in ('submitted','review') and (r['commission'] or 0) > pool_av %}<div class="msg error" style="margin-top:8px">⚠ কমিশন পুলে পর্যাপ্ত ফান্ড নেই — অ্যাপ্রুভ করা যাবে না (উপলব্ধ ৳{{money(pool_av)}}) — আগে পুলে ফান্ড যোগ করুন।</div>{% endif %}{% endif %}
{% if r['instructions'] %}<div class="hl" style="margin-top:6px">{{r['instructions']}}</div>{% endif %}
{% if r['trx'] %}<div style="margin-top:8px">TrxID: <b>{{r['trx']}}</b> <span class="k">(জমা: {{(r['submitted_at'] or '')[:16]}})</span></div>{% endif %}
{% if r['screenshot'] %}<a href="/shot/{{r['screenshot']}}" target="_blank"><img class="shot" src="/shot/{{r['screenshot']}}" alt="screenshot"></a>{% endif %}
{% if r['decided_by'] %}<div class="k">সিদ্ধান্ত: {{r['decided_by']}} · {{(r['decided_at'] or '')[:16]}}{% if r['reject_reason'] %} · {{r['reject_reason']}}{% endif %}</div>{% endif %}
{% if r['kind']=='withdraw' and r['status'] in ('submitted','review') and r['balance'] < r['amount'] %}<div class="msg error" style="margin-top:8px">⚠ ইউজারের বর্তমান ব্যালেন্স অনুরোধের চেয়ে কম — অ্যাপ্রুভ করা যাবে না।</div>{% endif %}</div>
{% if r['status'] in ('pending','submitted','review') %}<div class="card"><h3>কাজ</h3>
<form method="post" action="/admin/requests/{{r['id']}}/act" data-confirm="নিশ্চিত?"><input type="hidden" name="_csrf" value="{{csrf_token}}">
<input name="reason" placeholder="কারণ / নোট (রিজেক্টে আবশ্যক)" maxlength="200"><div class="row">
{% if r['status']=='submitted' %}<button name="act" value="review" class="btn sm s">যাচাইয়ে নিন</button>{% endif %}
{% if r['status'] in ('submitted','review') %}<button name="act" value="approve" class="btn sm g">✅ অ্যাপ্রুভ</button><button name="act" value="reject" class="btn sm r">❌ রিজেক্ট</button>{% endif %}
<button name="act" value="cancel" class="btn sm s">বাতিল করুন</button></div></form></div>{% endif %}
<div class="card"><h3>ইতিহাস</h3><div class="tw"><table>{% for l in log %}<tr><td>{{l['created'][:16]}}</td><td>{{l['action']}}</td><td>{{l['from_status'] or '-'}} → {{l['to_status']}}</td><td>{{l['actor']}}</td><td>{{l['note'] or ''}}</td></tr>{% endfor %}</table></div></div>
<a class="btn s" href="/admin/requests" style="width:100%">← সব রিকোয়েস্ট</a>""", active="/admin/requests", r=r, log=log, kinds=REQ_KIND, labels=REQ_LABEL, pool_av=pool_available(exclude=i))


@app.route("/admin/requests/<int:i>/act", methods=["POST"])
@staff_required("requests")
def admin_request_act(i):
    act = request.form.get("act", "")
    reason = request.form.get("reason", "").strip()[:200]
    a = me()
    if act not in REQ_ALLOWED:
        abort(400)
    back_to = "/admin/requests/%d" % i
    if act == "reject" and not reason:
        err("রিজেক্টের কারণ লিখুন।"); return redirect(back_to)
    expire_requests()
    try:
        with atomic():
            r = q1("SELECT * FROM requests WHERE id=?", (i,))
            if not r:
                abort(404)
            if r["status"] not in REQ_ALLOWED[act]:
                raise ReqError("এই অনুরোধে এখন এই কাজ সম্ভব নয় (হয়তো আগেই সম্পন্ন হয়েছে)।")
            if r["flow"] == "client_confirm" and act in ("review", "approve", "reject"):
                raise ReqError("এই অনুরোধ ক্লায়েন্টের সিদ্ধান্তের অপেক্ষায় — অ্যাডমিন অনুমোদন/রিজেক্ট করতে পারবে না (শুধু বাতিল করা যায়)।")
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
            req_log(i, act, r["status"], new, a["member_id"], a["id"], reason)
            audit("req_" + act, "req#%d order=%s %s ৳%s user#%d trx=%s admin_id=%d at=%s" %
                  (i, r["order_id"], r["kind"], r["amount"], r["user_id"], r["norm_trx"] or "-", a["id"], t))
            msgs = {"review": ("অনুরোধ যাচাইয়ে আছে", "Order %s এখন যাচাই করা হচ্ছে।" % r["order_id"]),
                    "approve": ("অনুরোধ অনুমোদিত", ("৳%s আপনার ওয়ালেটে যুক্ত হয়েছে।" if r["kind"] == "deposit" else "৳%s আপনার ওয়ালেট থেকে কাটা হয়েছে।")
                                % money(r["amount"]) + " Order %s" % r["order_id"]),
                    "reject": ("অনুরোধ রিজেক্ট", "Order %s গৃহীত হয়নি। কারণ: %s" % (r["order_id"], reason)),
                    "cancel": ("অনুরোধ বাতিল", "Order %s বাতিল করা হয়েছে।%s" % (r["order_id"], (" কারণ: " + reason) if reason else ""))}
            if act == "approve" and r["flow"] == "admin_review" and float(r["commission"] or 0) > 0:
                msgs["approve"] = ("অনুরোধ অনুমোদিত", "৳%s + কমিশন ৳%s আপনার ওয়ালেটে যুক্ত হয়েছে। Order %s" % (money(r["amount"]), money(r["commission"]), r["order_id"]))
            notify(r["user_id"], msgs[act][0], msgs[act][1], "/requests/%d" % i)
    except ReqError as ex:
        err(str(ex)); return redirect(back_to)
    except PoolError as ex:
        err("কমিশন পুলে পর্যাপ্ত ফান্ড নেই — অ্যাপ্রুভ হয়নি, কিছুই পরিবর্তন হয়নি: %s" % ex); return redirect(back_to)
    except LedgerError as ex:
        err("লেজার ত্রুটি, কিছুই পরিবর্তন হয়নি: %s" % ex); return redirect(back_to)
    flash("সম্পন্ন: %s" % REQ_LABEL[new])
    return redirect(back_to)


# ================================================================ Phase 2C: referral network, financial reports + CSV, reconciliation
# Read-only on money: nothing here creates or moves funds (referral rewards are paid by the pool engine above).
from flask import Response

LK_LABEL = {"deposit": "ডিপোজিট", "request_deposit": "অনুরোধ-ডিপোজিট", "withdraw_hold": "উইথড্র (হোল্ড)", "withdraw_release": "উইথড্র ফেরত",
            "request_withdraw": "অনুরোধ-উইথড্র", "request_payment": "ক্লায়েন্ট পেমেন্ট", "commission": "কমিশন", "commission_reversal": "কমিশন ফেরত",
            "referral_bonus": "রেফারেল বোনাস", "admin_adjust": "ব্যালেন্স সমন্বয়"}
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
                total=total, n=len(rows), buckets=buckets, show=show, pg=pg, loc=_loc)


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
                lines=lines[pg["off"]:pg["off"] + 40], pg=pg, loc=_loc, lk=LK_LABEL)


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
<p class="k">পরীক্ষার সময়: {{ts}} (UTC)</p>{% if can('pool_view') %}<a class="btn sm s" href="/admin/pool">কমিশন পুল</a>{% endif %} <a class="btn sm s" href="/admin/reports">রিপোর্ট</a></div>""",
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
<div class="card"><h3>যাদের রেফার করেছেন</h3>{% for r in kids %}<div class="row" style="justify-content:space-between;align-items:center"><span><a href="/admin/referrals/user/{{r['referred_id']}}">#{{r['mid']}} {{r['nm']}}</a> <span class="k">{{r['joined'][:10] if r['joined'] else ''}}</span></span><span class="k">{{r['status']}} · ৳{{money(r['amount'])}}{% if r['decided_at'] %} · {{r['decided_at'][:10]}}{% endif %}</span></div>{% endfor %}{% if not kids %}<div class="k">কাউকে রেফার করেননি</div>{% endif %}</div>
<div class="card"><h3>রেফারেল বোনাসের ইতিহাস (ওয়ালেটে জমা)</h3>{% for l in paid %}<div class="row" style="justify-content:space-between"><span class="k">{{l['created'][:16]}} · {{l['note'] or ''}}</span><b>৳{{money(l['amount'])}} <span class="k">{{'পুল' if l['funded'] else 'পুল-পূর্ব'}}</span></b></div>{% endfor %}{% if not paid %}<div class="k">কোনো বোনাস পাননি</div>{% endif %}</div>""",
                active="/admin/referrals", x=x, by=by, kids=kids, paid=paid, st=st)




# ---------------------------------------------------------------- PWA (installable app; only a static shell is ever cached - no private/financial data)
PWA_DIR = os.path.join(app.root_path, "static")


@app.route("/manifest.json")
def pwa_manifest():
    r = send_from_directory(PWA_DIR, "manifest.json", mimetype="application/manifest+json")
    r.headers["Cache-Control"] = "public, max-age=3600"
    return r


@app.route("/service-worker.js")
def pwa_service_worker():
    r = send_from_directory(PWA_DIR, "service-worker.js", mimetype="application/javascript")
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
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
