#!/usr/bin/env python3
"""E-Wallet Support v5 - migration / backup / verification tool. NEVER touches the source SQLite file (opened read-only)
and refuses to write into a PostgreSQL database that already contains users.

  python tools/dbtool.py import-sqlite  ewallet.db     copy a v4 SQLite database into the (empty) PostgreSQL database in DATABASE_URL
  python tools/dbtool.py verify         ewallet.db     compare source SQLite vs PostgreSQL: row counts + per-table checksums + ledger
  python tools/dbtool.py check                         ledger/balance reconciliation + row counts of the current database
  python tools/dbtool.py backup         out.zip        logical backup (CSV per table + manifest.json with SHA-256)
  python tools/dbtool.py restore-csv    backup.zip     restore such a backup into an EMPTY PostgreSQL database
  python tools/dbtool.py upload-screenshots <folder>   copy existing local screenshots to Supabase Storage (same file names, originals unchanged)
"""
import os, sys, io, csv, json, zipfile, hashlib, sqlite3
os.environ["EWALLET_SKIP_MIGRATE"] = "1"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as A

MONEY = {"balance", "commission", "amount"}
PK = {"admin_alert_reads": ("alert_id", "admin_id"), "settings": ("k",), "meta": ("k",)}


def die(msg, code=2):
    print("ERROR:", msg); sys.exit(code)


def pg():
    if not A.PG:
        die("DATABASE_URL (postgresql://...) is not set - nothing to do against PostgreSQL.")
    return A.PGConn(A._pg_connect())


def canon(table, cols, row):
    out = []
    for c, v in zip(cols, row):
        if v is None: out.append("∅")
        elif c in MONEY and v != "": out.append("%.2f" % round(float(v), 2))
        else: out.append(str(v))
    return "\x1f".join(out)


def table_digest(rows_canon):
    h = hashlib.sha256()
    for r in sorted(rows_canon): h.update(r.encode("utf-8")); h.update(b"\n")
    return h.hexdigest()


def src_open(path):
    if not os.path.isfile(path): die("source file not found: " + path)
    s = sqlite3.connect("file:%s?mode=ro" % path, uri=True); s.row_factory = sqlite3.Row
    try:
        v = s.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
    except sqlite3.Error:
        v = None
    if not v or str(v[0]) != str(A.SCHEMA_VERSION):
        die("source database is not at schema version %d (found %s). Run the v4/v5 app once in SQLite mode against a COPY of the file "
            "so it upgrades itself, then import that copy." % (A.SCHEMA_VERSION, v[0] if v else "none"))
    return s


def pg_cols(c, t):
    return [r["column_name"] for r in c.execute("SELECT column_name FROM information_schema.columns WHERE table_schema='public' "
                                                 "AND table_name=? ORDER BY ordinal_position", (t,))]


def insert_rows(c, t, cols, rows):
    if not rows: return
    sql = "INSERT INTO %s(%s) VALUES(%s)" % (t, ",".join(cols), ",".join(["%s"] * len(cols)))
    for r in rows:
        vals = [round(float(v), 2) if (k in MONEY and v is not None and v != "") else v for k, v in zip(cols, r)]
        c.c.execute(sql, tuple(vals))


def reset_sequences(c):
    for t in A.ID_TABLES:
        c.c.execute("SELECT setval(pg_get_serial_sequence('public.%s','id'), COALESCE((SELECT MAX(id) FROM %s),0)+1, false)" % (t, t))


def require_empty(c):
    n = c.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    if n: die("the PostgreSQL database already has %d users. Refusing to import into a non-empty database." % n)


def cmd_import(path):
    src = src_open(path); c = pg()
    A.pg_schema(c); require_empty(c)
    c.execute("BEGIN IMMEDIATE")
    try:
        for t in A.TABLES:
            if src.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (t,)).fetchone() is None: continue
            cols = [r[1] for r in src.execute("PRAGMA table_info(%s)" % t)]
            missing = [x for x in cols if x not in pg_cols(c, t)]
            if missing: raise RuntimeError("column(s) %s of %s do not exist in PostgreSQL" % (missing, t))
            rows = [tuple(r) for r in src.execute("SELECT %s FROM %s" % (",".join(cols), t))]
            insert_rows(c, t, cols, rows)
            print("  %-20s %6d rows" % (t, len(rows)))
        reset_sequences(c)
        A._seed_defaults(c)
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK"); print("ROLLED BACK - PostgreSQL left unchanged."); raise
    print("import finished; verifying ...")
    return cmd_verify(path, c)


def cmd_verify(path, c=None):
    src = src_open(path); c = c or pg(); bad = 0
    print("%-20s %8s %8s  %s" % ("table", "source", "postgres", "checksum"))
    for t in A.TABLES:
        cols = [r[1] for r in src.execute("PRAGMA table_info(%s)" % t)]
        a = [canon(t, cols, tuple(r)) for r in src.execute("SELECT %s FROM %s" % (",".join(cols), t))]
        b = [canon(t, cols, tuple(r)) for r in c.execute("SELECT %s FROM %s" % (",".join(cols), t))]
        same = len(a) == len(b) and table_digest(a) == table_digest(b)
        bad += not same
        print("%-20s %8d %8d  %s" % (t, len(a), len(b), "MATCH" if same else "MISMATCH"))
    sb = src.execute("SELECT ROUND(COALESCE(SUM(balance),0),2) FROM users").fetchone()[0]
    pb = c.execute("SELECT ROUND(COALESCE(SUM(balance),0),2) s FROM users").fetchone()["s"]
    print("sum(balance): source %.2f  postgres %.2f  %s" % (sb, pb, "MATCH" if abs(sb - pb) < 0.005 else "MISMATCH")); bad += abs(sb - pb) >= 0.005
    rc = cmd_check(c, quiet=True); print("ledger vs balance mismatches in PostgreSQL:", rc)
    print("RESULT:", "ALL MATCH" if not bad and rc == 0 else "PROBLEMS FOUND (see above)")
    return 0 if not bad and rc == 0 else 1


def cmd_check(c=None, quiet=False):
    c = c or pg()
    rows = c.execute("""SELECT u.id,u.member_id,u.balance, COALESCE(SUM(l.amount),0) AS ledger_sum FROM users u
                        LEFT JOIN ledger l ON l.user_id=u.id GROUP BY u.id HAVING ABS(u.balance-COALESCE(SUM(l.amount),0))>0.005""").fetchall()
    if not quiet:
        for t in A.TABLES: print("%-20s %6d" % (t, c.execute("SELECT COUNT(*) c FROM %s" % t).fetchone()["c"]))
        print("mismatching users:", len(rows))
        for r in rows: print("  user", r["id"], r["member_id"], "balance", r["balance"], "ledger", r["ledger_sum"])
    return len(rows)


def cmd_backup(out):
    c = pg() if A.PG else A.sqlite3.connect(A.DB)
    if not A.PG:
        c.row_factory = sqlite3.Row
    A.export_tables_zip(c, out); print("wrote", out)


def cmd_restore(path):
    c = pg(); A.pg_schema(c); require_empty(c)
    z = zipfile.ZipFile(path); man = json.loads(z.read("manifest.json"))
    if man.get("schema_version") != A.SCHEMA_VERSION: die("backup schema version %s != %s" % (man.get("schema_version"), A.SCHEMA_VERSION))
    c.execute("BEGIN IMMEDIATE")
    try:
        for t in A.TABLES:
            data = z.read(t + ".csv")
            if hashlib.sha256(data).hexdigest() != man["tables"][t]["sha256"]: raise RuntimeError("checksum mismatch for " + t)
            rd = csv.reader(io.StringIO(data.decode("utf-8")))
            cols = next(rd)
            rows = [tuple(None if v == A.NULL_MARK else v for v in r) for r in rd]
            if len(rows) != man["tables"][t]["rows"]: raise RuntimeError("row count mismatch for " + t)
            insert_rows(c, t, cols, rows); print("  %-20s %6d rows" % (t, len(rows)))
        reset_sequences(c); c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK"); print("ROLLED BACK - database left unchanged."); raise
    print("restore finished; run `check` to confirm ledger == balances.")


def cmd_upload(folder):
    if A.STORAGE != "supabase": die("set SUPABASE_URL and SUPABASE_SERVICE_KEY first.")
    names = sorted(n for n in os.listdir(folder) if A.SHOT_RE.fullmatch(n))
    up = skip = fail = 0
    for n in names:
        data = open(os.path.join(folder, n), "rb").read()
        try:
            A.store_put(n, data); up += 1
        except A.StorageError as e:
            if "409" in str(e): skip += 1
            else: fail += 1; print("  FAILED", n, e)
    bad = 0
    for n in names:  # read everything back and compare SHA-256
        got = A.store_get(n)
        if got is None or hashlib.sha256(got).hexdigest() != hashlib.sha256(open(os.path.join(folder, n), "rb").read()).hexdigest(): bad += 1
    print("files: %d  uploaded: %d  already there: %d  failed: %d  read-back mismatches: %d" % (len(names), up, skip, fail, bad))
    return 0 if not (fail or bad) else 1


if __name__ == "__main__":
    a = sys.argv[1:]
    cmds = {"import-sqlite": cmd_import, "verify": cmd_verify, "backup": cmd_backup, "restore-csv": cmd_restore, "upload-screenshots": cmd_upload}
    if a and a[0] == "check": sys.exit(1 if cmd_check() else 0)
    if len(a) != 2 or a[0] not in cmds: print(__doc__); sys.exit(2)
    sys.exit(cmds[a[0]](a[1]) or 0)
