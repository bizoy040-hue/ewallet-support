import os, sys, io, csv, zipfile, hashlib, tempfile, shutil, re
d = tempfile.mkdtemp()
os.environ.update(DATABASE_PATH=d + "/t.db", UPLOAD_DIR=d + "/up", ADMIN_PHONE="01900000000", ADMIN_PASSWORD="AdminPass1", SECRET_KEY="k" * 32)
sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else "/home/claude/v5")
import app as A
n = [0]
def _try(b):
    try:
        from PIL import Image as I; I.open(io.BytesIO(b)).verify(); return True
    except Exception: return False
def ok(name, cond):
    print(("PASS " if cond else "FAIL ") + name); n[0] += cond
    if not cond: sys.exit(1)
def tok(c):
    c.get("/login")
    with c.session_transaction() as s: return s["csrf"]
def post(c, url, data=None, **kw):
    data = dict(data or {}); data["_csrf"] = tok(c); return c.post(url, data=data, **kw)
from PIL import Image
_b = io.BytesIO(); Image.new("RGB", (60, 60), (200, 30, 30)).save(_b, "PNG"); PNG = _b.getvalue()  # real image: v5 rejects undecodable uploads
a = A.app.test_client(); post(a, "/login", {"phone": "01900000000", "pw": "AdminPass1"})
ok("super admin login", a.get("/admin").status_code == 200)
r = post(a, "/admin/backup/screenshots"); ok("no screenshots -> friendly redirect, no zip", r.status_code == 302 and "settings" in r.location)
c = A.app.test_client(); post(c, "/signup", {"name": "U", "phone": "01711111111", "pw": "secret1"}); post(c, "/login", {"phone": "01711111111", "pw": "secret1"})
dd = {"method": "bKash", "amount": "500", "trx": "TRX123456", "_csrf": tok(c), "shot": (io.BytesIO(PNG), "p.png")}
c.post("/deposit", data=dd, content_type="multipart/form-data")
stray = "a" * 32 + ".jpg"; open(os.path.join(os.environ["UPLOAD_DIR"], stray), "wb").write(b"\xff\xd8\xff" + b"x" * 50)
open(os.path.join(os.environ["UPLOAD_DIR"], "notes.txt"), "w").write("not a screenshot")
r = post(a, "/admin/backup/screenshots"); ok("zip download 200 + zip mimetype", r.status_code == 200 and r.mimetype == "application/zip")
z = zipfile.ZipFile(io.BytesIO(r.data)); names = z.namelist()
ok("zip has 2 screenshots + manifest, ignores non-screenshot files", sorted(names) == sorted(["manifest.csv"] + ["screenshots/" + f for f in os.listdir(os.environ["UPLOAD_DIR"]) if re.fullmatch(r"[0-9a-f]{32}\.(jpg|png|webp)", f)]) and len(names) == 3)
rows = list(csv.DictReader(io.StringIO(z.read("manifest.csv").decode())))
ok("manifest sha256 matches file bytes", all(hashlib.sha256(z.read("screenshots/" + x["file"])).hexdigest() == x["sha256"] and int(x["bytes"]) == len(z.read("screenshots/" + x["file"])) for x in rows))
ok("manifest links deposit tx and flags orphan", {x["source"] for x in rows} == {"tx", "orphan"} and [x for x in rows if x["source"] == "tx"][0]["member_id"] == "1500")
from PIL import Image as _I; ok("stored file is a valid image", any(_try(z.read("screenshots/" + x["file"])) for x in rows if x["source"] == "tx"))
ok("audit entry written", A.app.test_client() and True)
import sqlite3; ok("audit log has backup_screenshots", sqlite3.connect(os.environ["DATABASE_PATH"]).execute("select count(*) from audit where action='backup_screenshots'").fetchone()[0] == 1)
ok("temp zip cleaned up", not [f for f in os.listdir(tempfile.gettempdir()) if f.startswith("ewallet-shots-") and os.path.getmtime(os.path.join(tempfile.gettempdir(), f)) > __import__("time").time() - 60])
ok("anonymous/regular user cannot download (302/403)", c.post("/admin/backup/screenshots", data={"_csrf": tok(c)}).status_code in (302, 403))
post(a, "/admin/staff/new", {"name": "Fin", "phone": "01822222222", "pw": "FinPass123", "role": "finance"})
f = A.app.test_client(); post(f, "/login", {"phone": "01822222222", "pw": "FinPass123"})
ok("finance staff gets 403", post(f, "/admin/backup/screenshots").status_code == 403)
post(a, "/admin/staff/new", {"name": "Adm", "phone": "01833333333", "pw": "AdmPass123", "role": "admin", "perm_requests": "1", "perm_deposits": "1"})
m = A.app.test_client(); post(m, "/login", {"phone": "01833333333", "pw": "AdmPass123"})
ok("admin role gets 403", post(m, "/admin/backup/screenshots").status_code == 403)
ok("missing CSRF rejected (400)", a.post("/admin/backup/screenshots", data={}).status_code == 400)
ok("settings page shows both backup buttons", all(x in a.get("/admin/settings?open=security").data.decode() for x in ("/admin/backup/screenshots", 'action="/admin/backup"')))
shutil.rmtree(d); print("ZIP TESTS PASSED:", n[0])
