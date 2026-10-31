"""Phase 1 tests (SQLite). Language bn/en, Telegram support, Terms editor, permissions, migration compat.
Run: python tests/test_phase1.py   (never touches production; uses a temp database)"""
import os, sys, io, re, json, shutil, sqlite3, tempfile
d = tempfile.mkdtemp()
os.environ.update(DATABASE_PATH=d + "/t.db", UPLOAD_DIR=d + "/up", ADMIN_PHONE="01900000000", ADMIN_PASSWORD="AdminPass1", SECRET_KEY="k" * 32)
os.environ.pop("DATABASE_URL", None)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as A
N = [0]
def ok(name, cond):
    print(("PASS " if cond else "FAIL ") + name); N[0] += bool(cond)
    if not cond: sys.exit(1)
def tok(c):
    c.get("/login")
    with c.session_transaction() as s: return s["csrf"]
def post(c, url, data=None, **kw):
    data = dict(data or {}); data["_csrf"] = tok(c); return c.post(url, data=data, **kw)
def client(phone, pw, name="U"):
    c = A.app.test_client(); post(c, "/signup", {"name": name, "phone": phone, "pw": pw}); post(c, "/login", {"phone": phone, "pw": pw}); return c
def dbq(sql, a=()): return sqlite3.connect(d + "/t.db").execute(sql, a).fetchall()
BN_HOME, EN_HOME = "উপলব্ধ ব্যালেন্স", "Available balance"

adm = A.app.test_client(); post(adm, "/login", {"phone": "01900000000", "pw": "AdminPass1"})
u = client("01711111111", "secret1")

# ---- language
h = u.get("/").data.decode()
ok("default language is Bangla", BN_HOME in h and 'lang="bn"' in h and "Available balance" not in h)
r = u.get("/lang/en?next=/")
ok("switch to English redirects back", r.status_code == 302 and r.location.endswith("/"))
h = u.get("/").data.decode()
ok("English dashboard labels + html lang", EN_HOME in h and 'lang="en"' in h and BN_HOME not in h and "Total commission" in h and "Pending withdrawals" in h)
ok("nav + statuses translated", all(x in h for x in ("Home", "History", "Requests", "Insights", "Account")))
ok("preference stored per user in DB", dbq("select v from settings where k like 'ulang:%'")[0][0] == "en")
u2 = A.app.test_client(); post(u2, "/login", {"phone": "01711111111", "pw": "secret1"})
ok("preference remembered on a fresh browser after login", EN_HOME in u2.get("/").data.decode())
u2.get("/lang/bn")
ok("switch back to Bangla (and stored)", BN_HOME in u2.get("/").data.decode() and dbq("select v from settings where k like 'ulang:%'")[0][0] == "bn")
ok("invalid language code -> 404", u.get("/lang/xx").status_code == 404)
bad = [u.get("/lang/en?next=" + n).location for n in ("//evil.com", "https://evil.com", "/\\evil.com")]
ok("open-redirect blocked (next must be a local path)", all(x.endswith("/") and "evil" not in x for x in bad))
anon = A.app.test_client(); anon.get("/lang/en")
ok("anonymous visitor: cookie keeps English on login page", "Sign in" in anon.get("/login").data.decode())
ok("Bangla digits become 0-9 in English mode", "০" not in anon.get("/signup").data.decode())
u.get("/lang/en")
pages = ["/", "/history", "/referral", "/insight", "/account", "/account/settings", "/notifications", "/support", "/deposit", "/withdraw", "/payment-numbers", "/requests", "/about", "/feedback"]
ok("all client pages render 200 in English", all(u.get(p).status_code == 200 for p in pages))
u.get("/lang/bn")
ok("all client pages render 200 in Bangla", all(u.get(p).status_code == 200 for p in pages))
adm.get("/lang/en")
ap = ["/admin", "/admin/users", "/admin/deposits", "/admin/withdrawals", "/admin/requests", "/admin/referrals", "/admin/commission", "/admin/staff", "/admin/tickets", "/admin/notices", "/admin/settings", "/admin/audit", "/admin/profile", "/admin/payment-numbers", "/admin/alerts", "/admin/content"]
ok("all admin pages render 200 in English", all(adm.get(p).status_code == 200 for p in ap))
ok("admin tabs translated", "Dashboard" in adm.get("/admin").data.decode())
adm.get("/lang/bn")
ok("all admin pages render 200 in Bangla", all(adm.get(p).status_code == 200 for p in ap))

# ---- Terms editor
ok("About default shows built-in Bangla terms", "কোনো আয়ের নিশ্চয়তা" in u.get("/about").data.decode())
u.get("/lang/en")
ok("About default has English terms", "does not guarantee any income" in u.get("/about").data.decode())
u.get("/lang/bn")
ok("admin content page opens (Bangla)", "শর্তাবলি ও তথ্য" in adm.get("/admin/content").data.decode())
form = {"title_bn": "নতুন শিরোনাম", "title_en": "New Title", "ins_bn": "বাংলা নির্দেশনা", "ins_en": "English instruction <b>x</b>",
        "disc_bn": "বাংলা ডিসক্লেইমার", "disc_en": "English disclaimer", "pbn": ["পয়েন্ট ১", "পয়েন্ট ২", "মুছবো", ""], "pen": ["Point one", "Point two", "Delete me", ""], "pdel": ["2"]}
r = post(adm, "/admin/content/terms", form)
ok("terms saved", r.status_code == 302)
h = u.get("/about").data.decode()
ok("client sees Bangla edit immediately", "নতুন শিরোনাম" in h and "পয়েন্ট ১" in h and "বাংলা নির্দেশনা" in h and "মুছবো" not in h and "বাংলা ডিসক্লেইমার" in h)
u.get("/lang/en"); h = u.get("/about").data.decode()
ok("client sees English edit separately", "New Title" in h and "Point two" in h and "Delete me" not in h and "English disclaimer" in h)
ok("HTML in content is escaped (no injection)", "<b>x</b>" not in h and "&lt;b&gt;x&lt;/b&gt;" in h)
cur = json.loads(dbq("select v from settings where k='terms_json'")[0][0])
ok("points deleted/added correctly (2 left)", len(cur["points"]) == 2)
form2 = dict(form, pbn=["পয়েন্ট ১", "পয়েন্ট ২", "পয়েন্ট ৩ নতুন"], pen=["Point one", "Point two", "Point three new"], pdel=[])
post(adm, "/admin/content/terms", form2)
ok("add a new point", len(json.loads(dbq("select v from settings where k='terms_json'")[0][0])["points"]) == 3 and "Point three new" in u.get("/about").data.decode())
post(adm, "/admin/content/terms", dict(form2, title_en="", ins_en="", disc_en="", pen=["", "", ""], pbn=["ক", "খ", "গ"]))
u.get("/lang/en"); h = u.get("/about").data.decode()
ok("English empty -> falls back to Bangla (never blank page)", "নতুন শিরোনাম" in h)
r = post(adm, "/admin/content/terms", dict(form2, title_bn=""))
ok("empty Bangla title rejected", r.status_code == 302 and "নতুন শিরোনাম" in json.dumps(json.loads(dbq("select v from settings where k='terms_json'")[0][0]), ensure_ascii=False))
post(adm, "/admin/content/terms", dict(form2, pbn=["x" * 600] * 3, pen=["y"] * 3))
ok("point length capped at 500", all(len(p["bn"]) <= 500 for p in json.loads(dbq("select v from settings where k='terms_json'")[0][0])["points"]))
ok("audit log records terms edits", dbq("select count(*) from audit where action='terms_edit'")[0][0] >= 4)

# ---- Telegram
u.get("/lang/bn")
ok("no Telegram button when nothing configured (URL not hardcoded)", "t.me" not in u.get("/support").data.decode() and "telegram" not in u.get("/support").data.decode().lower().replace("টেলিগ্রামে", ""))
for bad_url in ("javascript:alert(1)", "http://t.me/x", "https://evil.com/x", "https://t.me.evil.com/x"):
    post(adm, "/admin/content/telegram", {"enabled": "1", "url": bad_url})
ok("unsafe/non-Telegram URLs rejected", dbq("select v from settings where k='telegram_url'")[0][0] == "")
post(adm, "/admin/content/telegram", {"enabled": "1", "url": "https://t.me/MySupportBD", "username": "MySupportBD", "label_bn": "আমাদের টেলিগ্রাম", "label_en": "Our Telegram"})
h = u.get("/support").data.decode()
ok("Bangla Telegram button + custom label on support page", 'href="https://t.me/MySupportBD"' in h and "আমাদের টেলিগ্রাম" in h)
ok("floating message icon links to Telegram", re.search(r'class="fab" href="https://t.me/MySupportBD"', u.get("/").data.decode()) is not None)
u.get("/lang/en"); h = u.get("/support").data.decode()
ok("English label shown in English mode", "Our Telegram" in h and "আমাদের টেলিগ্রাম" not in h)
post(adm, "/admin/content/telegram", {"enabled": "1", "url": "", "username": "@OnlyName"})
ok("username-only builds https://t.me/<name>", 'href="https://t.me/OnlyName"' in u.get("/support").data.decode())
post(adm, "/admin/content/telegram", {"url": "https://t.me/MySupportBD"})
ok("disabled -> button hidden everywhere", "t.me" not in u.get("/support").data.decode() and 'class="fab" href="/support"' in u.get("/").data.decode())
post(adm, "/admin/content/telegram", {"enabled": "1", "username": "ab"})
ok("bad username rejected", dbq("select v from settings where k='tg_username'")[0][0] == "")
ok("audit log records telegram edits", dbq("select count(*) from audit where action='telegram_settings'")[0][0] >= 3)

# ---- permissions
ok("regular user cannot open admin content", u.get("/admin/content").status_code == 403)
ok("regular user cannot POST terms/telegram", post(u, "/admin/content/terms", form).status_code == 403 and post(u, "/admin/content/telegram", {"enabled": "1", "url": "https://t.me/x"}).status_code == 403)
ok("anonymous redirected to login", A.app.test_client().get("/admin/content").status_code == 302)
ok("missing CSRF rejected", adm.post("/admin/content/terms", data=form).status_code == 400)
post(adm, "/admin/staff/new", {"name": "Fin", "phone": "01822222222", "pw": "FinPass123", "role": "finance"})
fin = A.app.test_client(); post(fin, "/login", {"phone": "01822222222", "pw": "FinPass123"})
ok("finance staff (no notices permission) gets 403", fin.get("/admin/content").status_code == 403)
post(adm, "/admin/staff/new", {"name": "Adm", "phone": "01833333333", "pw": "AdmPass123", "role": "admin", "perm_notices": "1"})
ad = A.app.test_client(); post(ad, "/login", {"phone": "01833333333", "pw": "AdmPass123"})
ok("admin with notices permission can edit terms", post(ad, "/admin/content/terms", form).status_code == 302 and ad.get("/admin/content").status_code == 200)
ok("...but cannot see/save Telegram settings (super admin only)", "/admin/content/telegram" not in ad.get("/admin/content").data.decode() and post(ad, "/admin/content/telegram", {"enabled": "1", "url": "https://t.me/zzz"}).status_code == 403)

# ---- migration compatibility: old DB without the new keys keeps its existing Telegram URL
c = sqlite3.connect(d + "/t.db"); c.execute("DELETE FROM settings WHERE k IN ('tg_enabled','tg_username','tg_label_bn','tg_label_en','terms_json')")
c.execute("INSERT OR REPLACE INTO settings VALUES('telegram_url','https://t.me/OldSupport')"); c.commit(); c.close()
before = dbq("select count(*), round(sum(balance),2) from users")[0]
A.migrate(); A.migrate()
ok("migrate() twice is idempotent; users/balances unchanged", dbq("select count(*), round(sum(balance),2) from users")[0] == before)
ok("new defaults seeded (enabled by default so an existing Telegram URL keeps working)", dbq("select v from settings where k='tg_enabled'")[0][0] == "1")
u.get("/lang/bn"); ok("existing telegram_url from old version still shown", 'href="https://t.me/OldSupport"' in u.get("/support").data.decode())
ok("About falls back to built-in default when terms_json absent", "কোনো আয়ের নিশ্চয়তা" in u.get("/about").data.decode())
ok("ledger still reconciles", A.app.test_request_context() is not None and not [1 for r in dbq("select u.id from users u left join ledger l on l.user_id=u.id group by u.id having abs(u.balance-coalesce(sum(l.amount),0))>0.005")])
shutil.rmtree(d); print("PHASE 1 TESTS PASSED:", N[0])
