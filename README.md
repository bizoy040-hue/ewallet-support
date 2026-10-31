# E-Wallet Support v5 — Supabase (PostgreSQL + Storage) মাইগ্রেশন গাইড

## v5-এ কী নতুন (v4-এর কোনো ফিচার বাদ যায়নি)
- **ডুয়াল-মোড ডাটাবেস:** `DATABASE_URL` সেট না থাকলে আগের মতোই SQLite। সেট থাকলে PostgreSQL (Supabase)। একই `app.py`।
- **স্ক্রিনশট:** `SUPABASE_URL` + `SUPABASE_SERVICE_KEY` সেট থাকলে Supabase Storage (private bucket), না থাকলে আগের লোকাল ফোল্ডার। ছবি সবসময় অ্যাপের মাধ্যমে (লগইন + অনুমতি যাচাই করে) দেখানো হয়, সরাসরি পাবলিক লিংক নেই।
- **স্ক্রিনশট অপ্টিমাইজ:** আপলোডের সময় ছবি যাচাই (পড়া না গেলে বাতিল), বড় হলে ১৬০০px-এ ছোট, WebP, EXIF (লোকেশন ইত্যাদি) মোছা। সাধারণত ফাইল অনেক ছোট হয়। (ছোট করার পরও বড় থাকলে আসল ফাইলই রাখা হয়।)
- **স্ক্রিনশট ZIP ব্যাকআপ:** সেটিংস → নিরাপত্তা → "স্ক্রিনশট ZIP নামান" (শুধু সুপার অ্যাডমিন)। ZIP-এ `manifest.csv` (SHA-256, কোন লেনদেনের ছবি)।
- **ডাটাবেস ব্যাকআপ বাটন:** SQLite মোডে `.db` ফাইল, PostgreSQL মোডে প্রতিটি টেবিলের CSV + `manifest.json` সহ ZIP।
- **টাকার নিরাপত্তা একই:** অপরিবর্তনীয় লেজার (PostgreSQL-এ ট্রিগার, `TRUNCATE`-ও বন্ধ), ডুপ্লিকেট TrxID/অ্যাপ্রুভ প্রতিরোধ, আইডেম্পোটেন্ট এন্ট্রি। SQLite-এর `BEGIN IMMEDIATE`-এর বদলে PostgreSQL-এ একই কাজের জন্য একটি গ্লোবাল অ্যাডভাইজরি লক (একসাথে একটাই লেখার ব্লক) ব্যবহার হয়, তাই লজিক বদলাইনি।
- ছোট বাগ-ফিক্স: ডুপ্লিকেট TrxID-তে রিজেক্ট হলে এইমাত্র আপলোড হওয়া ছবি আর পড়ে থাকে না (ফ্রি ১GB স্টোরেজ বাঁচাতে)।
- `/healthz` এখন ডাটাবেসে `SELECT 1` চালায় (ডাটাবেস না পেলে 503)।

## Environment ভেরিয়েবল
| নাম | কাজ |
|---|---|
| SECRET_KEY, ADMIN_PHONE, ADMIN_PASSWORD | আগের মতোই (বাধ্যতামূলক) |
| DATABASE_PATH, UPLOAD_DIR | SQLite/লোকাল মোডে আগের মতো |
| **DATABASE_URL** | `postgresql://...` — সেট করলেই PostgreSQL মোড |
| **SUPABASE_URL** | `https://<project-ref>.supabase.co` |
| **SUPABASE_SERVICE_KEY** | service_role key — **গোপন**, শুধু Render env-এ রাখুন |
| **SUPABASE_BUCKET** | bucket নাম (ডিফল্ট `screenshots`), অবশ্যই **Private** |

## মাইগ্রেশন — ধাপে ধাপে (প্রোডাকশন ডাটাবেস আগে ছোঁবেন না)
1. **ব্যাকআপ আগে:** চালু সাইটে অ্যাডমিন → সেটিংস → নিরাপত্তা → "ডাটাবেস ব্যাকআপ" ও "স্ক্রিনশট ZIP" দুটোই নামান, ফোন/ড্রাইভে রাখুন। (Render ফ্রিতে ফাইল ডিপ্লয়ে মুছে যায়, তাই ব্যাকআপই আপনার নিরাপত্তা।)
2. **Supabase:** নতুন প্রজেক্ট → Database পাসওয়ার্ড সেট করুন → Connect থেকে **Session pooler** স্ট্রিং নিন (পোর্ট 5432, IPv4 সাপোর্ট; Render-এ সরাসরি `db.<ref>.supabase.co` লাগে IPv6, তাই pooler দরকার)। Storage → New bucket → নাম `screenshots`, **Private**। Project Settings → API থেকে URL ও service_role key।
3. **কপি দিয়ে রিহার্সাল** (কম্পিউটার বা Termux; `pip install -r requirements.txt`):
   ```
   export DATABASE_URL='postgresql://postgres.<ref>:<পাসওয়ার্ড>@<pooler-host>:5432/postgres'
   python tools/dbtool.py import-sqlite ewallet-backup.db    # শুধু খালি PostgreSQL-এ; সোর্স ফাইল ReadOnly
   python tools/dbtool.py verify ewallet-backup.db           # প্রতি টেবিলের সংখ্যা + চেকসাম + ব্যালেন্স যোগফল
   ```
   `RESULT: ALL MATCH` না এলে থামুন, কিছু চালু করবেন না। (সোর্স v4 স্কিমার না হলে টুল আগেই জানাবে।)
4. **স্ক্রিনশট আপলোড** (আসল ফাইলের নাম একই থাকে, কিছু বদলায় না):
   ```
   export SUPABASE_URL=... SUPABASE_SERVICE_KEY=... SUPABASE_BUCKET=screenshots
   python tools/dbtool.py upload-screenshots <ZIP-খুলে-পাওয়া-screenshots-ফোল্ডার>
   ```
   শেষে "read-back mismatches: 0" দেখুন (প্রতিটি ফাইল ফেরত পড়ে SHA-256 মেলানো হয়)।
5. **Render-এ সুইচ:** GitHub-এ `app.py`, `requirements.txt`, `tools/` আপলোড → Environment-এ উপরের নতুন ভেরিয়েবলগুলো যোগ → Start Command: `gunicorn app:app --timeout 120` (ZIP ব্যাকআপে সময় লাগতে পারে)। চালুর পর `/healthz`, অ্যাডমিন লগইন, একটি ক্লায়েন্ট লগইন ও ব্যালেন্স মিলিয়ে দেখুন; `python tools/dbtool.py check` → `mismatching users: 0`।
6. **রোলব্যাক:** Render থেকে `DATABASE_URL` ও `SUPABASE_*` মুছলে অ্যাপ আবার SQLite মোডে ফেরে। কিন্তু ফ্রি Render-এ SQLite ফাইল ডিপ্লয়ে মুছে যায়, তাই ফেরার পর ধাপ ১-এর ব্যাকআপ `.db` রিস্টোর করতে হবে। এজন্য সুইচের আগে ব্যাকআপ ও কয়েকদিন পুরনো সেটআপ হাতে রাখুন।

## নিয়মিত কাজ (ফ্রি প্ল্যানের সীমা)
- Supabase ফ্রিতে **স্বয়ংক্রিয় ব্যাকআপ নেই** → সপ্তাহে অন্তত একবার "ডাটাবেস ব্যাকআপ" + "স্ক্রিনশট ZIP" নামান (বা `python tools/dbtool.py backup out.zip`)। রিস্টোর: `python tools/dbtool.py restore-csv out.zip` (শুধু খালি ডাটাবেসে)।
- ১ সপ্তাহ অ্যাক্টিভিটি না থাকলে Supabase ফ্রি প্রজেক্ট **পজ** করে। কোনো আপটাইম-পিংগার দিয়ে প্রতি ১০–১৪ মিনিটে `/healthz` ডাকুন (এটি Render-কেও জাগিয়ে রাখে ও ডাটাবেসে কুয়েরি চালায়)। এতে পজ ঠেকানো যায়, এটা Supabase গ্যারান্টি দেয় না — ব্যাকআপ ছাড়া নির্ভর করবেন না।
- সীমা: ডাটাবেস ৫০০MB, স্টোরেজ ১GB, ডাউনলোড (egress) মাসে ৫GB। অপ্টিমাইজড ছবি সাধারণত ছোট হয়, তবু মাঝে মাঝে ব্যবহার দেখুন।
- `python tools/dbtool.py check` যেকোনো সময় লেজার = ব্যালেন্স যাচাই করে।

## যা পরীক্ষিত আর যা নয়
দেখুন `TEST_RESULTS.md`। সংক্ষেপে: PostgreSQL পরীক্ষা আসল PostgreSQL 16 সার্ভারে, কিন্তু আসল `psycopg` প্যাকেজ ইনস্টল করা যায়নি (বিল্ড পরিবেশে PyPI বন্ধ ছিল), তাই একটি টেস্ট-অনলি libpq শিম ব্যবহার হয়েছে। Supabase Storage পরীক্ষা মক সার্ভারে। **আসল Supabase প্রজেক্টে একবারও চালানো হয়নি** — ধাপ ৩–৫-এর রিহার্সালই সেই যাচাই।
