# E-Wallet সাপোর্ট: চালানোর নিয়ম

## লোকাল পিসিতে চালান
```
pip install -r requirements.txt
set ADMIN_PHONE=01XXXXXXXXX        (Linux/Mac: export)
set ADMIN_PASSWORD=আপনার-শক্ত-পাসওয়ার্ড
set SECRET_KEY=যেকোনো-লম্বা-র‍্যান্ডম-লেখা
python app.py
```
ব্রাউজারে http://localhost:5000 খুলুন। অ্যাডমিন হিসেবে ওই নম্বর ও পাসওয়ার্ড দিয়ে সাইন ইন করুন, উপরে "অ্যাডমিন" লিংক পাবেন।

## অনলাইনে হোস্ট (Render.com, সহজ)
1. ফাইলগুলো GitHub রিপোতে আপলোড করুন।
2. Render → New → Web Service → রিপো সিলেক্ট।
3. Build Command: `pip install -r requirements.txt`
4. Start Command: `gunicorn app:app`
5. Environment-এ `ADMIN_PHONE`, `ADMIN_PASSWORD`, `SECRET_KEY` সেট করুন।
6. SQLite ডাটা যেন মুছে না যায়, তাই Persistent Disk যোগ করুন (অথবা পরে PostgreSQL)।
7. ডোমেইন কিনে Settings → Custom Domain-এ যুক্ত করুন।

## অ্যাডমিন প্যানেলে যা করা যায়
- bKash/Nagad নম্বর সেট (ডিপোজিট পেজে ইউজার এটাই দেখবে)
- ডিপোজিট/উইথড্র রিকোয়েস্ট অ্যাপ্রুভ বা রিজেক্ট (TrxID মিলিয়ে)
- সত্যিকারের কাজ সম্পন্ন হলে ইউজারকে কমিশন দেওয়া (নোটসহ)
- ইউজার ব্লক/আনব্লক, ন্যূনতম উইথড্র সেট

## চালুর আগে অবশ্যই
- ডিফল্ট পাসওয়ার্ড `admin123` কখনোই রাখবেন না।
- HTTPS চালু রাখুন (Render এটা নিজেই দেয়)।
- ইউজারের টাকা নেওয়ার আগে ব্যবসার বৈধতা/লাইসেন্স বিষয়ে আইনজীবীর পরামর্শ নিন।
