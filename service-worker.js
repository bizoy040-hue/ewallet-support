/* E-Wallet Support — Service Worker
 * নিরাপত্তা নীতি: এই Service Worker কখনোই কোনো ডাইনামিক/ব্যক্তিগত রেসপন্স (HTML পেজ, API, লগইন সেশন,
 * ব্যালেন্স, লেনদেন, স্ক্রিনশট ইত্যাদি) ক্যাশ করে না। শুধু নিচের PRECACHE তালিকার স্ট্যাটিক ফাইল (অফলাইন পেজ ও
 * আইকন) ক্যাশ হয়। সব পেজ ও অনুরোধ সবসময় সরাসরি নেটওয়ার্ক/সার্ভার থেকে আসে।
 */
var CACHE = 'ewallet-support-static-v1';
var OFFLINE = '/static/offline.html';
var PRECACHE = [
  OFFLINE,
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];

self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(CACHE).then(function (c) { return c.addAll(PRECACHE); }).then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.filter(function (k) {
        return k.indexOf('ewallet-support-') === 0 && k !== CACHE;
      }).map(function (k) { return caches.delete(k); }));
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function (event) {
  var req = event.request;
  if (req.method !== 'GET') return;                       // POST/ফর্ম/ডিপোজিট/উইথড্র — সম্পূর্ণ অপরিবর্তিত
  var url = new URL(req.url);
  if (url.origin !== self.location.origin) return;       // অন্য ডোমেইন (ফন্ট, Supabase ইত্যাদি) — অপরিবর্তিত

  if (req.mode === 'navigate') {
    // পেজ সবসময় নেটওয়ার্ক থেকে; শুধু ইন্টারনেট না থাকলে স্ট্যাটিক অফলাইন পেজ (কোনো ব্যক্তিগত ডেটা নেই)
    event.respondWith(
      fetch(req).catch(function () { return caches.match(OFFLINE); })
    );
    return;
  }

  if (PRECACHE.indexOf(url.pathname) !== -1) {            // কেবল পূর্ব-নির্ধারিত স্ট্যাটিক ফাইল
    event.respondWith(
      caches.match(req).then(function (hit) { return hit || fetch(req); })
    );
  }
  // বাকি সব (API, /api/notif, স্ক্রিনশট, ডাউনলোড ইত্যাদি): respondWith নেই => ব্রাউজারের স্বাভাবিক নেটওয়ার্ক আচরণ, কোনো ক্যাশ নেই
});
