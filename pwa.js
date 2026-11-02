/* E-Wallet Support — PWA: Service Worker রেজিস্ট্রেশন + "Download App" বাটন */
(function () {
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function () {
      navigator.serviceWorker.register('/service-worker.js', { scope: '/' }).catch(function () {});
    });
  }
  var btn = document.getElementById('pwa-install');
  if (!btn) return;
  var standalone = (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) || window.navigator.standalone === true;
  if (standalone) return;                                   // অ্যাপ হিসেবে খোলা থাকলে বাটন দেখানো হবে না
  var deferred = null;
  btn.hidden = false;
  window.addEventListener('beforeinstallprompt', function (e) { e.preventDefault(); deferred = e; btn.hidden = false; });
  window.addEventListener('appinstalled', function () { deferred = null; btn.hidden = true; });
  btn.addEventListener('click', function () {
    if (deferred) {
      var p = deferred; deferred = null;
      p.prompt();
      if (p.userChoice && p.userChoice.catch) p.userChoice.catch(function () {});
      return;
    }
    var en = (document.documentElement.lang || '').indexOf('en') === 0;
    alert(en
      ? 'To install: open the Chrome menu (⋮) and tap "Install app" or "Add to Home screen".'
      : 'ইনস্টল করতে: Chrome মেনু (⋮) খুলে "Install app" বা "Add to Home screen" চাপুন।');
  });
})();
