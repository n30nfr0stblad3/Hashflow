/* Hashflow Fleet Command — offline app shell.
   Cache-first for static assets, network-first for the API, so the
   dashboard keeps working on tablets/phones with poor connectivity. */
var CACHE = "hf-fleet-v2";
var SHELL = [
  "./",
  "./index.html",
  "./css/app.css",
  "./js/charts.js",
  "./js/state.js",
  "./js/ui.js",
  "./js/copilot.js",
  "./js/views.js",
  "./js/app.js",
  "./manifest.webmanifest",
  "./icons/icon-512.png"
];

self.addEventListener("install", function (ev) {
  ev.waitUntil(
    caches.open(CACHE).then(function (cache) {
      return cache.addAll(SHELL);
    }).then(function () {
      return self.skipWaiting();
    })
  );
});

self.addEventListener("activate", function (ev) {
  ev.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.map(function (key) {
        if (key !== CACHE) return caches.delete(key);
      }));
    }).then(function () {
      return self.clients.claim();
    })
  );
});

self.addEventListener("fetch", function (ev) {
  var url = new URL(ev.request.url);
  if (url.pathname.indexOf("/api/") === 0) {
    // Network-first for live data; fall back to cache for offline reads.
    ev.respondWith(
      fetch(ev.request).catch(function () {
        return caches.match(ev.request);
      })
    );
    return;
  }
  // Cache-first for the app shell.
  ev.respondWith(
    caches.match(ev.request).then(function (cached) {
      return cached || fetch(ev.request).then(function (resp) {
        if (resp.ok && url.origin === location.origin) {
          var copy = resp.clone();
          caches.open(CACHE).then(function (cache) {
            cache.put(ev.request, copy);
          });
        }
        return resp;
      });
    })
  );
});
