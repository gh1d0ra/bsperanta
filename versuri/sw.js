// Keeps /versuri/ usable without internet: the page and its CSS/JS libraries are
// fetched from the network when online (so updates show up right away) and served
// from this cache when offline. Song data is cached by the page itself
// (localStorage), so /api/ requests are left alone here.
const CACHE = "versuri-v1";
const CDN_HOSTS = ["cdn.jsdelivr.net", "ajax.googleapis.com"];

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  const isPage = req.mode === "navigate" && url.origin === location.origin && url.pathname.startsWith("/versuri/");
  const isLib = CDN_HOSTS.includes(url.hostname) || (url.origin === location.origin && url.pathname.startsWith("/assets/"));
  if (!isPage && !isLib) return;

  // Pages are stored under their path only, so /versuri/?song=7 and /versuri/ share one copy.
  const cacheKey = isPage ? url.origin + url.pathname : req;
  event.respondWith(
    fetch(req)
      .then((res) => {
        if (res.ok || res.type === "opaque") {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(cacheKey, copy));
        }
        return res;
      })
      .catch(() => caches.match(cacheKey).then((hit) => hit || Response.error()))
  );
});
