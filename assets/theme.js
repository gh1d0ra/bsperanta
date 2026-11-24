// Follow the device's light/dark setting. Loaded in <head> so the page never flashes the wrong theme.
(function () {
  var mq = window.matchMedia("(prefers-color-scheme: dark)");
  function apply() {
    document.documentElement.setAttribute("data-bs-theme", mq.matches ? "dark" : "light");
  }
  apply();
  if (mq.addEventListener) mq.addEventListener("change", apply);
})();
