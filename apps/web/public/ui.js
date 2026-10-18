// The only script of the UI: turns the session expiry time into a countdown. Without it the page shows the absolute time.
// No network, no storage, no eval, no inline handlers.
(function () {
  var el = document.querySelector("time[data-countdown]");
  if (!el) return;
  var end = Date.parse(el.getAttribute("data-countdown") || "");
  if (isNaN(end)) return;
  var abs = el.textContent;
  function tick() {
    var s = Math.max(0, Math.floor((end - Date.now()) / 1000));
    if (s === 0) { el.textContent = "expired"; return; }
    var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), r = s % 60;
    el.textContent = (h ? h + "h " : "") + (m < 10 && h ? "0" : "") + m + "m " + (r < 10 ? "0" : "") + r + "s";
    el.title = abs;
    setTimeout(tick, 1000);
  }
  tick();
})();
