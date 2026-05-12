/* Claude Design — shared theme + language switcher.
 *
 * Reads/writes localStorage so user choice persists across pages.
 * Injects a floating control pill in the top-right corner with:
 *   • Theme   : Light / Dark
 *   • Language: 中文 / EN
 *
 * Pages opt out of the pill by adding data-no-top-controls to <html>
 * (e.g. for full-bleed call screen). Theme + lang still apply.
 */

(function () {
  var THEME_KEY = "cx.design.theme";
  var LANG_KEY  = "cx.design.lang";

  var html = document.documentElement;

  function readTheme() {
    var t = localStorage.getItem(THEME_KEY);
    if (t === "light" || t === "dark") return t;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark" : "light";
  }
  function readLang() {
    var l = localStorage.getItem(LANG_KEY);
    if (l === "zh" || l === "en") return l;
    var nav = (navigator.language || "zh").toLowerCase();
    return nav.indexOf("zh") === 0 ? "zh" : "en";
  }
  function applyTheme(t) {
    html.setAttribute("data-theme", t);
    localStorage.setItem(THEME_KEY, t);
    var els = document.querySelectorAll("[data-theme-btn], [data-theme-set]");
    els.forEach(function (b) {
      var value = b.getAttribute("data-theme-btn") || b.getAttribute("data-theme-set");
      b.classList.toggle("active", value === t);
    });
  }
  function applyLang(l) {
    html.setAttribute("data-lang", l);
    html.setAttribute("lang", l === "zh" ? "zh-CN" : "en");
    localStorage.setItem(LANG_KEY, l);
    var els = document.querySelectorAll("[data-lang-btn]");
    els.forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-lang-btn") === l);
    });
  }

  function injectControls() {
    if (html.hasAttribute("data-no-top-controls")) return;
    if (document.querySelector(".top-controls")) return;
    var bar = document.createElement("div");
    bar.className = "top-controls";
    bar.setAttribute("aria-label", "Theme and language");
    bar.innerHTML =
      '<div class="seg" role="group" aria-label="Language">' +
      '  <button data-lang-btn="zh" title="中文">中</button>' +
      '  <button data-lang-btn="en" title="English">EN</button>' +
      '</div>' +
      '<div class="seg" role="group" aria-label="Theme">' +
      '  <button data-theme-btn="light" title="Light">☀</button>' +
      '  <button data-theme-btn="dark"  title="Dark">☾</button>' +
      '</div>';
    document.body.appendChild(bar);

    bar.addEventListener("click", function (e) {
      var t = e.target;
      if (t.hasAttribute && t.hasAttribute("data-theme-btn")) {
        applyTheme(t.getAttribute("data-theme-btn"));
      } else if (t.hasAttribute && t.hasAttribute("data-lang-btn")) {
        applyLang(t.getAttribute("data-lang-btn"));
      }
    });
  }

  function activateSettingsTabs() {
    var panels = document.querySelectorAll("[data-settings-panel]");
    if (!panels.length) return;

    var params = new URLSearchParams(window.location.search);
    var requested = params.get("tab") || window.location.hash.replace(/^#/, "") || "profile";
    var available = {};
    panels.forEach(function (panel) {
      available[panel.getAttribute("data-settings-panel")] = true;
    });
    var active = available[requested] ? requested : "profile";

    panels.forEach(function (panel) {
      panel.hidden = panel.getAttribute("data-settings-panel") !== active;
    });

    document.querySelectorAll("[data-settings-tab]").forEach(function (item) {
      item.classList.toggle("active", item.getAttribute("data-settings-tab") === active);
    });
  }

  function activateCurrentNav() {
    var path = window.location.pathname.split("/").pop() || "home.html";
    var query = window.location.search;

    document.querySelectorAll(".sidebar .nav-item").forEach(function (item) {
      var href = item.getAttribute("href") || "";
      if (!href || href.charAt(0) === "?") return;
      var parts = href.split("?");
      var hrefPath = parts[0];
      var hrefQuery = parts[1] ? "?" + parts[1] : "";
      var samePath = hrefPath === path;
      var sameQuery = !hrefQuery || hrefQuery === query;
      item.classList.toggle("active", samePath && sameQuery);
    });
  }

  // Apply early to avoid FOUC.
  applyTheme(readTheme());
  applyLang(readLang());

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      injectControls();
      activateSettingsTabs();
      activateCurrentNav();
      applyTheme(readTheme());
      applyLang(readLang());
    });
  } else {
    injectControls();
    activateSettingsTabs();
    activateCurrentNav();
    applyTheme(readTheme());
    applyLang(readLang());
  }
})();
