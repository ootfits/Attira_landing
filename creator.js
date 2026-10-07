(function () {
  "use strict";

  var TOKEN_KEY = "attira_creator_auth_token";
  var views = {
    landing: document.getElementById("landingView"),
    auth: document.getElementById("authView"),
    dashboard: document.getElementById("dashboardView"),
  };
  var toast = document.getElementById("toast");
  var toastTimer;
  var currentCreator = null;
  var currentRange = "7d";

  function token() {
    try { return localStorage.getItem(TOKEN_KEY); } catch (_) { return null; }
  }

  function saveToken(value) {
    try { localStorage.setItem(TOKEN_KEY, value); } catch (_) {}
  }

  function clearToken() {
    try { localStorage.removeItem(TOKEN_KEY); } catch (_) {}
  }

  function capture(event, properties) {
    try {
      if (window.posthog && typeof window.posthog.capture === "function") {
        window.posthog.capture(event, properties || {});
      }
    } catch (_) {}
  }

  async function request(url, options) {
    options = options || {};
    var headers = new Headers(options.headers || {});
    if (options.body) headers.set("Content-Type", "application/json");
    if (token()) headers.set("Authorization", "Bearer " + token());
    var response = await fetch(url, Object.assign({}, options, { headers: headers }));
    var body = response.status === 204 ? {} : await response.json().catch(function () { return {}; });
    if (!response.ok) throw new Error(body.error || "Something went wrong. Please try again.");
    return body;
  }

  function setUrl(view, mode) {
    var url = new URL(window.location.href);
    if (view === "landing") url.search = "";
    else {
      url.search = "";
      url.searchParams.set("view", view === "auth" ? mode : view);
    }
    history.replaceState({}, "", url.pathname + url.search);
  }

  function showView(name, updateUrl) {
    Object.keys(views).forEach(function (key) {
      views[key].hidden = key !== name;
    });
    if (updateUrl !== false && name !== "auth") setUrl(name);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function notify(message) {
    toast.textContent = message;
    toast.classList.add("is-visible");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toast.classList.remove("is-visible"); }, 2200);
  }

  function setAuthTab(mode) {
    var signup = mode === "signup";
    document.getElementById("signupTab").setAttribute("aria-selected", String(signup));
    document.getElementById("loginTab").setAttribute("aria-selected", String(!signup));
    document.getElementById("signupPanel").hidden = !signup;
    document.getElementById("loginPanel").hidden = signup;
    setUrl("auth", mode);
    setTimeout(function () {
      var panel = document.getElementById(signup ? "signupPanel" : "loginPanel");
      var firstInput = panel.querySelector("input");
      if (firstInput) firstInput.focus({ preventScroll: true });
    }, 30);
  }

  function openAuth(mode) {
    showView("auth", false);
    setAuthTab(mode || "signup");
  }

  function setFormError(id, message) {
    var el = document.getElementById(id);
    el.textContent = message || "";
    el.hidden = !message;
  }

  function setSubmitting(form, active, idleText) {
    var button = form.querySelector('button[type="submit"]');
    button.disabled = active;
    if (active) button.textContent = "Please wait…";
    else button.innerHTML = idleText + ' <span aria-hidden="true">→</span>';
  }

  async function submitSignup(event) {
    event.preventDefault();
    var form = event.currentTarget;
    setFormError("signupError", "");
    if (!form.checkValidity()) return form.reportValidity();
    var fields = new FormData(form);
    var payload = {
      name: fields.get("name"),
      email: fields.get("email"),
      password: fields.get("password"),
      confirmPassword: fields.get("confirmPassword"),
    };
    if (payload.password !== payload.confirmPassword) {
      return setFormError("signupError", "Passwords do not match.");
    }
    setSubmitting(form, true, "Create creator account");
    try {
      var result = await request("/api/creator/auth/signup", { method: "POST", body: JSON.stringify(payload) });
      saveToken(result.token);
      currentCreator = result.creator;
      capture("creator_account_created", { creator_code: result.creator.creator_code });
      await openDashboard();
      notify("Your creator link is ready.");
      form.reset();
    } catch (error) {
      setFormError("signupError", error.message);
    } finally {
      setSubmitting(form, false, "Create creator account");
    }
  }

  async function submitLogin(event) {
    event.preventDefault();
    var form = event.currentTarget;
    setFormError("loginError", "");
    if (!form.checkValidity()) return form.reportValidity();
    var fields = new FormData(form);
    setSubmitting(form, true, "Open dashboard");
    try {
      var result = await request("/api/creator/auth/login", {
        method: "POST",
        body: JSON.stringify({ email: fields.get("email"), password: fields.get("password") }),
      });
      saveToken(result.token);
      currentCreator = result.creator;
      capture("creator_logged_in");
      await openDashboard();
      form.reset();
    } catch (error) {
      setFormError("loginError", error.message);
    } finally {
      setSubmitting(form, false, "Open dashboard");
    }
  }

  function fillCreator(creator) {
    document.getElementById("creatorName").textContent = creator.name;
    document.getElementById("creatorCode").textContent = creator.creator_code;
    document.getElementById("referralLink").textContent = creator.referral_link;
  }

  function chartSvg(analytics) {
    var width = 760;
    var height = 260;
    var left = 40;
    var right = 14;
    var top = 18;
    var bottom = 38;
    var points = analytics.points || [];
    var max = Math.max.apply(Math, [1].concat(points.map(function (point) { return point.clicks; })));
    var plotted = points.map(function (point, index) {
      var x = left + (points.length <= 1 ? 0 : index * (width - left - right) / (points.length - 1));
      var y = top + (height - top - bottom) * (1 - point.clicks / max);
      return { date: point.date, clicks: point.clicks, x: x, y: y };
    });
    var line = plotted.map(function (point, index) {
      return (index ? "L" : "M") + point.x.toFixed(1) + " " + point.y.toFixed(1);
    }).join(" ");
    var labelEvery = Math.max(1, Math.ceil(plotted.length / 6));
    var labels = plotted.filter(function (_, index) {
      return index === 0 || index === plotted.length - 1 || index % labelEvery === 0;
    });
    var grid = [0, 0.5, 1].map(function (ratio) {
      var y = top + ratio * (height - top - bottom);
      return '<line class="grid" x1="' + left + '" x2="' + (width - right) + '" y1="' + y + '" y2="' + y + '" />';
    }).join("");
    var dateLabels = labels.map(function (point) {
      return '<text x="' + point.x.toFixed(1) + '" y="' + (height - 10) + '" text-anchor="middle">' + point.date.slice(5) + "</text>";
    }).join("");
    var last = plotted[plotted.length - 1];
    var dot = last ? '<circle class="dot" cx="' + last.x.toFixed(1) + '" cy="' + last.y.toFixed(1) + '" r="5" />' : "";
    return '<svg class="analytics-chart" viewBox="0 0 ' + width + " " + height + '" role="img" aria-label="Referral clicks over time">' +
      grid + '<path class="line" d="' + line + '" />' + dot + dateLabels +
      '<text x="4" y="' + (top + 4) + '">' + max + '</text><text x="18" y="' + (height - bottom + 4) + '">0</text></svg>';
  }

  async function loadAnalytics(range) {
    var wrap = document.getElementById("chartWrap");
    wrap.innerHTML = "<p>Loading clicks…</p>";
    try {
      var analytics = await request("/api/creator/analytics/clicks?range=" + encodeURIComponent(range));
      document.getElementById("totalClicks").textContent = analytics.total_clicks;
      var today = analytics.points.length ? analytics.points[analytics.points.length - 1].clicks : 0;
      document.getElementById("clicksToday").textContent = today;
      wrap.innerHTML = chartSvg(analytics);
    } catch (error) {
      wrap.innerHTML = "";
      var message = document.createElement("p");
      message.textContent = error.message;
      wrap.appendChild(message);
    }
  }

  async function openDashboard() {
    if (!token()) return openAuth("login");
    showView("dashboard");
    try {
      if (!currentCreator) {
        var result = await request("/api/creator/me");
        currentCreator = result.creator;
      }
      fillCreator(currentCreator);
      await loadAnalytics(currentRange);
    } catch (_) {
      clearToken();
      currentCreator = null;
      openAuth("login");
      setFormError("loginError", "Your session expired. Please log in again.");
    }
  }

  async function copyReferral() {
    if (!currentCreator) return;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(currentCreator.referral_link);
      } else {
        var input = document.createElement("textarea");
        input.value = currentCreator.referral_link;
        input.style.position = "fixed";
        input.style.opacity = "0";
        document.body.appendChild(input);
        input.select();
        document.execCommand("copy");
        input.remove();
      }
      document.getElementById("copyButton").textContent = "Copied";
      notify("Referral link copied.");
      capture("creator_link_copied");
      setTimeout(function () { document.getElementById("copyButton").textContent = "Copy link"; }, 1800);
    } catch (_) {
      notify("Copy failed. Select the link and copy it manually.");
    }
  }

  async function shareReferral() {
    if (!currentCreator) return;
    if (navigator.share) {
      try {
        await navigator.share({
          title: "Discover Attira",
          text: "Turn the clothes you already own into outfit possibilities with Attira.",
          url: currentCreator.referral_link,
        });
        capture("creator_link_shared");
      } catch (_) {}
    } else {
      copyReferral();
    }
  }

  async function logout() {
    try { await request("/api/creator/auth/session", { method: "DELETE" }); } catch (_) {}
    clearToken();
    currentCreator = null;
    showView("landing");
    notify("You’re logged out.");
  }

  document.querySelectorAll("[data-open-auth]").forEach(function (button) {
    button.addEventListener("click", function () { openAuth(button.getAttribute("data-open-auth")); });
  });
  document.querySelectorAll("[data-show-landing]").forEach(function (button) {
    button.addEventListener("click", function () { showView("landing"); });
  });
  document.querySelectorAll("[data-auth-tab]").forEach(function (button) {
    button.addEventListener("click", function () { setAuthTab(button.getAttribute("data-auth-tab")); });
  });
  document.querySelectorAll("[data-range]").forEach(function (button) {
    button.addEventListener("click", function () {
      currentRange = button.getAttribute("data-range");
      document.querySelectorAll("[data-range]").forEach(function (item) { item.classList.toggle("is-active", item === button); });
      loadAnalytics(currentRange);
    });
  });
  document.getElementById("signupForm").addEventListener("submit", submitSignup);
  document.getElementById("loginForm").addEventListener("submit", submitLogin);
  document.getElementById("copyButton").addEventListener("click", copyReferral);
  document.getElementById("shareButton").addEventListener("click", shareReferral);
  document.getElementById("logoutButton").addEventListener("click", logout);

  var initial = new URLSearchParams(window.location.search).get("view");
  if (initial === "signup" || initial === "login") openAuth(initial);
  else if (initial === "dashboard" || token()) openDashboard();
  else showView("landing", false);
})();
