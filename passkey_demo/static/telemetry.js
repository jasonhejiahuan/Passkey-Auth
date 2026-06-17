"use strict";

(() => {
  const script = document.currentScript;
  const tokenUrl = script?.dataset.passkeyTelemetryTokenUrl || "";
  if (!tokenUrl) {
    return;
  }

  const storageKey = `jason.passkey.telemetry.v2:${window.location.origin}`;

  function hasCollected() {
    try {
      return window.localStorage.getItem(storageKey) === "1";
    } catch (_error) {
      return document.cookie.includes(`${encodeURIComponent(storageKey)}=1`);
    }
  }

  function markCollected() {
    try {
      window.localStorage.setItem(storageKey, "1");
      return;
    } catch (_error) {
      document.cookie = `${encodeURIComponent(storageKey)}=1; Max-Age=31536000; Path=/; SameSite=Lax`;
    }
  }

  async function requestTelemetry() {
    if (hasCollected()) {
      return;
    }

    let statusUrl = "";
    try {
      const response = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          path: window.location.pathname,
          referrer: document.referrer || "",
        }),
        keepalive: true,
      });
      if (!response.ok) {
        return;
      }
      const data = await response.json();
      statusUrl = data.statusUrl || "";
    } catch (_error) {
      return;
    }

    if (!statusUrl) {
      return;
    }

    markCollected();

    const frame = document.createElement("iframe");
    frame.src = statusUrl;
    frame.title = "";
    frame.tabIndex = -1;
    frame.setAttribute("aria-hidden", "true");
    frame.style.position = "fixed";
    frame.style.width = "1px";
    frame.style.height = "1px";
    frame.style.opacity = "0";
    frame.style.pointerEvents = "none";
    frame.style.border = "0";
    frame.style.inset = "auto 0 0 auto";
    document.body.appendChild(frame);
  }

  const schedule = window.requestIdleCallback || ((callback) => window.setTimeout(callback, 800));
  schedule(requestTelemetry, { timeout: 2500 });
})();
