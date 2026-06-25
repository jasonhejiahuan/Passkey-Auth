"use strict";

(() => {
  const script = document.currentScript;
  const endpoint = script?.dataset.passkeyTelemetryEndpoint || "";
  const delivery = script?.dataset.passkeyTelemetryDelivery || "relay";
  const token = script?.dataset.passkeyTelemetryToken || "";
  const policyKey = script?.dataset.passkeyTelemetryPolicy || "";
  const features = (script?.dataset.passkeyTelemetryFeatures || "")
    .split(",")
    .filter(Boolean);
  if (!endpoint || !token || !policyKey || !features.length) return;

  const storageKey = `jason.passkey.telemetry.v3:${window.location.origin}:${policyKey}`;

  function alreadyCollected() {
    try {
      return window.localStorage.getItem(storageKey) === "1";
    } catch (_error) {
      return window.sessionStorage.getItem(storageKey) === "1";
    }
  }

  function markCollected() {
    try {
      window.localStorage.setItem(storageKey, "1");
    } catch (_error) {
      window.sessionStorage.setItem(storageKey, "1");
    }
  }

  function detectClient() {
    const source = `${navigator.userAgentData?.platform || ""} ${navigator.platform || ""} ${navigator.userAgent || ""}`.toLowerCase();
    let osFamily = "other";
    if (/iphone|ipad|ipod/.test(source)) osFamily = "ios";
    else if (source.includes("android")) osFamily = "android";
    else if (source.includes("windows")) osFamily = "windows";
    else if (source.includes("mac")) osFamily = "macos";
    else if (source.includes("cros")) osFamily = "chromeos";
    else if (source.includes("linux")) osFamily = "linux";

    const touchPoints = Number(navigator.maxTouchPoints || 0);
    const narrow = Math.min(screen.width || 0, screen.height || 0) < 820;
    const mobileHint = Boolean(navigator.userAgentData?.mobile);
    let deviceClass = "desktop";
    if (mobileHint || (/android|iphone|ipod/.test(source) && narrow)) deviceClass = "mobile";
    else if (touchPoints > 1 && narrow) deviceClass = "tablet";
    return { osFamily, deviceClass };
  }

  function screenSignal() {
    return {
      width: screen.width,
      height: screen.height,
      availableWidth: screen.availWidth,
      availableHeight: screen.availHeight,
      pixelRatio: Math.round((window.devicePixelRatio || 1) * 100) / 100,
      colorDepth: screen.colorDepth,
      orientation: screen.orientation?.type || "",
    };
  }

  async function hardwareSignal() {
    const result = {
      logicalProcessors: navigator.hardwareConcurrency || 0,
      deviceMemoryGb: navigator.deviceMemory || 0,
    };
    if (navigator.userAgentData?.getHighEntropyValues) {
      try {
        const hints = await navigator.userAgentData.getHighEntropyValues([
          "architecture",
          "bitness",
          "model",
        ]);
        result.architecture = hints.architecture || "";
        result.bitness = hints.bitness || "";
        result.model = hints.model || "";
      } catch (_error) {
        // High-entropy hints are optional and intentionally fail closed.
      }
    }
    return result;
  }

  function networkSignal() {
    const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!connection) return { supported: false };
    return {
      supported: true,
      effectiveType: connection.effectiveType || "",
      downlinkBucket: connection.downlink ? Math.round(connection.downlink * 2) / 2 : 0,
      rttBucket: connection.rtt ? Math.round(connection.rtt / 50) * 50 : 0,
      saveData: Boolean(connection.saveData),
    };
  }

  function preferencesSignal() {
    return {
      colorScheme: matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light",
      reducedMotion: matchMedia("(prefers-reduced-motion: reduce)").matches,
      contrast: matchMedia("(prefers-contrast: more)").matches ? "more" : "default",
      forcedColors: matchMedia("(forced-colors: active)").matches,
    };
  }

  async function fontSignal(osFamily) {
    const modules = {
      windows: "/static/telemetry/fonts-windows.js",
      macos: "/static/telemetry/fonts-macos.js",
      ios: "/static/telemetry/fonts-macos.js",
      linux: "/static/telemetry/fonts-linux.js",
      chromeos: "/static/telemetry/fonts-linux.js",
    };
    const modulePath = modules[osFamily];
    if (!modulePath) return { platform: osFamily, available: [] };
    try {
      const module = await import(modulePath);
      return {
        platform: osFamily,
        available: module.detectFonts(),
      };
    } catch (_error) {
      return { platform: osFamily, available: [] };
    }
  }

  async function batterySignal() {
    if (typeof navigator.getBattery !== "function") return { supported: false };
    try {
      const module = await import("/static/telemetry/battery.js");
      return module.readBattery();
    } catch (_error) {
      return { supported: false };
    }
  }

  function referrerOrigin() {
    if (!document.referrer) return "";
    try {
      return new URL(document.referrer).origin;
    } catch (_error) {
      return "";
    }
  }

  async function collect() {
    if (alreadyCollected()) return;
    const client = detectClient();
    const signals = {};
    if (features.includes("screen")) signals.screen = screenSignal();
    if (features.includes("hardware")) signals.hardware = await hardwareSignal();
    if (features.includes("fonts")) signals.fonts = await fontSignal(client.osFamily);
    if (features.includes("battery")) signals.battery = await batterySignal();
    if (features.includes("network")) signals.network = networkSignal();
    if (features.includes("preferences")) signals.preferences = preferencesSignal();

    const sample = {
      event: "passkey_auth.browser_telemetry",
      source: "passkey-auth",
      schemaVersion: 1,
      features,
      path: window.location.pathname,
      referrerOrigin: referrerOrigin(),
      client,
      signals,
    };
    if (delivery === "direct") {
      await sendDirect(sample);
      return;
    }
    const body = JSON.stringify({ token, ...sample });
    let queued = false;
    if (navigator.sendBeacon) {
      queued = navigator.sendBeacon(
        endpoint,
        new Blob([body], { type: "application/json" }),
      );
    }
    if (queued) {
      markCollected();
      return;
    }
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
        credentials: "same-origin",
        keepalive: true,
      });
      if (response.ok) markCollected();
    } catch (_error) {
      // Telemetry is deliberately best-effort and never surfaces UI errors.
    }
  }

  async function sendDirect(sample) {
    try {
      const bootstrapResponse = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
        credentials: "same-origin",
      });
      if (!bootstrapResponse.ok) return;
      const bootstrap = await bootstrapResponse.json();
      const target = bootstrap?.target;
      if (!target?.url) return;
      const body = JSON.stringify(sample);
      const targetHeaders = target.headers && typeof target.headers === "object"
        ? target.headers
        : {};
      const contentType = target.contentType || "text/plain;charset=UTF-8";
      const hasHeaders = Object.keys(targetHeaders).length > 0;
      if (target.opaque && !hasHeaders && navigator.sendBeacon) {
        const queued = navigator.sendBeacon(
          target.url,
          new Blob([body], { type: contentType }),
        );
        if (queued) {
          markCollected();
          return;
        }
      }
      const response = await fetch(target.url, {
        method: "POST",
        headers: { "Content-Type": contentType, ...targetHeaders },
        body,
        mode: target.opaque ? "no-cors" : "cors",
        credentials: "omit",
        keepalive: true,
      });
      if (target.opaque || response.ok) markCollected();
    } catch (_error) {
      // Direct telemetry is best-effort and cannot delay the visible flow.
    }
  }

  const schedule = window.requestIdleCallback
    || ((callback) => window.setTimeout(callback, 900));
  schedule(() => { void collect(); }, { timeout: 3000 });
})();
