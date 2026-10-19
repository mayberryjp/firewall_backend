"use strict";

const $ = (id) => document.getElementById(id);
let stage = "";
let busy = false;

async function api(path, method = "GET", body) {
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers: method === "GET" ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(data.error || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return data;
}

async function perform(action) {
  if (busy) return;
  busy = true;
  $("error").hidden = true;
  document.querySelectorAll("button").forEach((button) => { button.disabled = true; });
  try {
    await action();
  } catch (error) {
    if (error.status === 401) {
      $("new-key").value = "";
      $("reveal").close();
      $("key-list").replaceChildren();
      $("keys").hidden = true;
      $("finish-panel").hidden = true;
      $("account").hidden = true;
      $("steps").hidden = true;
      $("login").hidden = false;
      $("subtitle").textContent = "Sign in to continue.";
    }
    $("error").textContent = error.message;
    $("error").hidden = false;
  } finally {
    busy = false;
    document.querySelectorAll("button").forEach((button) => { button.disabled = false; });
  }
}

async function loadKeys() {
  const data = await api("/auth/keys");
  $("key-list").replaceChildren();
  $("no-keys").hidden = data.keys.length !== 0;
  $("review-setup").hidden = stage !== "keys" || data.keys.length === 0;
  for (const key of data.keys) {
    const row = document.createElement("tr");
    for (const value of [key.name, key.masked, new Date(key.created_at).toLocaleString()]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    const cell = document.createElement("td");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "danger";
    button.textContent = "Remove";
    button.setAttribute("aria-label", `Remove key ${key.name}`);
    button.addEventListener("click", () => {
      if (!window.confirm(`Remove "${key.name}"? Its API access will stop immediately.`)) return;
      perform(async () => {
        await api(`/auth/keys/${encodeURIComponent(key.id)}`, "DELETE");
        $("saved").checked = false;
        await loadKeys();
      });
    });
    cell.append(button);
    row.append(cell);
    $("key-list").append(row);
  }
}

async function refresh() {
  const status = await api("/auth/status");
  stage = status.stage;
  for (const id of ["account", "login", "keys"]) {
    $(id).hidden = id === "keys" ? !["keys", "ready"].includes(stage) : id !== stage;
  }
  $("steps").hidden = stage === "login" || stage === "ready";
  $("step-account").setAttribute("aria-current", stage === "account" ? "step" : "false");
  $("step-keys").setAttribute("aria-current", stage === "keys" ? "step" : "false");
  $("title").textContent = stage === "ready" ? "Device administration" : "Welcome to your device";
  $("subtitle").textContent = status.authenticated
    ? `Signed in as ${status.username}. Sessions expire after 30 minutes.`
    : "Set up your device account and API keys.";
  $("finish-panel").hidden = true;
  $("step-review").setAttribute("aria-current", "false");
  $("ready-panel").hidden = stage !== "ready";
  $("keys-title").textContent = stage === "ready" ? "Manage API keys" : "Create your first API key";
  $("api-url").textContent = `${window.location.origin}/api/v1/state`;
  if (status.authenticated) await loadKeys();
}

$("account-form").addEventListener("submit", (event) => {
  event.preventDefault();
  perform(async () => {
    const password = $("password").value;
    if (password !== $("confirm-password").value) throw new Error("Passwords do not match.");
    const length = new TextEncoder().encode(password).length;
    if (length < 12 || length > 72) throw new Error("Password must be 12 to 72 UTF-8 bytes.");
    try {
      await api("/auth/setup", "POST", { username: $("username").value, password });
    } finally {
      $("password").value = "";
      $("confirm-password").value = "";
    }
    await refresh();
  });
});

$("login-form").addEventListener("submit", (event) => {
  event.preventDefault();
  perform(async () => {
    try {
      await api("/auth/login", "POST", { username: $("login-username").value, password: $("login-password").value });
    } finally {
      $("login-password").value = "";
    }
    await refresh();
  });
});

$("key-form").addEventListener("submit", (event) => {
  event.preventDefault();
  perform(async () => {
    const data = await api("/auth/keys", "POST", { name: $("key-name").value });
    $("new-key").value = data.token;
    $("copy-status").textContent = "";
    $("reveal").showModal();
    $("new-key").focus();
    $("new-key").select();
    $("key-name").value = "";
    $("saved").checked = false;
    await loadKeys();
  });
});

$("reveal").addEventListener("cancel", (event) => { event.preventDefault(); });
$("copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("new-key").value);
    $("copy-status").textContent = "Copied. Store the key securely before hiding it.";
  } catch {
    $("copy-status").textContent = "Clipboard unavailable. Select and copy the key manually.";
  }
});
$("dismiss").addEventListener("click", () => {
  $("new-key").value = "";
  $("reveal").close();
});

$("review-setup").addEventListener("click", () => {
  $("keys").hidden = true;
  $("finish-panel").hidden = false;
  $("step-keys").setAttribute("aria-current", "false");
  $("step-review").setAttribute("aria-current", "step");
  $("saved").focus();
});
$("back-to-keys").addEventListener("click", () => {
  $("finish-panel").hidden = true;
  $("keys").hidden = false;
  $("step-keys").setAttribute("aria-current", "step");
  $("step-review").setAttribute("aria-current", "false");
});

$("finish-form").addEventListener("submit", (event) => {
  event.preventDefault();
  perform(async () => {
    await api("/auth/complete", "POST", { saved: $("saved").checked });
    await refresh();
  });
});
$("logout").addEventListener("click", () => perform(async () => {
  await api("/auth/logout", "POST", {});
  $("key-list").replaceChildren();
  $("new-key").value = "";
  $("saved").checked = false;
  await refresh();
}));
window.addEventListener("pagehide", () => {
  $("new-key").value = "";
  $("password").value = "";
  $("confirm-password").value = "";
  $("login-password").value = "";
});
window.addEventListener("pageshow", (event) => {
  if (event.persisted) {
    $("reveal").close();
    perform(refresh);
  }
});
perform(refresh);
