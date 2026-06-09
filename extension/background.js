// hecate background service worker.
//
// MV3 service workers are ephemeral, but we don't hold long-lived state: each
// request opens a one-shot native-messaging port, gets one reply, and closes.
// This sidesteps SW-suspension edge cases and matches the per-request process
// model on the native side.

const HOST = "com.rushivivek.hecate";

// Ops the extension is allowed to relay to the privileged native host. This
// allowlist is the security boundary — anything not listed is rejected here
// rather than forwarded blindly. Must stay in sync with the native Request enum.
const ALLOWED_OPS = new Set([
  "tree",
  "list",
  "add",
  "create_folder",
  "create_bookmark",
  "rename",
  "move",
  "delete",
]);

const CONTEXT_MENU_ID = "hecate-add";

// Bound on how long to wait for a native-host reply before failing the request,
// so a wedged host can't pin the MV3 message channel open indefinitely.
const HOST_TIMEOUT_MS = 10000;

// Send a single request to the native host and resolve with its JSON reply.
// Uses a short-lived connectNative port so we get exactly one response and then
// tear the port down.
function sendToHost(request) {
  return new Promise((resolve, reject) => {
    let port;
    try {
      port = chrome.runtime.connectNative(HOST);
    } catch (e) {
      reject(e);
      return;
    }

    let settled = false;
    let timer = null;
    const done = (fn, arg) => {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      try {
        port.disconnect();
      } catch (_) {}
      fn(arg);
    };

    port.onMessage.addListener((msg) => done(resolve, msg));
    port.onDisconnect.addListener(() => {
      const err = chrome.runtime.lastError;
      done(reject, new Error(err ? err.message : "native host disconnected"));
    });

    // A host that connects but never replies and never disconnects (wedged
    // process) would otherwise leave this promise — and the MV3 message channel
    // — open forever. Bound it.
    timer = setTimeout(() => done(reject, new Error("native host timeout")), HOST_TIMEOUT_MS);

    port.postMessage(request);
  });
}

// The single client-side "add a bookmark" path — popup, context menu, and the
// keyboard command all funnel through here. parent_id omitted = top level.
// Returns the host reply (throws on transport/host failure).
async function addTarget({ title, url, parent_id }) {
  if (!url) throw new Error("no URL to bookmark");
  const req = { op: "create_bookmark", title: title || url, url };
  if (parent_id != null) req.parent_id = parent_id;
  return sendToHost(req);
}

// Best-effort user feedback that doesn't require the notifications permission:
// flash a badge on the toolbar action.
function flashBadge(text, color) {
  try {
    chrome.action.setBadgeBackgroundColor({ color });
    chrome.action.setBadgeText({ text });
    setTimeout(() => chrome.action.setBadgeText({ text: "" }), 2000);
  } catch (_) {
    // action APIs unavailable in some contexts; ignore.
  }
}

// Add a target and flash a badge reflecting the actual outcome. The badge is
// green only when the host confirms `reply.ok` — a transport success with a
// host-level rejection (bad input, NotAFolder, depth cap, …) flashes the error
// badge, not a false checkmark. Every add surface goes through here.
async function addAndFlash(target) {
  try {
    const reply = await addTarget(target);
    const ok = !!(reply && reply.ok);
    flashBadge(ok ? "✓" : "!", ok ? "#0a0" : "#b00");
  } catch (_) {
    flashBadge("!", "#b00");
  }
}

async function addActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) {
    flashBadge("!", "#b00");
    return;
  }
  await addAndFlash({ title: tab.title, url: tab.url });
}

// --- relay (popup + manager page) -----------------------------------------
// Forwards an allowlisted op to the privileged native host. Two guards:
//   1. sender must be this extension's own pages. Today there are no content
//      scripts and no `externally_connectable`, so only our popup/manager can
//      message us — but check explicitly so a future manifest change can't
//      silently open a path from a web page to the native host.
//   2. only ALLOWED_OPS are forwarded; anything else is rejected synchronously
//      and the channel is not held open.
// Returns true only when a response will arrive asynchronously.
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (!sender || sender.id !== chrome.runtime.id) {
    sendResponse({ ok: false, error: "forbidden" });
    return false;
  }
  if (!request || !ALLOWED_OPS.has(request.op)) {
    sendResponse({ ok: false, error: "unknown op" });
    return false;
  }
  sendToHost(request)
    .then((reply) => sendResponse({ ok: true, reply }))
    .catch((err) =>
      sendResponse({ ok: false, error: String(err && err.message ? err.message : err) })
    );
  return true;
});

// --- context menu ----------------------------------------------------------
// Re-create on install/update. removeAll first so re-running can't hit a
// duplicate-id error.
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: CONTEXT_MENU_ID,
      title: "Bookmark with hecate",
      contexts: ["page", "link"],
    });
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  // A link click bookmarks the link target; a page click bookmarks the page.
  // addAndFlash gates the success badge on the host's reply.ok.
  if (info.linkUrl) {
    addAndFlash({ title: info.linkText || info.linkUrl, url: info.linkUrl });
  } else {
    const url = info.pageUrl || (tab && tab.url);
    addAndFlash({ title: (tab && tab.title) || url, url });
  }
});

// --- keyboard command ------------------------------------------------------
chrome.commands.onCommand.addListener((command) => {
  if (command === "add-current-page") addActiveTab();
});
