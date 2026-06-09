// hecate popup: add the current page (with a destination-folder picker) and
// show a flat list of bookmarks. Relays through the background worker.

const statusEl = document.getElementById("status");
const listEl = document.getElementById("list");
const refreshBtn = document.getElementById("refresh");
const addBtn = document.getElementById("add-page");
const folderSel = document.getElementById("folder");
const openManagerBtn = document.getElementById("open-manager");

const LAST_FOLDER_KEY = "lastFolderId";

function setStatus(text) {
  statusEl.textContent = text;
}

// Relay helper: resolve to the host reply, throw a readable error otherwise.
function call(op, extra) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ op, ...extra }, (resp) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      if (!resp || !resp.ok) return reject(new Error((resp && resp.error) || "no response"));
      const reply = resp.reply;
      if (!reply || !reply.ok) return reject(new Error((reply && reply.error) || "native host error"));
      resolve(reply);
    });
  });
}

// A bookmark URL is arbitrary user data. Only let web schemes through as a
// clickable href; anything else renders as inert text.
function safeHref(url) {
  try {
    const u = new URL(url);
    if (u.protocol === "http:" || u.protocol === "https:" || u.protocol === "ftp:") {
      return u.href;
    }
  } catch (_) {}
  return null;
}

function render(bookmarks) {
  listEl.replaceChildren();
  if (!bookmarks || bookmarks.length === 0) {
    setStatus("No bookmarks yet.");
    return;
  }
  setStatus(`${bookmarks.length} bookmark(s)`);
  for (const b of bookmarks) {
    const li = document.createElement("li");
    const href = safeHref(b.url);
    const titleEl = document.createElement(href ? "a" : "span");
    if (href) {
      titleEl.href = href;
      titleEl.target = "_blank";
      titleEl.rel = "noreferrer";
    }
    titleEl.textContent = b.title || b.url;
    const url = document.createElement("span");
    url.className = "url";
    url.textContent = b.url;
    li.append(titleEl, url);
    listEl.append(li);
  }
}

// Populate the destination-folder <select> from the tree (indented by depth).
async function loadFolders() {
  let reply;
  try {
    reply = await call("tree", {});
  } catch (e) {
    // Non-fatal for the picker; leave it with just a default option.
    folderSel.replaceChildren(new Option("(top level)", ""));
    return;
  }
  // Full root-to-folder path labels so duplicate-named folders at different
  // places stay distinguishable (matches the manager's move picker).
  const opts = [];
  (function walk(n, path) {
    if (n.kind !== "folder") return;
    const here = n.parent_id == null ? "" : path.concat(n.title).join(" / ");
    opts.push({ id: n.id, label: here || "(top level)" });
    const childPath = n.parent_id == null ? [] : path.concat(n.title);
    for (const c of n.children || []) walk(c, childPath);
  })(reply.root, []);

  folderSel.replaceChildren();
  for (const o of opts) folderSel.append(new Option(o.label, String(o.id)));

  // Restore last-used folder if it still exists.
  try {
    chrome.storage.local.get({ [LAST_FOLDER_KEY]: "" }, (v) => {
      const last = v[LAST_FOLDER_KEY];
      if (last && opts.some((o) => String(o.id) === String(last))) folderSel.value = String(last);
    });
  } catch (_) {}
}

async function listBookmarks() {
  setStatus("Loading…");
  listEl.replaceChildren();
  try {
    const reply = await call("list", {});
    render(reply.bookmarks);
  } catch (e) {
    setStatus("Error: " + e.message);
  }
}

async function addThisPage() {
  setStatus("Adding…");
  let tab;
  try {
    [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch (e) {
    setStatus("Error: " + e.message);
    return;
  }
  if (!tab || !tab.url) {
    setStatus("No active tab to add.");
    return;
  }
  const parentId = folderSel.value ? parseInt(folderSel.value, 10) : undefined;
  const extra = { title: tab.title || tab.url, url: tab.url };
  if (parentId != null && !Number.isNaN(parentId)) extra.parent_id = parentId;
  try {
    await call("create_bookmark", extra);
    if (extra.parent_id != null) {
      try {
        chrome.storage.local.set({ [LAST_FOLDER_KEY]: extra.parent_id });
      } catch (_) {}
    }
    setStatus("Added.");
    listBookmarks();
  } catch (e) {
    setStatus("Error: " + e.message);
  }
}

refreshBtn.addEventListener("click", listBookmarks);
addBtn.addEventListener("click", addThisPage);
openManagerBtn.addEventListener("click", () => {
  chrome.tabs.create({ url: "chrome://bookmarks" });
});

// Initial load.
loadFolders();
listBookmarks();
