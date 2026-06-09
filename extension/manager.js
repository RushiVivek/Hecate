// hecate bookmark manager — the chrome://bookmarks override page.
//
// Talks to the native host through the background service worker (same relay
// the popup uses). Because this page REPLACES Chrome's bookmark manager, a
// failure to reach the host must surface a clear banner, never a blank page.

const treeEl = document.getElementById("tree");
const bannerEl = document.getElementById("banner");

// Expanded-folder state survives reloads. Stored as an array of ids.
let expanded = new Set();

// --- host communication ----------------------------------------------------
// Wraps the relay: background replies {ok, reply|error}; the host reply is
// itself {ok, ...}. Resolve to the host payload, throw a readable error
// otherwise so callers (and the banner) get one consistent failure path.
function call(op, extra) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ op, ...extra }, (resp) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!resp || !resp.ok) {
        reject(new Error((resp && resp.error) || "no response from extension"));
        return;
      }
      const reply = resp.reply;
      if (!reply || !reply.ok) {
        reject(new Error((reply && reply.error) || "native host error"));
        return;
      }
      resolve(reply);
    });
  });
}

function showBanner(message) {
  bannerEl.textContent = "";
  const span = document.createElement("span");
  span.textContent = message + " — the native host is unavailable. Re-run ";
  const code = document.createElement("code");
  code.textContent = "install/install-chromium.sh";
  bannerEl.append(span, code, document.createTextNode(" and reload."));
  bannerEl.style.display = "block";
}

function hideBanner() {
  bannerEl.style.display = "none";
}

// --- url safety ------------------------------------------------------------
// Bookmark URLs are arbitrary user data: only web schemes become clickable
// links; anything else renders as inert text (no javascript:/data: vector).
function safeHref(url) {
  try {
    const u = new URL(url);
    if (u.protocol === "http:" || u.protocol === "https:" || u.protocol === "ftp:") {
      return u.href;
    }
  } catch (_) {}
  return null;
}

// --- rendering -------------------------------------------------------------
function renderTree(root) {
  treeEl.textContent = "";
  if (!root.children || root.children.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No bookmarks yet. Use “New folder” or the toolbar button to add one.";
    treeEl.append(li);
    return;
  }
  for (const child of root.children) {
    treeEl.append(renderNode(child, root.id));
  }
}

function renderNode(node, parentId) {
  const li = document.createElement("li");
  li.className = "node";

  const row = document.createElement("div");
  row.className = "row";

  const isFolder = node.kind === "folder";
  const isOpen = expanded.has(node.id);

  const twisty = document.createElement("span");
  twisty.className = "twisty" + (isFolder ? "" : " leaf");
  twisty.textContent = isFolder ? (isOpen ? "▾" : "▸") : "•";
  if (isFolder) {
    twisty.addEventListener("click", () => toggle(node.id));
  }

  const icon = document.createElement("span");
  icon.className = "icon";
  icon.textContent = isFolder ? "📁" : "🔖";

  const label = document.createElement("span");
  label.className = "label";
  if (isFolder) {
    label.textContent = node.title;
    label.style.cursor = "pointer";
    label.addEventListener("click", () => toggle(node.id));
  } else {
    const href = safeHref(node.url);
    if (href) {
      const a = document.createElement("a");
      a.href = href;
      a.target = "_blank";
      a.rel = "noreferrer";
      a.textContent = node.title || node.url;
      label.append(a);
    } else {
      label.textContent = node.title || node.url || "(untitled)";
    }
  }

  const actions = document.createElement("span");
  actions.className = "actions";
  if (isFolder) {
    actions.append(actionBtn("+bm", () => promptNewBookmark(node.id)));
    actions.append(actionBtn("+folder", () => promptNewFolder(node.id)));
  }
  actions.append(actionBtn("rename", () => promptRename(node)));
  actions.append(actionBtn("move", () => promptMove(node)));
  actions.append(actionBtn("delete", () => confirmDelete(node)));

  row.append(twisty, icon, label, actions);
  li.append(row);

  if (isFolder && isOpen && node.children && node.children.length) {
    const ul = document.createElement("ul");
    for (const child of node.children) {
      ul.append(renderNode(child, node.id));
    }
    li.append(ul);
  }
  return li;
}

function actionBtn(text, onClick) {
  const b = document.createElement("button");
  b.textContent = text;
  b.addEventListener("click", (e) => {
    e.stopPropagation();
    onClick();
  });
  return b;
}

// --- expand/collapse state -------------------------------------------------
function toggle(id) {
  if (expanded.has(id)) expanded.delete(id);
  else expanded.add(id);
  persistExpanded();
  refresh();
}

function persistExpanded() {
  try {
    chrome.storage.local.set({ expanded: [...expanded] });
  } catch (_) {}
}

function loadExpanded() {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.get({ expanded: [] }, (v) => {
        if (chrome.runtime.lastError) resolve([]);
        else resolve(v.expanded || []);
      });
    } catch (_) {
      resolve([]);
    }
  });
}

// --- actions ---------------------------------------------------------------
async function refresh() {
  try {
    const reply = await call("tree", {});
    hideBanner();
    renderTree(reply.root);
  } catch (e) {
    showBanner(e.message);
  }
}

async function mutate(op, extra, errPrefix) {
  try {
    await call(op, extra);
    await refresh();
  } catch (e) {
    // Immediate feedback for this action via alert...
    alert(`${errPrefix}: ${e.message}`);
    // ...and re-run the tree read so a host that went away mid-session raises
    // the persistent banner (a failed mutation skips refresh's own tree call).
    await refresh();
  }
}

function promptNewFolder(parentId) {
  const title = prompt("New folder name:");
  if (title && title.trim()) mutate("create_folder", { parent_id: parentId, title: title.trim() }, "Create folder failed");
}

function promptNewBookmark(parentId) {
  const url = prompt("Bookmark URL:");
  if (!url || !url.trim()) return;
  const title = prompt("Title:", url.trim());
  if (title === null) return;
  mutate(
    "create_bookmark",
    { parent_id: parentId, title: title.trim() || url.trim(), url: url.trim() },
    "Create bookmark failed"
  );
}

function promptRename(node) {
  const title = prompt("Rename to:", node.title);
  if (title !== null && title.trim()) mutate("rename", { id: node.id, title: title.trim() }, "Rename failed");
}

function confirmDelete(node) {
  const what = node.kind === "folder" ? "folder and everything inside it" : "bookmark";
  if (confirm(`Delete this ${what}?`)) mutate("delete", { id: node.id }, "Delete failed");
}

// Move via a folder picker (flattened, indented). Drag-and-drop is a later
// polish; the picker is fully testable and accessible.
async function promptMove(node) {
  let reply;
  try {
    reply = await call("tree", {});
  } catch (e) {
    alert(`Move failed: ${e.message}`);
    return;
  }
  // Build the list of valid destination folders. Exclude the node itself and
  // its descendants (the native host rejects cycles too, but don't offer them).
  // Each label is the full path from root so duplicate-named folders at
  // different places stay distinguishable in the numbered picker.
  const folders = [];
  (function walk(n, path, underBanned) {
    const isBanned = underBanned || n.id === node.id;
    if (n.kind === "folder") {
      const here = n.parent_id == null ? "" : path.concat(n.title).join(" / ");
      if (!isBanned) folders.push({ id: n.id, label: here || "(top level)" });
      const childPath = n.parent_id == null ? [] : path.concat(n.title);
      for (const c of n.children || []) walk(c, childPath, isBanned);
    }
  })(reply.root, [], false);

  if (folders.length === 0) {
    alert("No available destination folders.");
    return;
  }
  const choices = folders.map((f, i) => `${i}: ${f.label}`).join("\n");
  const pick = prompt(`Move “${node.title}” to which folder?\n\n${choices}\n\nEnter a number:`);
  if (pick === null) return;
  const idx = parseInt(pick, 10);
  if (Number.isNaN(idx) || idx < 0 || idx >= folders.length) {
    alert("Invalid choice.");
    return;
  }
  mutate("move", { id: node.id, new_parent_id: folders[idx].id }, "Move failed");
}

// --- wiring ----------------------------------------------------------------
document.getElementById("refresh").addEventListener("click", refresh);
document.getElementById("new-folder").addEventListener("click", () => {
  // Top-level new folder: pass no parent_id so the host defaults to root.
  const title = prompt("New folder name:");
  if (title && title.trim()) mutate("create_folder", { title: title.trim() }, "Create folder failed");
});

(async function init() {
  expanded = new Set(await loadExpanded());
  await refresh();
})();
