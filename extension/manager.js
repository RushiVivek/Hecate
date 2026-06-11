// hecate bookmark manager — the chrome://bookmarks override page.
//
// Talks to the native host through the background service worker. Because this
// page REPLACES Chrome's bookmark manager, a failure to reach the host must
// surface a clear banner, never a blank page.
//
// Two trees are shown: the normal store, and — once unlocked via the search
// box — a "🔒 Hidden" vault branch. They are kept strictly separate: vault
// node keys are prefixed so ids never alias, and a drag may not cross between
// them (the host can't move a node across the two databases).
//
// Folders lazy-load their children one page at a time (the `children` /
// `vault_children` ops), so a single reply never approaches the 1 MB native-
// messaging cap and huge trees stay responsive.

const treeEl = document.getElementById("tree");
const bannerEl = document.getElementById("banner");
const searchEl = document.getElementById("search");
const lockBtn = document.getElementById("lock-btn");

const PAGE = 200;
const IDLE_MS = 5 * 60 * 1000; // auto-lock the vault after inactivity
const DND_TYPE = "application/x-hecate-node";

// Scope tags. MAIN ops hit the normal store; VAULT ops carry the wire key.
const MAIN = { vault: false };
const VAULT = { vault: true };

// Vault session state. The derived key lives ONLY in this page's JS memory for
// the page session; it is cleared on lock, idle, or unload. (Documented
// tradeoff: key-over-the-wire means the browser heap is the trust boundary.)
let vaultKey = null;
let idleTimer = null;

// Expanded-folder state (node-keys), persisted across reloads. Vault keys are
// session-only — never written to storage — so a closed/locked vault leaves no
// trace of which hidden folders were open.
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

// --- scope-aware ops --------------------------------------------------------
function nodeKey(scope, id) {
  return (scope.vault ? "vault:" : "main:") + id;
}

// One page of a folder's children. `parentId == null` means that scope's root.
function fetchChildren(scope, parentId, offset) {
  if (scope.vault) {
    return call("vault_children", {
      key: vaultKey,
      parent_id: parentId,
      limit: PAGE,
      offset,
    });
  }
  return call("children", { parent_id: parentId, limit: PAGE, offset });
}

// Run a mutation in `scope`. Vault mutations carry the key. Returns the reply.
function mutateOp(scope, op, extra) {
  if (scope.vault) return call("vault_" + op, { key: vaultKey, ...extra });
  return call(op, extra);
}

// --- rendering --------------------------------------------------------------
// The top-level list holds: (optionally) the vault root branch, then the main
// store's top-level children. Each folder lazy-loads on expand.
async function renderRoot() {
  treeEl.textContent = "";
  if (vaultKey) {
    treeEl.append(makeRootBranch(VAULT, "🔒 Hidden", "vault-root"));
  }
  // Main top level loads into the shared tree element directly.
  try {
    await loadInto(treeEl, MAIN, null);
    hideBanner();
  } catch (e) {
    showBanner(e.message);
  }
}

// A synthetic root LI for a scope (used for the vault branch). The main store's
// top level renders flat into #tree, so it has no synthetic root.
function makeRootBranch(scope, title, extraClass) {
  const node = { id: null, kind: "folder", title, synthetic: true };
  const li = makeFolderLi(scope, node);
  if (extraClass) li.classList.add(extraClass);
  return li;
}

// Load one page of children of `parentId` (in `scope`) and append child LIs to
// `containerUl`. If the folder has more than one page, append a "Show more".
async function loadInto(containerUl, scope, parentId, offset = 0) {
  const reply = await fetchChildren(scope, parentId, offset);
  for (const child of reply.children) {
    containerUl.append(renderNode(scope, child));
  }
  const loaded = offset + reply.children.length;
  if (loaded < reply.total) {
    const li = document.createElement("li");
    const more = document.createElement("button");
    more.textContent = `Show more (${loaded}/${reply.total})`;
    more.addEventListener("click", async () => {
      li.remove();
      try {
        await loadInto(containerUl, scope, parentId, loaded);
      } catch (e) {
        showBanner(e.message);
      }
    });
    li.append(more);
    containerUl.append(li);
  }
}

function renderNode(scope, node) {
  if (node.kind === "folder") return makeFolderLi(scope, node);
  return makeBookmarkLi(scope, node);
}

function makeFolderLi(scope, node) {
  const li = document.createElement("li");
  li.className = "node";
  const isSynthetic = !!node.synthetic;
  const childParentId = isSynthetic ? null : node.id;
  const key = isSynthetic ? nodeKey(scope, "root") : nodeKey(scope, node.id);
  const isOpen = expanded.has(key);

  const row = document.createElement("div");
  row.className = "row";

  const twisty = document.createElement("span");
  twisty.className = "twisty";
  twisty.textContent = isOpen ? "▾" : "▸";
  twisty.addEventListener("click", () => toggleFolder(li, scope, node, key));

  const icon = document.createElement("span");
  icon.className = "icon";
  icon.textContent = isSynthetic ? "🔒" : "📁";

  const label = document.createElement("span");
  label.className = "label";
  label.textContent = node.title;
  label.style.cursor = "pointer";
  label.addEventListener("click", () => toggleFolder(li, scope, node, key));

  row.append(twisty, icon, label);

  // The two synthetic roots can't be renamed/moved/deleted; only +bm/+folder.
  const actions = document.createElement("span");
  actions.className = "actions";
  actions.append(actionBtn("+bm", () => promptNewBookmark(scope, childParentId)));
  actions.append(actionBtn("+folder", () => promptNewFolder(scope, childParentId)));
  if (!isSynthetic) {
    actions.append(actionBtn("rename", () => promptRename(scope, node)));
    actions.append(actionBtn("move", () => promptMove(scope, node)));
    actions.append(actionBtn("delete", () => confirmDelete(scope, node)));
  }
  row.append(actions);

  li.append(row);

  // Drag-and-drop: real folders are draggable and are drop targets (into +
  // reorder); synthetic roots are drop-into targets only.
  if (!isSynthetic) makeDraggable(row, scope, node);
  makeDropTarget(row, li, scope, node, childParentId);

  // A child <ul> is created lazily on expand.
  if (isOpen) {
    const ul = document.createElement("ul");
    li.append(ul);
    // Auto-load (e.g. restored expand state, or after a refresh).
    loadInto(ul, scope, childParentId).catch((e) => showBanner(e.message));
  }
  return li;
}

function makeBookmarkLi(scope, node) {
  const li = document.createElement("li");
  li.className = "node";
  const row = document.createElement("div");
  row.className = "row";

  const twisty = document.createElement("span");
  twisty.className = "twisty leaf";
  twisty.textContent = "•";

  const icon = document.createElement("span");
  icon.className = "icon";
  icon.textContent = "🔖";

  const label = document.createElement("span");
  label.className = "label";
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

  const actions = document.createElement("span");
  actions.className = "actions";
  actions.append(actionBtn("rename", () => promptRename(scope, node)));
  actions.append(actionBtn("move", () => promptMove(scope, node)));
  actions.append(actionBtn("delete", () => confirmDelete(scope, node)));

  row.append(twisty, icon, label, actions);
  li.append(row);

  makeDraggable(row, scope, node);
  makeDropTarget(row, li, scope, node, null); // reorder-around only (not into)
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

// --- expand/collapse --------------------------------------------------------
function toggleFolder(li, scope, node, key) {
  const open = expanded.has(key);
  if (open) {
    expanded.delete(key);
  } else {
    expanded.add(key);
  }
  persistExpanded();
  // Re-render just this folder LI in place (cheaper + preserves siblings).
  const fresh = makeFolderLi(scope, node);
  if (li.classList.contains("vault-root")) fresh.classList.add("vault-root");
  li.replaceWith(fresh);
}

function persistExpanded() {
  // Persist only MAIN keys — vault expand-state is session-only so a locked
  // vault leaves no on-disk hint of which hidden folders were open.
  try {
    const mainKeys = [...expanded].filter((k) => k.startsWith("main:"));
    chrome.storage.local.set({ expanded: mainKeys });
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

// --- mutations --------------------------------------------------------------
async function mutate(scope, op, extra, errPrefix) {
  try {
    await mutateOp(scope, op, extra);
    await renderRoot();
  } catch (e) {
    alert(`${errPrefix}: ${e.message}`);
    // Re-render so a dead host raises the banner, and a vault-auth failure
    // (e.g. key no longer valid) gets a chance to surface.
    await renderRoot();
  }
}

function promptNewFolder(scope, parentId) {
  const title = prompt("New folder name:");
  if (title && title.trim()) {
    mutate(scope, "create_folder", { parent_id: parentId, title: title.trim() }, "Create folder failed");
  }
}

function promptNewBookmark(scope, parentId) {
  const url = prompt("Bookmark URL:");
  if (!url || !url.trim()) return;
  const title = prompt("Title:", url.trim());
  if (title === null) return;
  mutate(
    scope,
    "create_bookmark",
    { parent_id: parentId, title: title.trim() || url.trim(), url: url.trim() },
    "Create bookmark failed"
  );
}

function promptRename(scope, node) {
  const title = prompt("Rename to:", node.title);
  if (title !== null && title.trim()) {
    mutate(scope, "rename", { id: node.id, title: title.trim() }, "Rename failed");
  }
}

function confirmDelete(scope, node) {
  const what = node.kind === "folder" ? "folder and everything inside it" : "bookmark";
  if (confirm(`Delete this ${what}?`)) {
    mutate(scope, "delete", { id: node.id }, "Delete failed");
  }
}

// Move via a folder picker (full paths). Drag-and-drop is the primary path;
// this stays as an accessible fallback. Within the node's own scope only.
async function promptMove(scope, node) {
  let folders;
  try {
    folders = await collectFolders(scope, node.id);
  } catch (e) {
    alert(`Move failed: ${e.message}`);
    return;
  }
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
  // The "(top level)" option carries a sentinel, not a real id — resolve it to
  // the scope's actual root id before sending (the host expects an i64).
  let dest = folders[idx].id;
  if (dest === rootSentinelId(scope)) {
    dest = await resolveRootId(scope);
    if (dest == null) {
      alert("Can't resolve the destination folder.");
      return;
    }
  }
  mutate(scope, "move", { id: node.id, new_parent_id: dest }, "Move failed");
}

// Walk a scope's folders (full-tree, paginated) building destination options,
// excluding the moved node and its descendants. `excludeId` is the node being
// moved. Bounded by the host's depth cap.
async function collectFolders(scope, excludeId) {
  const out = [];
  async function walk(parentId, path, underBanned) {
    let offset = 0;
    for (;;) {
      const reply = await fetchChildren(scope, parentId, offset);
      for (const c of reply.children) {
        if (c.kind !== "folder") continue;
        const banned = underBanned || c.id === excludeId;
        const label = path.concat(c.title).join(" / ");
        if (!banned) out.push({ id: c.id, label });
        await walk(c.id, path.concat(c.title), banned);
      }
      offset += reply.children.length;
      if (offset >= reply.total || reply.children.length === 0) break;
    }
  }
  // The scope root itself is a valid destination ("(top level)").
  out.push({ id: rootSentinelId(scope), label: "(top level)" });
  await walk(null, [], false);
  return out;
}

// The move op needs a concrete parent id. For "top level" we must pass the real
// root id — fetch it once via a child's parent_id, or fall back to a probe.
// Simpler: the host treats a move's new_parent_id; for top level we look up the
// root id from any existing child, else create-then-move isn't needed because
// the root always exists. We resolve it lazily.
let cachedRootId = { main: null, vault: null };
function rootSentinelId(scope) {
  // Sentinel; resolved to the real root id at move time via resolveRootId().
  return scope.vault ? "__vault_root__" : "__main_root__";
}
async function resolveRootId(scope) {
  const cacheKey = scope.vault ? "vault" : "main";
  if (cachedRootId[cacheKey] != null) return cachedRootId[cacheKey];
  // A node's parent_id chain bottoms out at the root; the first page's children
  // carry their parent_id (= root id) when parentId is null.
  const reply = await fetchChildren(scope, null, 0);
  let rootId = null;
  if (reply.children.length > 0 && reply.children[0].parent_id != null) {
    rootId = reply.children[0].parent_id;
  }
  cachedRootId[cacheKey] = rootId;
  return rootId;
}

// --- drag and drop ----------------------------------------------------------
function makeDraggable(row, scope, node) {
  row.setAttribute("draggable", "true");
  row.addEventListener("dragstart", (e) => {
    e.stopPropagation();
    const payload = JSON.stringify({
      vault: scope.vault,
      id: node.id,
      kind: node.kind,
      position: node.position,
      parent_id: node.parent_id,
    });
    e.dataTransfer.setData(DND_TYPE, payload);
    e.dataTransfer.effectAllowed = "move";
  });
}

// A row accepts: an internal node (move into a folder, or reorder around any
// row) and an external URL (add a bookmark into a folder). `intoParentId` is
// the folder's child-parent id when the row is a folder, else null.
function makeDropTarget(row, li, scope, node, intoParentId) {
  const isFolder = node.kind === "folder";

  row.addEventListener("dragover", (e) => {
    e.preventDefault();
    e.stopPropagation();
    clearDropHints(row);
    const zone = dropZone(e, row, isFolder);
    row.classList.add(zone);
    e.dataTransfer.dropEffect = hasInternal(e) ? "move" : "copy";
  });
  row.addEventListener("dragleave", () => clearDropHints(row));
  row.addEventListener("drop", async (e) => {
    e.preventDefault();
    e.stopPropagation();
    const zone = dropZone(e, row, isFolder);
    clearDropHints(row);
    try {
      await handleDrop(e, zone, scope, node, intoParentId);
    } catch (err) {
      alert(`Drop failed: ${err.message}`);
    }
  });
}

function hasInternal(e) {
  return Array.from(e.dataTransfer.types || []).includes(DND_TYPE);
}

// Decide intent from the cursor position within the row: top third = before,
// bottom third = after, middle = into (folders only; for a bookmark the middle
// also counts as after).
function dropZone(e, row, isFolder) {
  const r = row.getBoundingClientRect();
  const y = e.clientY - r.top;
  if (y < r.height / 3) return "drop-before";
  if (y > (r.height * 2) / 3) return "drop-after";
  return isFolder ? "drop-into" : "drop-after";
}

function clearDropHints(row) {
  row.classList.remove("drop-into", "drop-before", "drop-after");
}

async function handleDrop(e, zone, scope, node, intoParentId) {
  const raw = e.dataTransfer.getData(DND_TYPE);
  if (raw) {
    // Internal move/reorder.
    let src;
    try {
      src = JSON.parse(raw);
    } catch (_) {
      return;
    }
    if (!!src.vault !== scope.vault) {
      alert("Can't move between the hidden vault and the normal tree.");
      return;
    }
    if (src.id === node.id) return; // dropped on itself
    // The synthetic root header has no position, so a before/after drop on it
    // is meaningless — always treat any drop on it as "move into top level"
    // (avoids serializing position: NaN, which would silently append anyway).
    if (node.synthetic) {
      const dest = await resolveRootId(scope);
      if (dest == null) {
        alert("Can't resolve the destination folder.");
        return;
      }
      await mutateOp(scope, "move", { id: src.id, new_parent_id: dest });
      await renderRoot();
      return;
    }
    if (zone === "drop-into") {
      await mutateOp(scope, "move", { id: src.id, new_parent_id: node.id });
    } else {
      // Reorder: drop before/after this row, within this row's parent folder.
      const newParent = node.parent_id != null ? node.parent_id : await resolveRootId(scope);
      if (newParent == null) {
        alert("Can't resolve the destination folder.");
        return;
      }
      // Target index among this folder's children: the row's position, +1 for
      // an "after" drop. The host's move excludes the dragged node from the
      // destination list BEFORE inserting at this index, so when we're
      // reordering within the SAME folder and the dragged node currently sits
      // above the target, everything at/after the target shifts up by one once
      // it's excluded — decrement to compensate. (Cross-folder and upward
      // moves need no adjustment: the dragged node isn't ahead of the target.)
      let pos = node.position;
      if (zone === "drop-after") pos += 1;
      const sameFolder = src.parent_id != null && src.parent_id === newParent;
      if (sameFolder && src.position < pos) pos -= 1;
      await mutateOp(scope, "move", { id: src.id, new_parent_id: newParent, position: pos });
    }
    await renderRoot();
    return;
  }

  // External URL drop → add a bookmark.
  const url = extractUrl(e.dataTransfer);
  if (!url) return;
  const safe = safeHref(url);
  if (!safe) {
    alert("Only http/https/ftp links can be bookmarked.");
    return;
  }
  // Drop a URL onto a folder → add inside it; onto a bookmark → add as a
  // sibling (into the bookmark's parent).
  const parentId =
    node.kind === "folder" && zone === "drop-into"
      ? node.synthetic
        ? null
        : node.id
      : node.parent_id != null
      ? node.parent_id
      : null;
  await mutateOp(scope, "create_bookmark", { parent_id: parentId, title: safe, url: safe });
  await renderRoot();
}

function extractUrl(dt) {
  const uri = dt.getData("text/uri-list");
  if (uri) {
    // uri-list may contain comments (#) and multiple lines; take the first URL.
    const line = uri.split(/\r?\n/).find((l) => l && !l.startsWith("#"));
    if (line) return line.trim();
  }
  const text = (dt.getData("text/plain") || "").trim();
  return text || null;
}

// --- search & vault unlock --------------------------------------------------
// The search box does double duty: it filters the visible tree, and if a query
// matches nothing it is tried as a vault phrase. A real high-entropy phrase
// matches no titles/urls, so it falls through to unlock; this also avoids
// running Argon2id on every keystroke (only on a zero-result Enter).
async function onSearch() {
  const q = searchEl.value.trim();
  if (!q) {
    await renderRoot();
    return;
  }
  let results;
  try {
    results = (await call("search", { query: q, limit: 200 })).results;
  } catch (e) {
    showBanner(e.message);
    return;
  }
  if (results.length > 0) {
    renderSearchResults(results);
    return;
  }
  // No matches — try the text as a vault phrase.
  try {
    const reply = await call("vault_unlock", { phrase: q });
    openVaultSession(reply.key);
    await renderRoot();
  } catch (_) {
    // Unlock failed. If a vault EXISTS, this was a wrong phrase → just "No
    // matches" (no content oracle). If NO vault exists, offer to create one
    // with this phrase (existence is non-secret in this model — vault_status
    // exposes it anyway — so the create affordance leaks nothing new).
    let exists = true;
    try {
      exists = (await call("vault_status", {})).exists;
    } catch (_) {}
    renderSearchResults([], exists ? null : q);
  }
}

function openVaultSession(key) {
  vaultKey = key;
  armIdleTimer();
  document.body.classList.add("vault-on");
  searchEl.value = "";
  expanded.add(nodeKey(VAULT, "root")); // reveal the branch expanded
}

async function createVault(phrase) {
  try {
    const reply = await call("vault_create", { phrase });
    openVaultSession(reply.key);
    await renderRoot();
  } catch (e) {
    alert(`Create vault failed: ${e.message}`);
  }
}

function renderSearchResults(results, createPhrase = null) {
  treeEl.textContent = "";
  if (results.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No matches.";
    // Only when there is no vault yet do we offer to create one with the typed
    // phrase (gated on vault_status by the caller — preserves the no-oracle
    // property: a wrong phrase against an existing vault never shows this).
    if (createPhrase) {
      const btn = document.createElement("button");
      btn.textContent = "Create a hidden vault with this phrase";
      btn.style.marginLeft = "8px";
      btn.addEventListener("click", () => {
        if (
          confirm(
            "Create a hidden encrypted vault with the phrase you typed?\n\n" +
              "There is NO recovery — if you forget this phrase the vault is lost forever. " +
              "Use a long, high-entropy passphrase."
          )
        ) {
          createVault(createPhrase);
        }
      });
      li.append(btn);
    }
    treeEl.append(li);
    return;
  }
  // Render hits as a FLAT, non-interactive list. Crucially we do NOT reuse the
  // folder/bookmark tree nodes here: those wire a twisty whose toggle mutates
  // and persists the shared `expanded` set and lazy-loads children inline,
  // which would corrupt both the search view and the normal tree's saved state.
  for (const node of results) {
    const li = document.createElement("li");
    li.className = "node";
    const row = document.createElement("div");
    row.className = "row";

    const icon = document.createElement("span");
    icon.className = "icon";
    icon.textContent = node.kind === "folder" ? "📁" : "🔖";

    const label = document.createElement("span");
    label.className = "label";
    const href = node.kind === "bookmark" ? safeHref(node.url) : null;
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

    row.append(icon, label);
    li.append(row);
    treeEl.append(li);
  }
}

// --- vault lock -------------------------------------------------------------
function lockVault() {
  vaultKey = null;
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = null;
  document.body.classList.remove("vault-on");
  // Drop any vault expand-state so it doesn't linger.
  for (const k of [...expanded]) if (k.startsWith("vault:")) expanded.delete(k);
  renderRoot();
}

function armIdleTimer() {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(lockVault, IDLE_MS);
}

// Any interaction while unlocked resets the idle countdown.
function bumpIdle() {
  if (vaultKey) armIdleTimer();
}

// --- wiring -----------------------------------------------------------------
document.getElementById("refresh").addEventListener("click", renderRoot);
document.getElementById("new-folder").addEventListener("click", () => {
  const title = prompt("New folder name:");
  if (title && title.trim()) {
    mutate(MAIN, "create_folder", { title: title.trim() }, "Create folder failed");
  }
});
lockBtn.addEventListener("click", lockVault);
searchEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter") onSearch();
});
searchEl.addEventListener("search", onSearch); // clearing the box (×) re-renders
for (const ev of ["click", "keydown", "mousemove"]) {
  document.addEventListener(ev, bumpIdle, { passive: true });
}
// Lock the vault fully when the page is hidden/closed — clears the key AND the
// visible 🔒 branch + session expand-state, so the UI never outlives the key.
window.addEventListener("pagehide", () => {
  if (vaultKey) lockVault();
});
// If the page is restored from the bfcache, re-render from current (locked)
// state so a stale hidden branch can't reappear.
window.addEventListener("pageshow", (e) => {
  if (e.persisted) renderRoot();
});

(async function init() {
  expanded = new Set(await loadExpanded());
  await renderRoot();
})();
