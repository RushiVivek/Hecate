// hecate popup: ask the background worker (which relays to the native host)
// for the bookmark list and render it.

const statusEl = document.getElementById("status");
const listEl = document.getElementById("list");
const refreshBtn = document.getElementById("refresh");

function setStatus(text) {
  statusEl.textContent = text;
}

// A bookmark URL is arbitrary user data. Only let through web schemes when
// using it as a link href, so a stored `javascript:`/`data:` URL can't become
// a clickable script vector. Anything else renders as inert text.
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
    // Use an <a> only for safe schemes; otherwise show the title as plain text.
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

async function listBookmarks() {
  setStatus("Loading…");
  listEl.replaceChildren();
  // chrome.runtime.sendMessage rejects/uses lastError if the worker errors.
  chrome.runtime.sendMessage({ op: "list" }, (resp) => {
    if (chrome.runtime.lastError) {
      setStatus("Error: " + chrome.runtime.lastError.message);
      return;
    }
    if (!resp || !resp.ok) {
      setStatus("Error: " + (resp && resp.error ? resp.error : "no response"));
      return;
    }
    const reply = resp.reply;
    if (!reply || !reply.ok) {
      setStatus("Host error: " + (reply && reply.error ? reply.error : "unknown"));
      return;
    }
    render(reply.bookmarks);
  });
}

refreshBtn.addEventListener("click", listBookmarks);
// Auto-load on open.
listBookmarks();
