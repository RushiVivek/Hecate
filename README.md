# hecate

A personal cross-browser bookmark manager. A local **native app** owns the
bookmark store and all crypto; a thin **WebExtension** talks to it over
[native messaging](https://developer.chrome.com/docs/apps/nativeMessaging).
Both Chromium- and Firefox-family browsers point at the same native app, so
they share one store — sync without a server.

> Status: **Milestone 3 — hidden encrypted vault + pagination + drag-and-drop.**
> On top of the M2 folder tree: a single encrypted hidden vault (the marquee
> feature), folders that lazy-load a page at a time, full-text search, and
> drag-and-drop in the manager. Firefox wiring and native-bookmark-bar
> mirroring come next.

## Layout

```
native/      Rust binary: bookmark store + native-messaging host
extension/   Chromium MV3 WebExtension (popup + chrome://bookmarks override)
install/     installer that registers the native-messaging host manifest
```

## Native binary

The store is a single SQLite file: one `nodes` table holding folders and
bookmarks in a tree (a single root, `parent_id` links, per-folder ordering).
The native app is the sole source of truth and enforces all tree invariants
(no cycles, atomic recursive delete, contiguous ordering) inside transactions.

```
cargo build                          # from native/
hecate init                          # create/migrate (~/.local/share/hecate/hecate.db)
hecate tree                          # print the folder tree
hecate list                          # flat list of bookmarks
hecate add   <title> <url> [--parent ID]
hecate mkdir <title> [--parent ID]
hecate rename <id> <title>
hecate move  <id> <new_parent> [--pos N]
hecate rm    <id>                    # folders delete recursively
hecate children [--parent ID] [--limit N] [--offset N]   one page of children
hecate serve                         # native-messaging loop (used by the extension)

# hidden vault — phrase is read from stdin, never argv
echo "<phrase>" | hecate vault-create
echo "<phrase>" | hecate vault-tree
echo "<phrase>" | hecate vault-mkdir <title> [--parent ID]
echo "<phrase>" | hecate vault-add <title> <url> [--parent ID]
```

`serve` reads length-prefixed JSON requests on stdin and writes JSON replies on
stdout per Chrome's native-messaging protocol. Each request is its own process;
the store uses WAL + `BEGIN IMMEDIATE` so concurrent browsers stay safe.

## Hidden encrypted vault

A single hidden vault holds an arbitrarily-nested secret subtree, encrypted at
rest and **physically absent from the normal `nodes` tree** (it lives in a
separate `vault` table as one opaque AEAD blob — it can never leak into the
visible tree or a future bookmark-bar mirror).

- **Model "b": the phrase IS the key.** A passphrase → Argon2id (with a stored,
  cleartext salt + params) → 32-byte key; the subtree is sealed with
  XChaCha20-Poly1305. Nothing that can recover the data is stored — no key, no
  verifier.
- **Reveal:** type the phrase into the manager's search box. If it matches no
  bookmarks it's tried as a vault phrase; success reveals a "🔒 Hidden" branch
  for the page session. Wrong phrase shows "no matches" — no oracle.

**Honest caveats (by design):**

- Forget the phrase → the vault is **unrecoverable**. No escrow.
- It is **offline-brute-forceable**: anyone with the disk has the salt, params,
  and ciphertext — a complete offline verifier. The only defense is **phrase
  entropy** × Argon2id cost (tuned to ~hundreds of ms). Use a real high-entropy
  passphrase, not a password.
- The derived key is returned to the manager page and held in **browser JS
  memory** for the unlocked session (a deliberate simplicity tradeoff over a
  key-holding daemon). So a live attacker on the unlocked page can read the key
  and plaintext; the locks (manual, 5-min idle, page-close) are best-effort.
  The protection this *does* deliver is **at rest**: a stolen disk / copied DB /
  backup reveals nothing without the phrase.

## Extension UI

- **`chrome://bookmarks`** is overridden with hecate's tree manager. Folders
  **lazy-load one page at a time** (so a huge tree stays responsive and no
  reply approaches the native-messaging 1 MB cap). Create/rename/move/delete,
  plus **drag-and-drop**: drag a URL onto a folder to add it, drag items between
  folders to move, drop between siblings to reorder. A "Move to…" button stays
  as a keyboard-accessible fallback. If the host is unreachable it shows a
  banner, never a blank page.
- **Search box** filters the tree; doubles as the vault reveal (see above).
- **Toolbar popup** — "Add this page" with a destination-folder picker.
- **Right-click menu** — "Bookmark with hecate" on pages and links.
- **Keyboard** — `Ctrl+Shift+D` (`Cmd+Shift+D` on mac) bookmarks the current
  page; rebind at `chrome://extensions/shortcuts`.

## Install (Chromium family)

```
./install/install-chromium.sh
```

This builds the release binary, derives the extension ID from
`extension/manifest.json`'s `key`, and writes the host manifest into the
NativeMessagingHosts dir of any installed Chromium/Chrome/Brave. Then load
`extension/` unpacked at `chrome://extensions` (Developer mode) — its ID is
pinned by the `key` field to `ldhiobhepncgobiicdghlgnaijokdffg`.

The host manifest records the **absolute path** to the built binary
(`native/target/release/hecate`), so the repo must stay put after install —
moving or deleting it breaks the extension (it'll report "native host
disconnected"). Re-run the installer after relocating.

### The signing key

`install/hecate-extension-key.pem` is the RSA key whose public half is embedded
in the manifest's `key` field to pin a stable extension ID. **It is gitignored
and must be backed up out-of-band** — losing it changes the ID; leaking it lets
someone impersonate the extension's identity.
