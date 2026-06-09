# hecate

A personal cross-browser bookmark manager. A local **native app** owns the
bookmark store and all crypto; a thin **WebExtension** talks to it over
[native messaging](https://developer.chrome.com/docs/apps/nativeMessaging).
Both Chromium- and Firefox-family browsers point at the same native app, so
they share one store — sync without a server.

> Status: **Milestone 2 — folder tree + CRUD.** Nested folders/bookmarks with
> full CRUD over native messaging + CLI; the extension overrides
> `chrome://bookmarks` with hecate's own tree UI, and adds bookmarks via the
> popup, a right-click menu, and a keyboard shortcut. Hidden encrypted folders,
> Firefox wiring, and native-bookmark-bar mirroring come next.

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
hecate serve                         # native-messaging loop (used by the extension)
```

`serve` reads length-prefixed JSON requests on stdin and writes JSON replies on
stdout per Chrome's native-messaging protocol. Each request is its own process;
the store uses WAL + `BEGIN IMMEDIATE` so concurrent browsers stay safe.

## Extension UI

- **`chrome://bookmarks`** is overridden with hecate's tree manager (expand/
  collapse, create/rename/move/delete). If the native host is unreachable it
  shows a banner with remediation rather than a blank page.
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
