# hecate

A personal cross-browser bookmark manager. A local **native app** owns the
bookmark store and all crypto; a thin **WebExtension** talks to it over
[native messaging](https://developer.chrome.com/docs/apps/nativeMessaging).
Both Chromium- and Firefox-family browsers point at the same native app, so
they share one store — sync without a server.

> Status: **v1 thin vertical slice.** Native app (Rust + SQLite) + Chromium
> extension + native-messaging wiring, doing one op end-to-end (`list`/`add`).
> Hidden encrypted folders, folder nesting, and Firefox come next.

## Layout

```
native/      Rust binary: bookmark store + native-messaging host
extension/   Chromium MV3 WebExtension (thin client)
install/     installer that registers the native-messaging host manifest
```

## Native binary

```
cargo build            # from native/
hecate init            # create the store (~/.local/share/hecate/hecate.db)
hecate add <title> <url>
hecate list
hecate serve           # native-messaging loop (spoken by the extension)
```

The store is a single SQLite file. `serve` reads length-prefixed JSON requests
on stdin and writes JSON replies on stdout per Chrome's native-messaging
protocol.

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
