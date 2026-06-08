#!/usr/bin/env bash
# Install the hecate native-messaging host for Chromium-family browsers.
#
# - builds the native binary (release)
# - derives the extension ID from extension/manifest.json's "key" field
# - writes the native-messaging host manifest into each installed browser's
#   NativeMessagingHosts dir, pointing at the built binary
#
# Idempotent: re-running just rewrites the manifests.

set -euo pipefail

HOST_NAME="com.rushivivek.hecate"

# Resolve repo paths relative to this script, regardless of CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NATIVE_DIR="$REPO_DIR/native"
MANIFEST_JSON="$REPO_DIR/extension/manifest.json"

# --- 1. build the binary --------------------------------------------------
echo "==> building native binary"
( cd "$NATIVE_DIR" && cargo build --release )
BIN_PATH="$NATIVE_DIR/target/release/hecate"
[ -x "$BIN_PATH" ] || { echo "error: binary not found at $BIN_PATH" >&2; exit 1; }

# Initialize the store once, up front, so its journal is converted to WAL by a
# single process. Browsers spawn one `serve` process per request, so without
# this a cold first-run could race several processes through the one-time
# rollback->WAL conversion at once and trip "database is locked".
echo "==> initializing store"
"$BIN_PATH" init

# --- 2. derive the extension ID from the manifest "key" -------------------
# Chrome's ID = first 16 bytes of SHA256(DER public key), hex, with each
# nibble 0-f mapped to a-p. The "key" field is the base64 of that DER pubkey.
echo "==> deriving extension id"
KEY_B64="$(
  python3 - "$MANIFEST_JSON" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    print(json.load(f)["key"], end="")
PY
)"
[ -n "$KEY_B64" ] || { echo "error: no \"key\" field in $MANIFEST_JSON" >&2; exit 1; }

# od (POSIX, always present) rather than xxd (ships with vim, often absent and
# would abort the pipeline under `set -o pipefail`).
EXT_ID="$(
  printf '%s' "$KEY_B64" | base64 -d \
    | openssl dgst -sha256 -binary \
    | head -c16 | od -An -tx1 | tr -d ' \n' | tr '0-9a-f' 'a-p'
)"
echo "    extension id: $EXT_ID"

# --- 3. write the host manifest into each installed browser ---------------
write_manifest() {
  local dir="$1"
  mkdir -p "$dir"
  local out="$dir/$HOST_NAME.json"
  cat > "$out" <<EOF
{
  "name": "$HOST_NAME",
  "description": "hecate native bookmark host",
  "path": "$BIN_PATH",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$EXT_ID/"]
}
EOF
  echo "    wrote $out"
}

CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}"
# Parallel arrays (bash 3.2-compatible: no associative arrays). Each entry is
# "Label|config-dir".
BROWSERS="
Chromium|$CONFIG/chromium
Chrome|$CONFIG/google-chrome
Brave|$CONFIG/BraveSoftware/Brave-Browser
"

echo "==> installing host manifests"
installed=0
while IFS='|' read -r name base; do
  [ -n "$name" ] || continue
  if [ -d "$base" ]; then
    echo "  $name:"
    write_manifest "$base/NativeMessagingHosts"
    installed=$((installed + 1))
  fi
done <<EOF
$BROWSERS
EOF

if [ "$installed" -eq 0 ]; then
  echo "  no Chromium-family browser config dirs found; nothing written." >&2
  echo "  (install/run a browser first, or create one of the dirs above.)" >&2
fi

echo
echo "Done. Next:"
echo "  1. Load $REPO_DIR/extension as an unpacked extension (chrome://extensions, Developer mode)."
echo "  2. Confirm its ID is: $EXT_ID"
echo "  3. Open the popup and click \"List bookmarks\"."
