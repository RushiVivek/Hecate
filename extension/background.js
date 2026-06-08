// hecate background service worker.
//
// MV3 service workers are ephemeral, but an open native-messaging port keeps
// the worker alive for the port's lifetime. We use sendNativeMessage-style
// one-shot connects per request instead of holding a long-lived port: simpler,
// and it sidesteps SW-suspension edge cases for the slice's request/response ops.

const HOST = "com.rushivivek.hecate";

// Ops the extension is allowed to relay to the privileged native host. Anything
// not on this list is rejected at the boundary rather than forwarded blindly.
const ALLOWED_OPS = new Set(["list", "add"]);

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
    const done = (fn, arg) => {
      if (settled) return;
      settled = true;
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

    port.postMessage(request);
  });
}

// Relay popup requests to the native host. Only known ops are forwarded; an
// unknown/malformed message is rejected synchronously and the channel is not
// held open. Returns true only when a response will arrive asynchronously.
chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  if (!request || !ALLOWED_OPS.has(request.op)) {
    sendResponse({ ok: false, error: "unknown op" });
    return false;
  }
  sendToHost(request)
    .then((reply) => sendResponse({ ok: true, reply }))
    .catch((err) => sendResponse({ ok: false, error: String(err && err.message ? err.message : err) }));
  return true;
});
