//! hecate native binary.
//!
//! Subcommands:
//!   hecate serve            native-messaging loop (spoken by the extension)
//!   hecate init             create the store if absent, then exit
//!   hecate add <title> <url>
//!   hecate list

mod nm;
mod store;

use std::io;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{json, Value};

use store::Store;

/// Incoming native-messaging request. Untagged-ish: we match on `op`.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Request {
    List,
    Add { title: String, url: String },
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str);
    let rest = args.get(1..).unwrap_or(&[]);

    let result = match cmd {
        Some("serve") => serve(),
        Some("init") => cmd_init(),
        Some("list") => cmd_list(),
        Some("add") => cmd_add(rest),
        // When a browser launches us as a native-messaging host, the first
        // argument is the caller's origin (e.g. `chrome-extension://<id>/` or
        // `moz-extension://<uuid>/`), NOT a subcommand. Route those to serve.
        Some(arg) if is_extension_origin(arg) => serve(),
        Some(other) => {
            eprintln!("unknown subcommand: {other}");
            usage();
            return ExitCode::from(2);
        }
        None => {
            usage();
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hecate: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() {
    eprintln!("usage: hecate <serve|init|list|add <title> <url>>");
}

/// True if `arg` looks like the browser-supplied caller origin passed to a
/// native-messaging host (Chromium: `chrome-extension://…`; Firefox:
/// `moz-extension://…`). Firefox also appends the extension ID as a second arg,
/// which `serve` ignores.
fn is_extension_origin(arg: &str) -> bool {
    arg.starts_with("chrome-extension://") || arg.starts_with("moz-extension://")
}

/// Seconds since the Unix epoch. Clamps a pre-1970 clock to 0 rather than
/// panicking.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn cmd_init() -> anyhow_lite::Result {
    Store::open()?;
    println!("store ready");
    Ok(())
}

fn cmd_list() -> anyhow_lite::Result {
    let store = Store::open()?;
    let bookmarks = store.list()?;
    if bookmarks.is_empty() {
        println!("(no bookmarks)");
    }
    for b in &bookmarks {
        println!("{}\t{}\t{}", b.id, b.title, b.url);
    }
    Ok(())
}

fn cmd_add(rest: &[String]) -> anyhow_lite::Result {
    let (title, url) = match rest {
        [title, url] => (title.as_str(), url.as_str()),
        _ => return Err("usage: hecate add <title> <url>".into()),
    };
    let store = Store::open()?;
    let id = store.add(title, url, now_secs())?;
    println!("added {id}");
    Ok(())
}

/// Native-messaging loop: read framed JSON requests from stdin, write framed
/// JSON responses to stdout, until the browser closes the port (clean EOF).
fn serve() -> anyhow_lite::Result {
    let store = Store::open()?;
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();

    while let Some(raw) = nm::read_message(&mut stdin)? {
        let response = handle(&store, &raw);
        let bytes = serde_json::to_vec(&response)?;
        nm::write_message(&mut stdout, &bytes)?;
    }
    Ok(())
}

/// Parse and dispatch one request, always returning a JSON response value
/// (errors become `{ok:false, error:...}` rather than tearing down the loop).
fn handle(store: &Store, raw: &[u8]) -> Value {
    let req: Request = match serde_json::from_slice(raw) {
        Ok(r) => r,
        Err(e) => return json!({ "ok": false, "error": format!("bad request: {e}") }),
    };
    match req {
        Request::List => match store.list() {
            Ok(bookmarks) => json!({ "ok": true, "bookmarks": bookmarks }),
            Err(e) => json!({ "ok": false, "error": e.to_string() }),
        },
        Request::Add { title, url } => match store.add(&title, &url, now_secs()) {
            Ok(id) => json!({ "ok": true, "id": id }),
            Err(e) => json!({ "ok": false, "error": e.to_string() }),
        },
    }
}

/// Tiny local error alias so the binary needs no extra deps: any error that
/// implements `Error` flows into a boxed trait object, and `&str`/`String`
/// convert via `From`.
mod anyhow_lite {
    pub type Error = Box<dyn std::error::Error>;
    pub type Result = std::result::Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use super::is_extension_origin;

    #[test]
    fn recognizes_browser_origins() {
        // The exact shapes browsers pass as argv[1] when launching the host.
        assert!(is_extension_origin(
            "chrome-extension://ldhiobhepncgobiicdghlgnaijokdffg/"
        ));
        assert!(is_extension_origin(
            "moz-extension://2c7d0d2a-1234-4abc-9def-000000000000/"
        ));
    }

    #[test]
    fn does_not_swallow_real_subcommands() {
        for cmd in ["serve", "init", "list", "add", "bogus"] {
            assert!(!is_extension_origin(cmd));
        }
    }
}
