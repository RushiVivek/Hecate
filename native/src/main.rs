//! hecate native binary.
//!
//! Subcommands:
//!   hecate serve                         native-messaging loop (the extension)
//!   hecate init                          create/migrate the store, then exit
//!   hecate tree                          print the folder tree
//!   hecate list                          flat list of bookmarks (back-compat)
//!   hecate add <title> <url> [--parent ID]
//!   hecate addbm <title> <url> [--parent ID]
//!   hecate mkdir <title> [--parent ID]
//!   hecate rename <id> <title>
//!   hecate move <id> <new_parent> [--pos N]
//!   hecate rm <id>

mod nm;
mod store;
mod vault;

use std::io;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{json, Value};

use store::{Node, NodeKind, Store};

/// Incoming native-messaging request, dispatched on the `op` field.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Tree {
        #[serde(default)]
        include_hidden: bool,
    },
    List,
    Add {
        title: String,
        url: String,
        parent_id: Option<i64>,
    },
    CreateFolder {
        parent_id: Option<i64>,
        title: String,
    },
    CreateBookmark {
        parent_id: Option<i64>,
        title: String,
        url: String,
    },
    Rename {
        id: i64,
        title: String,
    },
    Move {
        id: i64,
        new_parent_id: i64,
        position: Option<i64>,
    },
    Delete {
        id: i64,
    },
    /// Paginated direct children of a folder (default root).
    Children {
        parent_id: Option<i64>,
        #[serde(default = "default_limit")]
        limit: i64,
        #[serde(default)]
        offset: i64,
    },
    /// Flat substring search over the visible tree.
    Search {
        query: String,
        #[serde(default = "default_limit")]
        limit: i64,
    },

    // --- hidden vault ops -------------------------------------------------
    /// Does a hidden vault exist on disk?
    VaultStatus,
    /// Create a new empty vault. Returns the wire key.
    VaultCreate { phrase: String },
    /// Unlock with a phrase. Returns the wire key + the vault's top-level page.
    VaultUnlock {
        phrase: String,
        #[serde(default = "default_limit")]
        limit: i64,
        #[serde(default)]
        offset: i64,
    },
    /// Paginated children inside the (already-unlocked) vault, by wire key.
    VaultChildren {
        key: String,
        parent_id: Option<i64>,
        #[serde(default = "default_limit")]
        limit: i64,
        #[serde(default)]
        offset: i64,
    },
    VaultCreateFolder {
        key: String,
        parent_id: Option<i64>,
        title: String,
    },
    VaultCreateBookmark {
        key: String,
        parent_id: Option<i64>,
        title: String,
        url: String,
    },
    VaultRename {
        key: String,
        id: i64,
        title: String,
    },
    VaultMove {
        key: String,
        id: i64,
        new_parent_id: i64,
        position: Option<i64>,
    },
    VaultDelete {
        key: String,
        id: i64,
    },
    /// Re-key the vault under a new phrase. Returns the new wire key.
    VaultChangePhrase { key: String, new_phrase: String },
}

/// Default page size for paginated reads.
fn default_limit() -> i64 {
    200
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str);
    let rest = args.get(1..).unwrap_or(&[]);

    let result = match cmd {
        Some("serve") => serve(),
        Some("init") => cmd_init(),
        Some("tree") => cmd_tree(),
        Some("list") => cmd_list(),
        Some("add") | Some("addbm") => cmd_add(rest),
        Some("mkdir") => cmd_mkdir(rest),
        Some("rename") => cmd_rename(rest),
        Some("move") => cmd_move(rest),
        Some("rm") => cmd_rm(rest),
        Some("children") => cmd_children(rest),
        // Vault CLI parity — phrase is read from stdin, NEVER argv (argv leaks
        // into ps/history). Useful for testing the vault without a browser.
        Some("vault-status") => cmd_vault_status(),
        Some("vault-create") => cmd_vault_create(),
        Some("vault-tree") => cmd_vault_tree(),
        Some("vault-mkdir") => cmd_vault_mkdir(rest),
        Some("vault-add") => cmd_vault_add(rest),
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
    eprintln!(
        "usage: hecate <command>\n\
         \n\
         serve                          native-messaging loop (used by the extension)\n\
         init                           create/migrate the store, then exit\n\
         tree                           print the folder tree\n\
         list                           flat list of bookmarks\n\
         add   <title> <url> [--parent ID]   add a bookmark (alias: addbm)\n\
         mkdir <title> [--parent ID]         create a folder\n\
         rename <id> <title>                 rename a node\n\
         move  <id> <new_parent> [--pos N]   move/reorder a node\n\
         rm    <id>                          delete a node (folders: recursive)\n\
         children [--parent ID] [--limit N] [--offset N]   one page of a folder's children\n\
         \n\
         vault-status                        is there a hidden vault?\n\
         vault-create                        create a vault (phrase on stdin)\n\
         vault-tree                          print the vault tree (phrase on stdin)\n\
         vault-mkdir <title> [--parent ID]   add a hidden folder (phrase on stdin)\n\
         vault-add <title> <url> [--parent ID]   add a hidden bookmark (phrase on stdin)"
    );
}

/// Pull an optional `--flag VALUE` (parsed as i64) out of an arg slice,
/// returning the value and the remaining positional args.
fn take_flag(args: &[String], flag: &str) -> Result<(Option<i64>, Vec<String>), anyhow_lite::Error> {
    let mut value = None;
    let mut rest = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            let v = it
                .next()
                .ok_or_else(|| format!("{flag} requires a value"))?;
            value = Some(v.parse::<i64>().map_err(|_| format!("{flag} value must be a number"))?);
        } else {
            rest.push(a.clone());
        }
    }
    Ok((value, rest))
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

fn cmd_tree() -> anyhow_lite::Result {
    let store = Store::open()?;
    let root = store.tree(false)?;
    print_node(&root, 0);
    Ok(())
}

/// Indented tree print: `<id> [pos] kind title (url)`.
fn print_node(node: &Node, depth: usize) {
    let indent = "  ".repeat(depth);
    match node.kind {
        NodeKind::Folder => println!("{indent}{} [{}] {}/", node.id, node.position, node.title),
        NodeKind::Bookmark => println!(
            "{indent}{} [{}] {} -> {}",
            node.id,
            node.position,
            node.title,
            node.url.as_deref().unwrap_or("")
        ),
    }
    for child in &node.children {
        print_node(child, depth + 1);
    }
}

fn cmd_list() -> anyhow_lite::Result {
    let store = Store::open()?;
    let bookmarks = store.list()?;
    if bookmarks.is_empty() {
        println!("(no bookmarks)");
    }
    for b in &bookmarks {
        println!("{}\t{}\t{}", b.id, b.title, b.url.as_deref().unwrap_or(""));
    }
    Ok(())
}

fn cmd_add(rest: &[String]) -> anyhow_lite::Result {
    let (parent, pos) = take_flag(rest, "--parent")?;
    let (title, url) = match pos.as_slice() {
        [title, url] => (title.clone(), url.clone()),
        _ => return Err("usage: hecate add <title> <url> [--parent ID]".into()),
    };
    let store = Store::open()?;
    let id = store.create_bookmark(parent, &title, &url, now_secs())?;
    println!("added {id}");
    Ok(())
}

fn cmd_mkdir(rest: &[String]) -> anyhow_lite::Result {
    let (parent, pos) = take_flag(rest, "--parent")?;
    let title = match pos.as_slice() {
        [title] => title.clone(),
        _ => return Err("usage: hecate mkdir <title> [--parent ID]".into()),
    };
    let store = Store::open()?;
    let id = store.create_folder(parent, &title, now_secs())?;
    println!("created folder {id}");
    Ok(())
}

fn cmd_rename(rest: &[String]) -> anyhow_lite::Result {
    let (id, title) = match rest {
        [id, title] => (parse_id(id)?, title.clone()),
        _ => return Err("usage: hecate rename <id> <title>".into()),
    };
    let store = Store::open()?;
    store.rename(id, &title, now_secs())?;
    println!("renamed {id}");
    Ok(())
}

fn cmd_move(rest: &[String]) -> anyhow_lite::Result {
    let (position, pos) = take_flag(rest, "--pos")?;
    let (id, new_parent) = match pos.as_slice() {
        [id, parent] => (parse_id(id)?, parse_id(parent)?),
        _ => return Err("usage: hecate move <id> <new_parent> [--pos N]".into()),
    };
    let store = Store::open()?;
    store.move_node(id, new_parent, position, now_secs())?;
    println!("moved {id}");
    Ok(())
}

fn cmd_rm(rest: &[String]) -> anyhow_lite::Result {
    let id = match rest {
        [id] => parse_id(id)?,
        _ => return Err("usage: hecate rm <id>".into()),
    };
    let store = Store::open()?;
    let n = store.delete(id)?;
    println!("deleted {n}");
    Ok(())
}

fn cmd_children(rest: &[String]) -> anyhow_lite::Result {
    let (parent, _) = take_flag(rest, "--parent")?;
    let (limit, r2) = take_flag(rest, "--limit")?;
    let (offset, _) = take_flag(&r2, "--offset")?;
    let store = Store::open()?;
    let (page, total) = store.children(parent, limit.unwrap_or(200), offset.unwrap_or(0))?;
    println!("total {total}");
    for n in &page {
        print_flat(n);
    }
    Ok(())
}

/// Read a secret phrase from stdin (never argv). Trims the trailing newline.
fn read_phrase() -> Result<String, anyhow_lite::Error> {
    use std::io::Read;
    let mut s = String::new();
    io::stdin().read_to_string(&mut s)?;
    let s = s.trim_end_matches(['\n', '\r']).to_string();
    if s.is_empty() {
        return Err("empty phrase on stdin".into());
    }
    Ok(s)
}

fn cmd_vault_status() -> anyhow_lite::Result {
    let store = Store::open()?;
    println!("{}", if vault::exists(store.conn())? { "exists" } else { "none" });
    Ok(())
}

fn cmd_vault_create() -> anyhow_lite::Result {
    let phrase = read_phrase()?;
    let store = Store::open()?;
    vault::create(store.conn(), &phrase)?;
    println!("vault created");
    Ok(())
}

fn cmd_vault_tree() -> anyhow_lite::Result {
    let phrase = read_phrase()?;
    let store = Store::open()?;
    let unlocked = vault::unlock(store.conn(), &phrase)?;
    let root = unlocked.store.tree(true)?;
    print_node(&root, 0);
    Ok(())
}

fn cmd_vault_mkdir(rest: &[String]) -> anyhow_lite::Result {
    let (parent, pos) = take_flag(rest, "--parent")?;
    let title = match pos.as_slice() {
        [title] => title.clone(),
        _ => return Err("usage: hecate vault-mkdir <title> [--parent ID]  (phrase on stdin)".into()),
    };
    let phrase = read_phrase()?;
    let store = Store::open()?;
    let unlocked = vault::unlock(store.conn(), &phrase)?;
    let now = now_secs();
    let id = vault::with_vault_mut(store.conn(), &unlocked.key_b64, |s| {
        s.create_folder(parent, &title, now)
    })?;
    println!("created folder {id}");
    Ok(())
}

fn cmd_vault_add(rest: &[String]) -> anyhow_lite::Result {
    let (parent, pos) = take_flag(rest, "--parent")?;
    let (title, url) = match pos.as_slice() {
        [title, url] => (title.clone(), url.clone()),
        _ => return Err("usage: hecate vault-add <title> <url> [--parent ID]  (phrase on stdin)".into()),
    };
    let phrase = read_phrase()?;
    let store = Store::open()?;
    let unlocked = vault::unlock(store.conn(), &phrase)?;
    let now = now_secs();
    let id = vault::with_vault_mut(store.conn(), &unlocked.key_b64, |s| {
        s.create_bookmark(parent, &title, &url, now)
    })?;
    println!("added {id}");
    Ok(())
}

fn print_flat(n: &Node) {
    match n.kind {
        NodeKind::Folder => println!("{} [{}] {}/", n.id, n.position, n.title),
        NodeKind::Bookmark => println!(
            "{} [{}] {} -> {}",
            n.id,
            n.position,
            n.title,
            n.url.as_deref().unwrap_or("")
        ),
    }
}

fn parse_id(s: &str) -> Result<i64, anyhow_lite::Error> {
    s.parse::<i64>().map_err(|_| format!("invalid id: {s}").into())
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
        if bytes.len() > nm::MAX_OUTGOING {
            // The reply is too big for one native-messaging frame. Don't let it
            // tear down the whole serve loop (which would make the offending
            // folder/vault permanently un-openable on every retry) — reply with
            // a small structured error instead. Pages are byte-budgeted in the
            // store, so this is a last-resort guard (e.g. one node whose own
            // fields exceed the cap).
            let small = serde_json::to_vec(
                &json!({ "ok": false, "error": "reply too large for one message" }),
            )?;
            nm::write_message(&mut stdout, &small)?;
        } else {
            nm::write_message(&mut stdout, &bytes)?;
        }
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
    let now = now_secs();
    match req {
        Request::Tree { include_hidden } => match store.tree(include_hidden) {
            Ok(root) => json!({ "ok": true, "root": root }),
            Err(e) => err(e),
        },
        Request::List => match store.list() {
            Ok(bookmarks) => json!({ "ok": true, "bookmarks": bookmarks }),
            Err(e) => err(e),
        },
        Request::Add {
            title,
            url,
            parent_id,
        } => id_result(store.create_bookmark(parent_id, &title, &url, now)),
        Request::CreateFolder { parent_id, title } => {
            id_result(store.create_folder(parent_id, &title, now))
        }
        Request::CreateBookmark {
            parent_id,
            title,
            url,
        } => id_result(store.create_bookmark(parent_id, &title, &url, now)),
        Request::Rename { id, title } => ok_result(store.rename(id, &title, now)),
        Request::Move {
            id,
            new_parent_id,
            position,
        } => ok_result(store.move_node(id, new_parent_id, position, now)),
        Request::Delete { id } => match store.delete(id) {
            Ok(deleted) => json!({ "ok": true, "deleted": deleted }),
            Err(e) => err(e),
        },
        Request::Children {
            parent_id,
            limit,
            offset,
        } => match store.children(parent_id, limit, offset) {
            Ok((children, total)) => json!({ "ok": true, "children": children, "total": total }),
            Err(e) => err(e),
        },
        Request::Search { query, limit } => match store.search(&query, limit) {
            Ok(results) => json!({ "ok": true, "results": results }),
            Err(e) => err(e),
        },

        // --- hidden vault ---------------------------------------------------
        Request::VaultStatus => match vault::exists(store.conn()) {
            Ok(exists) => json!({ "ok": true, "exists": exists }),
            Err(e) => verr(e),
        },
        Request::VaultCreate { phrase } => match vault::create(store.conn(), &phrase) {
            Ok(key) => json!({ "ok": true, "key": key }),
            Err(e) => verr(e),
        },
        Request::VaultUnlock {
            phrase,
            limit,
            offset,
        } => match vault::unlock(store.conn(), &phrase) {
            Ok(unlocked) => match unlocked.store.children(None, limit, offset) {
                Ok((children, total)) => json!({
                    "ok": true, "key": unlocked.key_b64,
                    "children": children, "total": total,
                }),
                Err(e) => err(e),
            },
            Err(e) => verr(e),
        },
        Request::VaultChildren {
            key,
            parent_id,
            limit,
            offset,
        } => match vault::open_with_key(store.conn(), &key) {
            Ok(vstore) => match vstore.children(parent_id, limit, offset) {
                Ok((children, total)) => {
                    json!({ "ok": true, "children": children, "total": total })
                }
                Err(e) => err(e),
            },
            Err(e) => verr(e),
        },
        Request::VaultCreateFolder {
            key,
            parent_id,
            title,
        } => vid_result(vault::with_vault_mut(store.conn(), &key, |s| {
            s.create_folder(parent_id, &title, now)
        })),
        Request::VaultCreateBookmark {
            key,
            parent_id,
            title,
            url,
        } => vid_result(vault::with_vault_mut(store.conn(), &key, |s| {
            s.create_bookmark(parent_id, &title, &url, now)
        })),
        Request::VaultRename { key, id, title } => {
            vok_result(vault::with_vault_mut(store.conn(), &key, |s| {
                s.rename(id, &title, now)
            }))
        }
        Request::VaultMove {
            key,
            id,
            new_parent_id,
            position,
        } => vok_result(vault::with_vault_mut(store.conn(), &key, |s| {
            s.move_node(id, new_parent_id, position, now)
        })),
        Request::VaultDelete { key, id } => {
            match vault::with_vault_mut(store.conn(), &key, |s| s.delete(id)) {
                Ok(deleted) => json!({ "ok": true, "deleted": deleted }),
                Err(e) => verr(e),
            }
        }
        Request::VaultChangePhrase { key, new_phrase } => {
            match vault::change_phrase(store.conn(), &key, &new_phrase) {
                Ok(new_key) => json!({ "ok": true, "key": new_key }),
                Err(e) => verr(e),
            }
        }
    }
}

fn err(e: store::StoreError) -> Value {
    json!({ "ok": false, "error": e.to_string() })
}

fn verr(e: vault::VaultError) -> Value {
    json!({ "ok": false, "error": e.to_string() })
}

/// A vault mutation returning a new node id.
fn vid_result(r: Result<i64, vault::VaultError>) -> Value {
    match r {
        Ok(id) => json!({ "ok": true, "id": id }),
        Err(e) => verr(e),
    }
}

/// A vault mutation returning nothing.
fn vok_result(r: Result<(), vault::VaultError>) -> Value {
    match r {
        Ok(()) => json!({ "ok": true }),
        Err(e) => verr(e),
    }
}

fn id_result(r: Result<i64, store::StoreError>) -> Value {
    match r {
        Ok(id) => json!({ "ok": true, "id": id }),
        Err(e) => err(e),
    }
}

fn ok_result(r: Result<(), store::StoreError>) -> Value {
    match r {
        Ok(()) => json!({ "ok": true }),
        Err(e) => err(e),
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
