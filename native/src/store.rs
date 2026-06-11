//! SQLite-backed bookmark store. The native app owns this file; it is the
//! single source of truth for all bookmarks AND the only place tree invariants
//! (no cycles, atomic recursive delete, contiguous ordering) are enforced.
//!
//! Folders and bookmarks live in one `nodes` table distinguished by `kind`.
//! There is a single explicit root row (`parent_id IS NULL`) so the top level
//! is just "children of root" and ordering/move/cycle-check/tree-read can treat
//! it like any other folder. (The `hidden`/`enc_blob` columns are vestigial —
//! reserved in an earlier milestone but never populated; hidden content now
//! lives entirely in the separate encrypted `vault` table, see `vault.rs`.)
//!
//! The same `Store` engine backs two databases: the on-disk store, and an
//! ephemeral in-memory copy of a decrypted hidden vault (`from_vault_rows`),
//! which reuses every tree invariant (cycle/depth/reindex) for free.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Current on-disk schema version (PRAGMA user_version). v3 adds the `vault`
/// table; v2 is the `nodes` tree; v1 was the flat `bookmarks` table.
const SCHEMA_VERSION: i64 = 3;

/// The `nodes` tree table + its index. Created standalone (no root seeded) so
/// the vault's in-memory store can build the table and bulk-load its own rows.
const NODES_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS nodes (
    id        INTEGER PRIMARY KEY,
    parent_id INTEGER REFERENCES nodes(id),
    kind      TEXT NOT NULL CHECK (kind IN ('folder','bookmark')),
    title     TEXT NOT NULL,
    url       TEXT,
    position  INTEGER NOT NULL,
    created   INTEGER NOT NULL,
    modified  INTEGER NOT NULL,
    hidden    INTEGER NOT NULL DEFAULT 0,
    enc_blob  BLOB
);
CREATE INDEX IF NOT EXISTS idx_nodes_parent_pos ON nodes(parent_id, position);
";

/// Singleton table holding the one encrypted hidden vault. No row exists until
/// the user creates a vault. `kdf` is a cleartext PHC-style params+salt string
/// (storing the salt/params is standard and consistent with "nothing stored" —
/// there is no key or verifier on disk; security rests on phrase entropy).
const VAULT_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS vault (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    kdf        TEXT NOT NULL,
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    version    INTEGER NOT NULL,
    updated    INTEGER NOT NULL
);
";

/// Maximum folder nesting depth (root = depth 0). The tree is serialized to
/// JSON and dropped recursively (the `Node` struct is recursive by structure),
/// so an unbounded chain of `create_folder`/`move` calls could overflow the
/// stack during `tree()` and crash the host. A generous but bounded cap keeps
/// every recursive sink (serde, Drop, the extension's render/picker walks) safe
/// while being far deeper than any real bookmark hierarchy.
const MAX_DEPTH: i64 = 200;

/// Errors from store operations.
#[derive(Debug)]
pub enum StoreError {
    /// No XDG/OS data directory could be resolved (e.g. HOME unset).
    NoDataDir,
    /// The data directory could not be created.
    Io(std::io::Error),
    /// SQLite failed.
    Sqlite(rusqlite::Error),
    /// No node with this id exists.
    NotFound(i64),
    /// Expected a folder but the node is a bookmark.
    NotAFolder(i64),
    /// A move would make a folder its own ancestor.
    CycleDetected,
    /// A required argument was missing or invalid.
    InvalidArg(String),
    /// Attempted to rename/move/delete the root folder.
    CannotModifyRoot,
    /// The operation would nest folders beyond the maximum allowed depth.
    MaxDepthExceeded,
    /// The store is structurally invalid (e.g. the singleton root is missing).
    CorruptStore(&'static str),
    /// A decrypted vault blob is structurally invalid; refuse to persist it
    /// (would otherwise overwrite recoverable data with a corrupt rewrite).
    CorruptVault(&'static str),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::NoDataDir => write!(
                f,
                "could not resolve a data directory (is HOME/XDG_DATA_HOME set?)"
            ),
            StoreError::Io(e) => write!(f, "creating data directory: {e}"),
            StoreError::Sqlite(e) => write!(f, "database error: {e}"),
            StoreError::NotFound(id) => write!(f, "no node with id {id}"),
            StoreError::NotAFolder(id) => write!(f, "node {id} is not a folder"),
            StoreError::CycleDetected => {
                write!(f, "cannot move a folder into itself or its own descendant")
            }
            StoreError::InvalidArg(m) => write!(f, "{m}"),
            StoreError::CannotModifyRoot => write!(f, "the root folder cannot be modified"),
            StoreError::MaxDepthExceeded => {
                write!(f, "maximum folder nesting depth ({MAX_DEPTH}) exceeded")
            }
            StoreError::CorruptStore(what) => write!(f, "corrupt store: {what}"),
            StoreError::CorruptVault(what) => write!(f, "corrupt vault: {what}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sqlite(e)
    }
}

/// Folder vs bookmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeKind {
    Folder,
    Bookmark,
}

/// A flat node row — the serialization unit for a hidden vault's plaintext.
/// Unlike `Node` (the nested display shape), this carries every column with no
/// omissions, so a vault round-trips byte-for-byte through JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRow {
    pub id: i64,
    pub parent_id: Option<i64>,
    pub kind: NodeKind,
    pub title: String,
    pub url: Option<String>,
    pub position: i64,
    pub created: i64,
    pub modified: i64,
}

/// One tree node, as returned to callers. `children` is populated only by
/// `tree()`; flat reads (`list`) leave it empty (and it is omitted from JSON).
#[derive(Debug, Serialize)]
pub struct Node {
    pub id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<i64>,
    pub kind: NodeKind,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub position: i64,
    pub created: i64,
    pub modified: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<Node>,
}

/// Handle to the open store.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating + migrating if needed) the store at the default location.
    pub fn open() -> Result<Self, StoreError> {
        // Fail loudly rather than silently falling back to the current working
        // directory: under native messaging Chrome picks an arbitrary CWD, and
        // a relative DB would let `serve` and the CLI diverge onto different
        // stores. A resolvable data dir is a hard requirement.
        let path = default_db_path().ok_or(StoreError::NoDataDir)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        Self::from_conn(conn)
    }

    /// Build a store from an existing connection (tests use `:memory:`). Sets
    /// concurrency pragmas and runs schema migrations.
    pub fn from_conn(conn: Connection) -> Result<Self, StoreError> {
        // hecate's whole premise is one store shared by concurrently-open
        // browsers, and each native-messaging request is its own `serve`
        // process — concurrent connections are the normal case. WAL lets
        // readers and a writer coexist; busy_timeout makes a contended write
        // wait-and-retry instead of failing with SQLITE_BUSY. (WAL is a no-op
        // on an in-memory DB.)
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        migrate(&conn)?;
        Ok(Self { conn })
    }

    // --- reads ------------------------------------------------------------

    /// The full nested tree rooted at the singleton root folder. When
    /// `include_hidden` is false, `hidden=1` nodes (and anything only reachable
    /// through them) are omitted.
    pub fn tree(&self, include_hidden: bool) -> Result<Node, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, parent_id, kind, title, url, position, created, modified
             FROM nodes
             WHERE (?1 = 1 OR hidden = 0)
             ORDER BY parent_id, position, id",
        )?;
        let rows = stmt.query_map([include_hidden as i64], |r| {
            Ok((
                r.get::<_, i64>(0)?,                 // id
                r.get::<_, Option<i64>>(1)?,         // parent_id
                row_to_node(r)?,                     // node (children empty)
            ))
        })?;

        // Bucket children by parent in position order, keep nodes by id.
        let mut by_id: HashMap<i64, Node> = HashMap::new();
        let mut children_of: HashMap<Option<i64>, Vec<i64>> = HashMap::new();
        for row in rows {
            let (id, parent_id, node) = row?;
            children_of.entry(parent_id).or_default().push(id);
            by_id.insert(id, node);
        }

        let root_id = *children_of
            .get(&None)
            .and_then(|v| v.first())
            .ok_or(StoreError::CorruptStore("root folder is missing"))?;

        // Defence in depth: the write paths cap nesting at MAX_DEPTH, but a
        // hand-edited / externally-migrated DB could still hold a deeper chain.
        // `assemble` (and serde serialization, and Node's Drop) recurse per
        // level, so reject an over-deep tree HERE — using the already-bucketed
        // maps, iteratively — before building a structure that would overflow
        // the stack on assemble/serialize/drop.
        check_depth(root_id, &children_of)?;
        Ok(assemble(root_id, &mut by_id, &children_of))
    }

    /// Flat list of all bookmark nodes, newest first. Back-compat read for the
    /// v1 popup.
    pub fn list(&self) -> Result<Vec<Node>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, parent_id, kind, title, url, position, created, modified
             FROM nodes WHERE kind = 'bookmark'
             ORDER BY created DESC, id DESC",
        )?;
        let rows = stmt.query_map([], row_to_node)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// One page of a folder's direct children, ordered by `(position, id)`,
    /// plus the total child count. `parent_id` defaults to root. This is the
    /// paginated read that lets the extension lazy-load each folder. The page is
    /// bounded both by item count (the `limit`) AND by serialized bytes (see
    /// `trim_to_byte_budget`) so a folder of fat nodes can't produce a reply
    /// that exceeds the native-messaging cap and tears down the serve loop.
    /// `total` is always the true child count, so the client's "show more"
    /// paging advances even when a page was byte-trimmed. `children` here are
    /// flat (no nested grandchildren).
    pub fn children(
        &self,
        parent_id: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Node>, i64), StoreError> {
        let parent = resolve_parent(&self.conn, parent_id)?;
        ensure_folder(&self.conn, parent)?;
        let total: i64 = self.conn.query_row(
            "SELECT count(*) FROM nodes WHERE parent_id = ?1",
            [parent],
            |r| r.get(0),
        )?;
        // Clamp limit to a sane band so a bad client can't ask for a giant page.
        let limit = limit.clamp(1, 1000);
        let offset = offset.max(0);
        let mut stmt = self.conn.prepare(
            "SELECT id, parent_id, kind, title, url, position, created, modified
             FROM nodes WHERE parent_id = ?1
             ORDER BY position, id
             LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map((parent, limit, offset), row_to_node)?;
        let page = trim_to_byte_budget(rows.collect::<rusqlite::Result<Vec<_>>>()?);
        Ok((page, total))
    }

    /// Flat substring search over bookmark/folder titles and bookmark URLs,
    /// newest-first, capped. Powers the manager's search box. `query` is matched
    /// case-insensitively as a literal substring (LIKE wildcards in the query
    /// are escaped so a user typing `%` searches for a literal percent). The
    /// root row is excluded.
    pub fn search(&self, query: &str, limit: i64) -> Result<Vec<Node>, StoreError> {
        let q = query.trim();
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let pattern = format!("%{}%", escape_like(q));
        let limit = limit.clamp(1, 1000);
        let mut stmt = self.conn.prepare(
            "SELECT id, parent_id, kind, title, url, position, created, modified
             FROM nodes
             WHERE parent_id IS NOT NULL
               AND (title LIKE ?1 ESCAPE '\\' OR (url IS NOT NULL AND url LIKE ?1 ESCAPE '\\'))
             ORDER BY created DESC, id DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map((pattern, limit), row_to_node)?;
        Ok(trim_to_byte_budget(rows.collect::<rusqlite::Result<Vec<_>>>()?))
    }

    /// Borrow the underlying connection (the vault module drives crypto-aware
    /// transactions against the same on-disk database through it).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Consume the store and return its connection (used by vault tests that
    /// want a fully-migrated connection without holding the `Store` wrapper).
    #[cfg(test)]
    pub fn into_conn(self) -> Connection {
        self.conn
    }

    /// Build an ephemeral in-memory store from a decrypted vault's flat row set,
    /// reusing the whole tree-CRUD engine (cycle/depth/reindex invariants) for
    /// the hidden subtree. The rows MUST include the vault's own root row
    /// (`parent_id IS NULL`); no root is auto-seeded here.
    ///
    /// The blob is untrusted on read (a phrase-holder or host bug could produce
    /// a structurally-bad one), so after loading we validate: a single root,
    /// every node reachable from it (no dangling parents / orphan cycles), and
    /// depth within the cap. A corrupt blob is rejected as `CorruptVault` rather
    /// than silently dropping nodes — otherwise the next re-encrypt would
    /// persist the data loss.
    pub fn from_vault_rows(conn: Connection, rows: &[NodeRow]) -> Result<Self, StoreError> {
        conn.execute_batch(NODES_SCHEMA)?;
        // Stamp the version so a stray migrate() on this connection is a no-op
        // and never seeds a second root.
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        // Disable FK enforcement for the bulk load so corruption surfaces as our
        // own typed `CorruptVault` (via the roots-count + reachability checks
        // below) rather than a generic SQLite FK error — deterministic
        // regardless of the build's default_foreign_keys setting. The vault's
        // tree invariants (cycle/depth/reindex) are enforced in app code, not
        // by FKs, so this doesn't weaken later mutations.
        conn.pragma_update(None, "foreign_keys", false)?;
        {
            let tx = rusqlite::Transaction::new_unchecked(
                &conn,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            let mut roots = 0;
            for r in rows {
                if r.parent_id.is_none() {
                    roots += 1;
                    // The root must be a folder — every write path enforces this
                    // via ensure_folder, so a bookmark-root means a corrupt blob.
                    if r.kind != NodeKind::Folder {
                        return Err(StoreError::CorruptVault("vault root must be a folder"));
                    }
                }
                let kind = match r.kind {
                    NodeKind::Folder => "folder",
                    NodeKind::Bookmark => "bookmark",
                };
                tx.execute(
                    "INSERT INTO nodes (id, parent_id, kind, title, url, position, created, modified, hidden)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
                    (
                        r.id,
                        r.parent_id,
                        kind,
                        &r.title,
                        &r.url,
                        r.position,
                        r.created,
                        r.modified,
                    ),
                )
                .map_err(dup_id_is_corrupt)?;
            }
            if roots != 1 {
                return Err(StoreError::CorruptVault("vault must have exactly one root"));
            }
            tx.commit()?;
        }
        let store = Self { conn };
        // Reachability + depth validation: tree() walks from the root applying
        // check_depth and the cycle guards. A bad structure here means the
        // decrypted blob is corrupt (only a phrase-holder or a host bug can
        // reach this) — normalize EVERY structural failure to CorruptVault so
        // the caller treats it uniformly and never re-encrypts/persists it
        // (which would destroy recoverable data). tree() returning e.g.
        // MaxDepthExceeded or CorruptStore("root missing") becomes CorruptVault.
        let tree = match store.tree(true) {
            Ok(t) => t,
            Err(StoreError::Sqlite(e)) => return Err(StoreError::Sqlite(e)),
            Err(_) => return Err(StoreError::CorruptVault("vault tree is structurally invalid")),
        };
        let reachable = count_nodes(&tree);
        if reachable != rows.len() {
            return Err(StoreError::CorruptVault(
                "vault has unreachable nodes (dangling parent or orphan cycle)",
            ));
        }
        Ok(store)
    }

    /// Dump every node as a flat row set (for re-encrypting a vault). Ordered by
    /// id for a deterministic blob.
    pub fn dump_rows(&self) -> Result<Vec<NodeRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, parent_id, kind, title, url, position, created, modified
             FROM nodes ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            let kind_str: String = r.get(2)?;
            Ok(NodeRow {
                id: r.get(0)?,
                parent_id: r.get(1)?,
                kind: if kind_str == "folder" {
                    NodeKind::Folder
                } else {
                    NodeKind::Bookmark
                },
                title: r.get(3)?,
                url: r.get(4)?,
                position: r.get(5)?,
                created: r.get(6)?,
                modified: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // --- writes -----------------------------------------------------------

    /// Begin a write transaction with `BEGIN IMMEDIATE` so the write lock is
    /// acquired up front. Under WAL a deferred (lazy) transaction that upgrades
    /// a read snapshot to a write returns `SQLITE_BUSY` *immediately* — the
    /// `busy_timeout` does not retry that upgrade. Taking the write lock at
    /// BEGIN means contended writers wait-and-retry instead of erroring with
    /// "database is locked". Each native-messaging request is its own process,
    /// so concurrent writers are the normal case.
    fn write_txn(&self) -> rusqlite::Result<rusqlite::Transaction<'_>> {
        // `new_unchecked` is the `&self`-compatible constructor (the same one
        // `unchecked_transaction` uses) but here with Immediate behavior rather
        // than its Deferred default — so it issues `BEGIN IMMEDIATE` and rolls
        // back on drop unless committed.
        rusqlite::Transaction::new_unchecked(
            &self.conn,
            rusqlite::TransactionBehavior::Immediate,
        )
    }

    /// Create a folder under `parent_id` (default: root). Returns the new id.
    pub fn create_folder(
        &self,
        parent_id: Option<i64>,
        title: &str,
        now: i64,
    ) -> Result<i64, StoreError> {
        require_nonempty(title, "title")?;
        let tx = self.write_txn()?;
        let parent = resolve_parent(&tx, parent_id)?;
        ensure_folder(&tx, parent)?;
        // A new folder sits one level below its parent; bound the chain so the
        // recursive tree serialization can't overflow the stack.
        if depth_of(&tx, parent)? + 1 > MAX_DEPTH {
            return Err(StoreError::MaxDepthExceeded);
        }
        let pos = next_position(&tx, parent)?;
        tx.execute(
            "INSERT INTO nodes (parent_id, kind, title, url, position, created, modified, hidden)
             VALUES (?1, 'folder', ?2, NULL, ?3, ?4, ?4, 0)",
            (parent, title, pos, now),
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// Create a bookmark under `parent_id` (default: root). Returns the new id.
    pub fn create_bookmark(
        &self,
        parent_id: Option<i64>,
        title: &str,
        url: &str,
        now: i64,
    ) -> Result<i64, StoreError> {
        require_nonempty(title, "title")?;
        require_nonempty(url, "url")?;
        let tx = self.write_txn()?;
        let parent = resolve_parent(&tx, parent_id)?;
        ensure_folder(&tx, parent)?;
        // A bookmark lands one level below its parent. Guard it like folders do:
        // without this, a bookmark under a max-depth folder reaches depth
        // MAX_DEPTH+1, which tree()'s read-side check_depth then rejects for the
        // WHOLE store — bricking every reader until the row is removed by hand.
        if depth_of(&tx, parent)? + 1 > MAX_DEPTH {
            return Err(StoreError::MaxDepthExceeded);
        }
        let pos = next_position(&tx, parent)?;
        tx.execute(
            "INSERT INTO nodes (parent_id, kind, title, url, position, created, modified, hidden)
             VALUES (?1, 'bookmark', ?2, ?3, ?4, ?5, ?5, 0)",
            (parent, title, url, pos, now),
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// Rename any node (not the root).
    pub fn rename(&self, id: i64, title: &str, now: i64) -> Result<(), StoreError> {
        require_nonempty(title, "title")?;
        let tx = self.write_txn()?;
        if node_parent(&tx, id)?.is_none() {
            return Err(StoreError::CannotModifyRoot);
        }
        tx.execute(
            "UPDATE nodes SET title = ?1, modified = ?2 WHERE id = ?3",
            (title, now, id),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Move `id` under `new_parent_id`, optionally at `position` (default:
    /// append). Reparents and reorders in one transaction; rejects cycles.
    pub fn move_node(
        &self,
        id: i64,
        new_parent_id: i64,
        position: Option<i64>,
        now: i64,
    ) -> Result<(), StoreError> {
        let tx = self.write_txn()?;

        // Must exist and not be the root.
        let old_parent = match node_parent(&tx, id)? {
            None => return Err(StoreError::CannotModifyRoot),
            Some(p) => p,
        };
        ensure_folder(&tx, new_parent_id)?;
        // Cycle check covers the self-move case (is_descendant(id, id) == true).
        if is_descendant(&tx, id, new_parent_id)? {
            return Err(StoreError::CycleDetected);
        }
        // Reject a move that would push the moved subtree's deepest node past
        // the nesting cap (its leaves land at new_parent depth + 1 + height).
        if depth_of(&tx, new_parent_id)? + 1 + subtree_height(&tx, id)? > MAX_DEPTH {
            return Err(StoreError::MaxDepthExceeded);
        }

        // Rebuild the destination's child ordering with `id` inserted at the
        // clamped target index. Excludes `id` first so same-folder reorder works.
        let mut siblings: Vec<i64> = {
            let mut stmt = tx.prepare(
                "SELECT id FROM nodes WHERE parent_id = ?1 AND id <> ?2 ORDER BY position, id",
            )?;
            let v: Vec<i64> = stmt
                .query_map((new_parent_id, id), |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            v
        };
        let len = siblings.len() as i64;
        let idx = position.unwrap_or(len).clamp(0, len) as usize;
        siblings.insert(idx, id);

        tx.execute(
            "UPDATE nodes SET parent_id = ?1, modified = ?2 WHERE id = ?3",
            (new_parent_id, now, id),
        )?;
        for (i, nid) in siblings.iter().enumerate() {
            tx.execute(
                "UPDATE nodes SET position = ?1 WHERE id = ?2",
                (i as i64, nid),
            )?;
        }
        if old_parent != new_parent_id {
            reindex(&tx, old_parent)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Delete a node and (if it is a folder) its whole subtree. Returns the
    /// number of nodes removed. Rejects deleting the root.
    pub fn delete(&self, id: i64) -> Result<u64, StoreError> {
        let tx = self.write_txn()?;
        let parent = match node_parent(&tx, id)? {
            None => return Err(StoreError::CannotModifyRoot),
            Some(p) => p,
        };
        let ids = collect_subtree_ids(&tx, id)?;
        // Delete deepest-first so this stays correct even if foreign-key
        // enforcement is ever turned on.
        for nid in ids.iter().rev() {
            tx.execute("DELETE FROM nodes WHERE id = ?1", [nid])?;
        }
        reindex(&tx, parent)?;
        tx.commit()?;
        Ok(ids.len() as u64)
    }
}

// --- free helpers ---------------------------------------------------------

/// Read the common node columns from a `SELECT id, parent_id, kind, title, url,
/// position, created, modified` row. `children` starts empty.
fn row_to_node(r: &rusqlite::Row<'_>) -> rusqlite::Result<Node> {
    let kind_str: String = r.get(2)?;
    Ok(Node {
        id: r.get(0)?,
        parent_id: r.get(1)?,
        kind: if kind_str == "folder" {
            NodeKind::Folder
        } else {
            NodeKind::Bookmark
        },
        title: r.get(3)?,
        url: r.get(4)?,
        position: r.get(5)?,
        created: r.get(6)?,
        modified: r.get(7)?,
        children: Vec::new(),
    })
}

/// Reject a tree whose nesting exceeds `MAX_DEPTH`, walked iteratively over the
/// already-bucketed children map (root = depth 0). Guards `tree()` against
/// pre-existing/corrupt data that the write-path cap never saw.
fn check_depth(
    root: i64,
    children_of: &HashMap<Option<i64>, Vec<i64>>,
) -> Result<(), StoreError> {
    // (node, depth) stack; depth bounded so a corrupt cycle can't loop forever.
    let mut stack = vec![(root, 0i64)];
    while let Some((id, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Err(StoreError::MaxDepthExceeded);
        }
        if let Some(kids) = children_of.get(&Some(id)) {
            for &k in kids {
                stack.push((k, depth + 1));
            }
        }
    }
    Ok(())
}

/// Attach children (in stored order) to build the nested tree, bottom-up and
/// iteratively — no recursion, so an arbitrarily deep tree can't blow the stack.
fn assemble(
    root: i64,
    by_id: &mut HashMap<i64, Node>,
    children_of: &HashMap<Option<i64>, Vec<i64>>,
) -> Node {
    // DFS pushing children; reversing yields an order where every node appears
    // after all its descendants, so each node's children are already built when
    // we reach it.
    let mut order = Vec::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        order.push(id);
        if let Some(kids) = children_of.get(&Some(id)) {
            stack.extend(kids.iter().copied());
        }
    }
    order.reverse();

    let mut built: HashMap<i64, Node> = HashMap::new();
    for id in order {
        let mut node = by_id.remove(&id).expect("id present by construction");
        if let Some(kids) = children_of.get(&Some(id)) {
            for &k in kids {
                if let Some(child) = built.remove(&k) {
                    node.children.push(child);
                }
            }
        }
        built.insert(id, node);
    }
    built.remove(&root).expect("root present by construction")
}

/// Count every node in a nested tree (root included), iteratively. Used to
/// verify a loaded vault has no unreachable rows.
fn count_nodes(root: &Node) -> usize {
    let mut n = 0;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        n += 1;
        for child in &node.children {
            stack.push(child);
        }
    }
    n
}

/// Resolve an optional parent to a concrete id, defaulting to the root.
fn resolve_parent(conn: &Connection, parent_id: Option<i64>) -> Result<i64, StoreError> {
    match parent_id {
        Some(p) => Ok(p),
        None => root_id(conn),
    }
}

fn root_id(conn: &Connection) -> Result<i64, StoreError> {
    conn.query_row("SELECT id FROM nodes WHERE parent_id IS NULL", [], |r| {
        r.get(0)
    })
    .map_err(StoreError::from)
}

/// The node's parent id: `Ok(None)` for the root, `Err(NotFound)` if missing.
fn node_parent(conn: &Connection, id: i64) -> Result<Option<i64>, StoreError> {
    conn.query_row("SELECT parent_id FROM nodes WHERE id = ?1", [id], |r| {
        r.get::<_, Option<i64>>(0)
    })
    .optional()?
    .ok_or(StoreError::NotFound(id))
}

/// Error unless `id` exists and is a folder.
fn ensure_folder(conn: &Connection, id: i64) -> Result<(), StoreError> {
    let kind: Option<String> = conn
        .query_row("SELECT kind FROM nodes WHERE id = ?1", [id], |r| r.get(0))
        .optional()?;
    match kind.as_deref() {
        None => Err(StoreError::NotFound(id)),
        Some("folder") => Ok(()),
        Some(_) => Err(StoreError::NotAFolder(id)),
    }
}

/// Next sort index at the end of `parent_id`'s children.
fn next_position(conn: &Connection, parent_id: i64) -> Result<i64, StoreError> {
    conn.query_row(
        "SELECT COALESCE(MAX(position) + 1, 0) FROM nodes WHERE parent_id = ?1",
        [parent_id],
        |r| r.get(0),
    )
    .map_err(StoreError::from)
}

/// Compact a folder's children back to contiguous 0..n-1 in their current order.
fn reindex(conn: &Connection, parent_id: i64) -> Result<(), StoreError> {
    let ids: Vec<i64> = {
        let mut stmt =
            conn.prepare("SELECT id FROM nodes WHERE parent_id = ?1 ORDER BY position, id")?;
        let v: Vec<i64> = stmt
            .query_map([parent_id], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        v
    };
    for (i, id) in ids.iter().enumerate() {
        conn.execute("UPDATE nodes SET position = ?1 WHERE id = ?2", (i as i64, id))?;
    }
    Ok(())
}

/// True if `candidate` is `ancestor` itself or sits somewhere below it.
/// Iterative walk up the parent chain — no recursion, safe on deep trees.
fn is_descendant(conn: &Connection, ancestor: i64, candidate: i64) -> Result<bool, StoreError> {
    let mut cur = Some(candidate);
    let mut guard = 0u64;
    while let Some(c) = cur {
        if c == ancestor {
            return Ok(true);
        }
        guard += 1;
        if guard > 1_000_000 {
            // Corrupt cycle in the data itself; bail rather than spin forever.
            return Err(StoreError::CycleDetected);
        }
        cur = conn
            .query_row("SELECT parent_id FROM nodes WHERE id = ?1", [c], |r| {
                r.get::<_, Option<i64>>(0)
            })
            .optional()?
            .flatten();
    }
    Ok(false)
}

/// Depth of `id` measured from the root (root = 0). Iterative parent walk.
fn depth_of(conn: &Connection, id: i64) -> Result<i64, StoreError> {
    let mut cur = Some(id);
    let mut depth = -1; // becomes 0 once we count `id` itself
    let mut guard = 0i64;
    while let Some(c) = cur {
        depth += 1;
        guard += 1;
        if guard > MAX_DEPTH * 4 {
            // Far past any legitimate depth — treat as corrupt and refuse.
            return Err(StoreError::MaxDepthExceeded);
        }
        cur = conn
            .query_row("SELECT parent_id FROM nodes WHERE id = ?1", [c], |r| {
                r.get::<_, Option<i64>>(0)
            })
            .optional()?
            .flatten();
    }
    Ok(depth)
}

/// Height of the subtree rooted at `id`: 0 for a leaf, else 1 + max child
/// height. Iterative (BFS by level) so a deep subtree can't overflow the stack.
fn subtree_height(conn: &Connection, id: i64) -> Result<i64, StoreError> {
    let mut level = vec![id];
    let mut height = -1i64;
    let mut stmt = conn.prepare("SELECT id FROM nodes WHERE parent_id = ?1")?;
    while !level.is_empty() {
        height += 1;
        if height > MAX_DEPTH * 4 {
            return Err(StoreError::MaxDepthExceeded);
        }
        let mut next = Vec::new();
        for p in level {
            let children: Vec<i64> = stmt
                .query_map([p], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            next.extend(children);
        }
        level = next;
    }
    Ok(height)
}

/// All ids in the subtree rooted at `id`, `id` first (BFS). Iterative, with a
/// visited set so a corrupt non-root `parent_id` cycle (only possible in a
/// hand-edited/externally-migrated DB — the API's move cycle-check prevents it,
/// and FKs aren't enforced) terminates cleanly instead of looping forever and
/// OOMing the host. Matches the defensive posture of the other tree walkers.
fn collect_subtree_ids(conn: &Connection, id: i64) -> Result<Vec<i64>, StoreError> {
    use std::collections::HashSet;
    let mut seen: HashSet<i64> = HashSet::new();
    let mut out = Vec::new();
    let mut queue = vec![id];
    let mut stmt = conn.prepare("SELECT id FROM nodes WHERE parent_id = ?1")?;
    while let Some(p) = queue.pop() {
        if !seen.insert(p) {
            continue; // already visited — corrupt cycle, don't recurse again
        }
        out.push(p);
        let children: Vec<i64> = stmt
            .query_map([p], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        queue.extend(children);
    }
    Ok(out)
}

/// Map a SQLite constraint violation (e.g. a duplicate `id` in a vault blob)
/// to `CorruptVault`, leaving genuine I/O errors as `Sqlite`. Keeps every
/// structural defect in a decrypted blob in the single uniform corrupt class.
fn dup_id_is_corrupt(e: rusqlite::Error) -> StoreError {
    match e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            StoreError::CorruptVault("duplicate node id in vault")
        }
        other => StoreError::Sqlite(other),
    }
}

/// Trim a page so its serialized JSON stays under the native-messaging reply
/// cap. Pagination caps by item *count* (limit≤1000), but titles/urls are
/// unbounded, so a page of fat nodes can still blow Chrome's 1 MB cap and tear
/// down the serve loop — leaving that folder permanently un-openable. Bound the
/// page by actual serialized *bytes*: measure each node's real JSON length
/// (`serde_json` escapes strings — a control byte becomes `\u00XX`, 6×, so a
/// raw-length estimate is NOT a safe upper bound) and stop before the running
/// size would exceed a budget that leaves headroom under the cap for the reply
/// envelope. Always keep at least one node so the client's `loaded < total`
/// paging still advances; a single node larger than the budget is the accepted,
/// unavoidable "giant single node" case (handled by serve()'s oversize guard).
fn trim_to_byte_budget(nodes: Vec<Node>) -> Vec<Node> {
    // ~768 KiB leaves comfortable headroom under the 1 MiB cap for the wrapping
    // `{"ok":true,"children":[...],"total":N}` envelope (and vault_unlock's
    // extra `key` field) plus per-node comma separators.
    const BUDGET: usize = 768 * 1024;
    let mut total = 0usize;
    let mut out = Vec::with_capacity(nodes.len());
    for node in nodes {
        // Measure the ACTUAL serialized size (accounts for JSON string
        // escaping). +1 for the comma joining it to the previous element.
        let sz = serde_json::to_vec(&node).map(|v| v.len()).unwrap_or(usize::MAX) + 1;
        if !out.is_empty() && total + sz > BUDGET {
            break;
        }
        total += sz;
        out.push(node);
    }
    out
}

/// Escape SQL LIKE metacharacters (`%`, `_`, and the `\` escape char itself)
/// so a search query is matched literally rather than as a wildcard pattern.
fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' || c == '%' || c == '_' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn require_nonempty(s: &str, what: &str) -> Result<(), StoreError> {
    if s.trim().is_empty() {
        Err(StoreError::InvalidArg(format!("{what} must not be empty")))
    } else {
        Ok(())
    }
}

/// Bring the database schema up to the current version (`SCHEMA_VERSION`).
///
/// - fresh DB: create `nodes` + root + `vault` table, stamp version 3.
/// - legacy v1 (flat `bookmarks` table): create `nodes` + root, copy bookmarks
///   in as children of root preserving created-order, drop `bookmarks`.
/// - v2 (`nodes` only): additively create the `vault` table.
///
/// Wrapped in one transaction so a crash leaves the prior version intact, and
/// `user_version` makes it idempotent under concurrent `serve` processes.
fn migrate(conn: &Connection) -> Result<(), StoreError> {
    // Cheap pre-check outside the lock to skip the common already-migrated case.
    if conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))? >= SCHEMA_VERSION {
        return Ok(());
    }

    let now = migration_now();
    // IMMEDIATE so the write lock is held from the start — concurrent first-run
    // processes serialize cleanly instead of racing the WAL upgrade.
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;

    // Re-read the version INSIDE the transaction. A concurrent process may have
    // migrated between the pre-check and acquiring the write lock; re-checking
    // here makes the second process a clean no-op.
    if tx.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))? >= SCHEMA_VERSION {
        return Ok(());
    }
    let has_bookmarks: bool = tx.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='bookmarks'",
        [],
        |r| r.get::<_, i64>(0),
    )? > 0;

    // Idempotent CREATE IF NOT EXISTS for both tables covers fresh, v2→v3, and
    // partially-migrated databases.
    tx.execute_batch(NODES_SCHEMA)?;
    tx.execute_batch(VAULT_SCHEMA)?;

    // Find the existing root, or create one. Do NOT hard-code id=1 for the
    // insert: a corrupt/hand-edited DB could have no root yet already occupy
    // id=1 with some other row, and `VALUES (1, ...)` would hit a UNIQUE
    // violation and brick the store on every run. Let SQLite assign the id and
    // read it back — the rest of the code finds the root by `parent_id IS NULL`,
    // never by a hard-coded id, so any assigned id is fine. (Same "never wedge
    // the store" posture as the malformed-legacy-row salvage below.)
    let root_id: i64 = match tx
        .query_row("SELECT id FROM nodes WHERE parent_id IS NULL", [], |r| r.get(0))
        .optional()?
    {
        Some(id) => id,
        None => {
            tx.execute(
                "INSERT INTO nodes (parent_id, kind, title, url, position, created, modified, hidden)
                 VALUES (NULL, 'folder', 'hecate', NULL, 0, ?1, ?1, 0)",
                [now],
            )?;
            tx.last_insert_rowid()
        }
    };

    if has_bookmarks {
        // Copy old flat bookmarks under root, preserving order; new ids (old
        // ids were never referenced externally). Be defensive about malformed
        // legacy rows: the genuine v1 schema was NOT NULL on title/url, but an
        // externally-corrupted DB with a NULL title/url would otherwise abort
        // the whole migration and brick the store on every retry. COALESCE a
        // bad row to a placeholder rather than failing hard — never lose data
        // we can salvage, and never wedge the store.
        // Append after any children the root already has (normally none on the
        // real v1 path, so base = 0; nonzero only on a hand-edited DB that has
        // both a `nodes` tree and a leftover `bookmarks` table — append rather
        // than collide on position 0).
        let base: i64 = tx.query_row(
            "SELECT COALESCE(MAX(position) + 1, 0) FROM nodes WHERE parent_id = ?1",
            [root_id],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO nodes (parent_id, kind, title, url, position, created, modified, hidden)
             SELECT ?1, 'bookmark',
                    COALESCE(NULLIF(title, ''), '(untitled)'),
                    COALESCE(url, ''),
                    ?2 + row_number() OVER (ORDER BY created, id) - 1,
                    COALESCE(created, 0), COALESCE(created, 0), 0
             FROM bookmarks",
            (root_id, base),
        )?;
        tx.execute("DROP TABLE bookmarks", [])?;
    }

    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(())
}

/// Timestamp for migration-created rows. Not a deterministic-test path (tests
/// assert structure, not migration timestamps).
fn migration_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `~/.local/share/hecate/hecate.db` (via the XDG/OS data dir). `None` if no
/// data dir can be resolved — callers must treat that as an error.
fn default_db_path() -> Option<PathBuf> {
    Some(dirs::data_dir()?.join("hecate").join("hecate.db"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_store() -> Store {
        Store::from_conn(Connection::open_in_memory().unwrap()).unwrap()
    }

    /// id of the single root folder.
    fn root(s: &Store) -> i64 {
        root_id(&s.conn).unwrap()
    }

    #[test]
    fn fresh_db_has_root_only() {
        let s = mem_store();
        let t = s.tree(false).unwrap();
        assert_eq!(t.parent_id, None);
        assert_eq!(t.kind, NodeKind::Folder);
        assert!(t.children.is_empty());
    }

    #[test]
    fn add_then_list_roundtrips() {
        let s = mem_store();
        let id = s.create_bookmark(None, "Rust", "https://rust-lang.org", 100).unwrap();
        assert!(id > 0);
        let all = s.list().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].title, "Rust");
        assert_eq!(all[0].url.as_deref(), Some("https://rust-lang.org"));
    }

    #[test]
    fn list_is_newest_first() {
        let s = mem_store();
        s.create_bookmark(None, "old", "https://a.example", 100).unwrap();
        s.create_bookmark(None, "new", "https://b.example", 200).unwrap();
        let all = s.list().unwrap();
        assert_eq!(all[0].title, "new");
        assert_eq!(all[1].title, "old");
    }

    #[test]
    fn nested_create_and_tree() {
        let s = mem_store();
        let r = root(&s);
        let work = s.create_folder(Some(r), "work", 1).unwrap();
        let sub = s.create_folder(Some(work), "sub", 2).unwrap();
        s.create_bookmark(Some(sub), "deep", "https://deep.example", 3)
            .unwrap();
        s.create_bookmark(Some(r), "top", "https://top.example", 4)
            .unwrap();

        let t = s.tree(false).unwrap();
        assert_eq!(t.children.len(), 2); // work, top
        let work_node = t.children.iter().find(|n| n.title == "work").unwrap();
        assert_eq!(work_node.children.len(), 1);
        assert_eq!(work_node.children[0].title, "sub");
        assert_eq!(work_node.children[0].children[0].title, "deep");
    }

    #[test]
    fn create_under_bookmark_is_not_a_folder() {
        let s = mem_store();
        let bm = s.create_bookmark(None, "b", "https://b.example", 1).unwrap();
        let err = s.create_folder(Some(bm), "x", 2).unwrap_err();
        assert!(matches!(err, StoreError::NotAFolder(id) if id == bm));
    }

    #[test]
    fn create_under_missing_parent_is_not_found() {
        let s = mem_store();
        let err = s.create_bookmark(Some(9999), "x", "https://x.example", 1).unwrap_err();
        assert!(matches!(err, StoreError::NotFound(9999)));
    }

    #[test]
    fn empty_title_and_url_rejected() {
        let s = mem_store();
        assert!(matches!(
            s.create_folder(None, "  ", 1).unwrap_err(),
            StoreError::InvalidArg(_)
        ));
        assert!(matches!(
            s.create_bookmark(None, "t", "", 1).unwrap_err(),
            StoreError::InvalidArg(_)
        ));
    }

    #[test]
    fn positions_are_contiguous_after_delete() {
        let s = mem_store();
        let r = root(&s);
        let a = s.create_bookmark(Some(r), "a", "https://a.example", 1).unwrap();
        let b = s.create_bookmark(Some(r), "b", "https://b.example", 2).unwrap();
        let c = s.create_bookmark(Some(r), "c", "https://c.example", 3).unwrap();
        // positions 0,1,2
        let _ = (a, c);
        s.delete(b).unwrap();
        let t = s.tree(false).unwrap();
        let positions: Vec<i64> = t.children.iter().map(|n| n.position).collect();
        assert_eq!(positions, vec![0, 1]);
        let titles: Vec<&str> = t.children.iter().map(|n| n.title.as_str()).collect();
        assert_eq!(titles, vec!["a", "c"]);
    }

    #[test]
    fn move_reparents_and_reorders() {
        let s = mem_store();
        let r = root(&s);
        let f = s.create_folder(Some(r), "f", 1).unwrap();
        let a = s.create_bookmark(Some(r), "a", "https://a.example", 2).unwrap();
        let b = s.create_bookmark(Some(r), "b", "https://b.example", 3).unwrap();
        // Move a into f at position 0.
        s.move_node(a, f, Some(0), 10).unwrap();
        let t = s.tree(false).unwrap();
        let f_node = t.children.iter().find(|n| n.id == f).unwrap();
        assert_eq!(f_node.children.len(), 1);
        assert_eq!(f_node.children[0].id, a);
        // root now has f(0), b(1) contiguous.
        assert!(t.children.iter().any(|n| n.id == b && n.position == 1));
    }

    #[test]
    fn move_same_folder_excludes_then_inserts() {
        // Documents the exact semantics the manager's drag-reorder math relies
        // on: move_node removes the node from the destination ordering FIRST,
        // then inserts at the given position. So for siblings [A,B,C,D], moving
        // A to position 2 yields [B,C,A,D] — NOT [B,A,C,D]. The JS compensates
        // for downward same-folder drags by decrementing the target index.
        let s = mem_store();
        let r = root(&s);
        let a = s.create_bookmark(Some(r), "A", "https://a.example", 1).unwrap();
        let b = s.create_bookmark(Some(r), "B", "https://b.example", 2).unwrap();
        let c = s.create_bookmark(Some(r), "C", "https://c.example", 3).unwrap();
        let d = s.create_bookmark(Some(r), "D", "https://d.example", 4).unwrap();
        let _ = (b, c, d);
        s.move_node(a, r, Some(2), 10).unwrap();
        let t = s.tree(false).unwrap();
        let order: Vec<&str> = t.children.iter().map(|n| n.title.as_str()).collect();
        assert_eq!(order, vec!["B", "C", "A", "D"]);
    }

    #[test]
    fn move_into_own_descendant_is_cycle() {
        let s = mem_store();
        let r = root(&s);
        let a = s.create_folder(Some(r), "a", 1).unwrap();
        let b = s.create_folder(Some(a), "b", 2).unwrap();
        let c = s.create_folder(Some(b), "c", 3).unwrap();
        assert!(matches!(
            s.move_node(a, c, None, 4).unwrap_err(),
            StoreError::CycleDetected
        ));
        assert!(matches!(
            s.move_node(a, a, None, 5).unwrap_err(),
            StoreError::CycleDetected
        ));
        // Valid: move c up to root.
        s.move_node(c, r, None, 6).unwrap();
        assert!(s.tree(false).unwrap().children.iter().any(|n| n.id == c));
    }

    #[test]
    fn delete_folder_is_recursive() {
        let s = mem_store();
        let r = root(&s);
        let f = s.create_folder(Some(r), "f", 1).unwrap();
        let g = s.create_folder(Some(f), "g", 2).unwrap();
        s.create_bookmark(Some(g), "deep", "https://deep.example", 3).unwrap();
        s.create_bookmark(Some(f), "shallow", "https://shallow.example", 4).unwrap();
        let count = s.delete(f).unwrap();
        assert_eq!(count, 4); // f, g, deep, shallow
        let t = s.tree(false).unwrap();
        assert!(t.children.is_empty());
        // No orphans (every non-root node reaches a real parent).
        let orphans: i64 = s
            .conn
            .query_row(
                "SELECT count(*) FROM nodes WHERE parent_id IS NOT NULL
                 AND parent_id NOT IN (SELECT id FROM nodes)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphans, 0);
    }

    #[test]
    fn root_cannot_be_modified() {
        let s = mem_store();
        let r = root(&s);
        assert!(matches!(
            s.rename(r, "x", 1).unwrap_err(),
            StoreError::CannotModifyRoot
        ));
        assert!(matches!(s.delete(r).unwrap_err(), StoreError::CannotModifyRoot));
        let f = s.create_folder(Some(r), "f", 2).unwrap();
        assert!(matches!(
            s.move_node(r, f, None, 3).unwrap_err(),
            StoreError::CannotModifyRoot
        ));
    }

    #[test]
    fn rename_changes_title() {
        let s = mem_store();
        let r = root(&s);
        let f = s.create_folder(Some(r), "old", 1).unwrap();
        s.rename(f, "new", 2).unwrap();
        let t = s.tree(false).unwrap();
        assert_eq!(t.children[0].title, "new");
    }

    #[test]
    fn duplicate_sibling_names_allowed() {
        let s = mem_store();
        let r = root(&s);
        s.create_folder(Some(r), "dup", 1).unwrap();
        s.create_folder(Some(r), "dup", 2).unwrap();
        let t = s.tree(false).unwrap();
        assert_eq!(t.children.len(), 2);
    }

    #[test]
    fn deep_tree_does_not_overflow() {
        // Build right up to the nesting cap; the iterative walks (is_descendant,
        // assemble) and serialization must all stay safe at max depth.
        let s = mem_store();
        let mut parent = root(&s);
        let mut first_child = None;
        for i in 0..super::MAX_DEPTH {
            parent = s.create_folder(Some(parent), &format!("d{i}"), i).unwrap();
            if first_child.is_none() {
                first_child = Some(parent);
            }
        }
        // Cycle check walks the whole chain; must not stack-overflow.
        assert!(matches!(
            s.move_node(first_child.unwrap(), parent, None, 1).unwrap_err(),
            StoreError::CycleDetected
        ));
        // tree() assembles the whole chain to exactly MAX_DEPTH levels.
        let t = s.tree(false).unwrap();
        let mut n = &t;
        let mut depth = 0;
        while let Some(child) = n.children.first() {
            n = child;
            depth += 1;
        }
        assert_eq!(depth as i64, super::MAX_DEPTH);
    }

    #[test]
    fn migrates_legacy_v1_bookmarks() {
        let conn = Connection::open_in_memory().unwrap();
        // Recreate a v1-shaped db with rows and no user_version.
        conn.execute_batch(
            "CREATE TABLE bookmarks (
                 id INTEGER PRIMARY KEY, parent_id INTEGER,
                 title TEXT NOT NULL, url TEXT NOT NULL, created INTEGER NOT NULL);
             INSERT INTO bookmarks (parent_id, title, url, created)
                 VALUES (NULL, 'first', 'https://1.example', 100),
                        (NULL, 'second', 'https://2.example', 200);",
        )
        .unwrap();
        let s = Store::from_conn(conn).unwrap();
        let t = s.tree(false).unwrap();
        assert_eq!(t.title, "hecate");
        assert_eq!(t.children.len(), 2);
        // created order preserved (first then second), contiguous positions.
        assert_eq!(t.children[0].title, "first");
        assert_eq!(t.children[0].position, 0);
        assert_eq!(t.children[1].title, "second");
        assert_eq!(t.children[1].position, 1);
        // Old table is gone.
        let n: i64 = s
            .conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='bookmarks'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn concurrent_writers_do_not_deadlock() {
        // Regression: a deferred (lazy) WAL transaction upgrading a read to a
        // write returns SQLITE_BUSY immediately, which busy_timeout does NOT
        // retry — concurrent `serve` processes then failed with "database is
        // locked". write_txn uses BEGIN IMMEDIATE to take the lock up front so
        // contended writers wait-and-retry. Separate connections to one file
        // (mimics the per-request process model).
        let dir = std::env::temp_dir().join(format!("hecate_conc_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.db");
        let _ = std::fs::remove_file(&path);
        // Initialise once (migration), then hammer with several threads.
        Store::from_conn(Connection::open(&path).unwrap()).unwrap();

        let threads: Vec<_> = (0..8)
            .map(|t| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let s = Store::from_conn(Connection::open(&path).unwrap()).unwrap();
                    for i in 0..10 {
                        s.create_bookmark(None, &format!("t{t}-{i}"), "https://x.example", 0)
                            .expect("concurrent write must not fail with database is locked");
                    }
                })
            })
            .collect();
        for th in threads {
            th.join().unwrap();
        }

        let s = Store::from_conn(Connection::open(&path).unwrap()).unwrap();
        assert_eq!(s.tree(false).unwrap().children.len(), 80);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migrate_is_idempotent_when_repeated() {
        // Deterministic guard: migrate() must be a clean no-op once the DB is at
        // the current version — re-running it must not re-insert bookmarks or
        // error on the already-dropped `bookmarks` table. (The concurrency
        // hardening — reading `has_bookmarks` inside the write txn — also relies
        // on this version gate; see `concurrent_legacy_migration_stress`.)
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE bookmarks (
                 id INTEGER PRIMARY KEY, parent_id INTEGER,
                 title TEXT NOT NULL, url TEXT NOT NULL, created INTEGER NOT NULL);
             INSERT INTO bookmarks (parent_id, title, url, created)
                 VALUES (NULL, 'a', 'https://a.example', 1),
                        (NULL, 'b', 'https://b.example', 2);",
        )
        .unwrap();
        migrate(&conn).unwrap();
        // Second and third calls must be no-ops, not errors or duplications.
        migrate(&conn).unwrap();
        migrate(&conn).unwrap();
        let s = Store { conn };
        assert_eq!(s.tree(false).unwrap().children.len(), 2);
    }

    #[test]
    fn folder_nesting_is_capped() {
        // Regression: the Node tree is serialized/dropped recursively, so an
        // unbounded folder chain could overflow the stack during tree(). Depth
        // is capped; tree() must stay safe right at the limit.
        let s = mem_store();
        let mut parent = root(&s);
        // root is depth 0; folders may go to depth MAX_DEPTH.
        for i in 0..super::MAX_DEPTH {
            parent = s.create_folder(Some(parent), &format!("d{i}"), i).unwrap();
        }
        // One more folder would exceed the cap.
        assert!(matches!(
            s.create_folder(Some(parent), "too-deep", 0).unwrap_err(),
            StoreError::MaxDepthExceeded
        ));
        // A BOOKMARK under the deepest folder would also land at MAX_DEPTH+1.
        // It must be rejected too — otherwise it commits and then tree()'s
        // read-side check_depth rejects the whole store (bricking all readers).
        assert!(matches!(
            s.create_bookmark(Some(parent), "too-deep", "https://x.example", 0)
                .unwrap_err(),
            StoreError::MaxDepthExceeded
        ));
        // tree() still works at max depth (no overflow, not bricked).
        assert!(s.tree(false).is_ok());
    }

    #[test]
    fn tree_rejects_pre_existing_overdeep_data() {
        // The write-path cap doesn't see hand-edited/externally-migrated data.
        // Insert a chain far deeper than MAX_DEPTH directly, bypassing the cap,
        // then confirm tree() returns a typed error instead of stack-overflowing
        // during assemble/serialize.
        let s = mem_store();
        let r = root(&s);
        let mut parent = r;
        for i in 0..(super::MAX_DEPTH + 50) {
            s.conn
                .execute(
                    "INSERT INTO nodes (parent_id, kind, title, url, position, created, modified, hidden)
                     VALUES (?1, 'folder', ?2, NULL, 0, 0, 0, 0)",
                    (parent, format!("d{i}")),
                )
                .unwrap();
            parent = s.conn.last_insert_rowid();
        }
        assert!(matches!(
            s.tree(false).unwrap_err(),
            StoreError::MaxDepthExceeded
        ));
    }

    #[test]
    fn delete_terminates_on_corrupt_parent_cycle() {
        // A hand-edited/corrupt DB can hold a non-root parent_id cycle the API
        // would never create. delete() walks the subtree; without a visited set
        // it would loop forever and OOM the host. It must terminate.
        let s = mem_store();
        let r = root(&s);
        let a = s.create_folder(Some(r), "a", 1).unwrap();
        let b = s.create_folder(Some(a), "b", 2).unwrap();
        // Force a mutual cycle a <-> b directly. FK enforcement would reject
        // this, but an external editor (sqlite3 CLI, FKs off by default) can
        // write exactly this corruption to disk — disable FKs to mimic that.
        s.conn.pragma_update(None, "foreign_keys", false).unwrap();
        s.conn
            .execute("UPDATE nodes SET parent_id = ?1 WHERE id = ?2", (b, a))
            .unwrap();
        // delete must terminate (not hang/OOM); the visited set caps the walk
        // at the two distinct nodes.
        let n = s.delete(a).unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn move_respecting_depth_cap() {
        // Moving a subtree must be rejected if its deepest node would land past
        // the cap.
        let s = mem_store();
        let r = root(&s);
        // Build a chain of depth MAX_DEPTH under root.
        let mut parent = r;
        let mut first = None;
        for i in 0..super::MAX_DEPTH {
            parent = s.create_folder(Some(parent), &format!("d{i}"), i).unwrap();
            if first.is_none() {
                first = Some(parent);
            }
        }
        // A separate one-level folder at top level.
        let other = s.create_folder(Some(r), "other", 0).unwrap();
        // Moving the whole deep chain (rooted at `first`, height MAX_DEPTH-1)
        // under `other` (depth 1) would exceed the cap.
        assert!(matches!(
            s.move_node(first.unwrap(), other, None, 0).unwrap_err(),
            StoreError::MaxDepthExceeded
        ));
    }

    #[test]
    fn migration_survives_malformed_legacy_rows() {
        // A corrupt/hand-edited v1 DB with NULL title/url must not abort the
        // whole migration (which would brick the store on every retry). Bad
        // rows are salvaged to placeholders.
        let conn = Connection::open_in_memory().unwrap();
        // No NOT NULL constraints here so we can insert the malformed rows the
        // guard defends against.
        conn.execute_batch(
            "CREATE TABLE bookmarks (
                 id INTEGER PRIMARY KEY, parent_id INTEGER,
                 title TEXT, url TEXT, created INTEGER);
             INSERT INTO bookmarks (parent_id, title, url, created)
                 VALUES (NULL, 'ok', 'https://ok.example', 1),
                        (NULL, NULL, NULL, NULL),
                        (NULL, '', '', 3);",
        )
        .unwrap();
        migrate(&conn).unwrap();
        let s = Store { conn };
        let t = s.tree(false).unwrap();
        assert_eq!(t.children.len(), 3);
        // Both the NULL-title and empty-string-title rows are salvaged to the
        // placeholder, not dropped, left blank, or fatal.
        assert_eq!(t.children.iter().filter(|n| n.title == "(untitled)").count(), 2);
    }

    #[test]
    fn migration_survives_missing_root_with_id1_occupied() {
        // A corrupt/hand-edited DB at an older version with NO root row but with
        // id=1 already taken by a non-root node must NOT brick on migrate: the
        // root insert no longer hard-codes id=1 (which would UNIQUE-violate and
        // abort every run). The root is seeded with an assigned id and found by
        // `parent_id IS NULL`.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(NODES_SCHEMA).unwrap();
        // Mimic external corruption (sqlite3 CLI, FKs off by default): a non-root
        // node squatting on id=1 whose parent points nowhere, and no NULL-parent
        // root, pre-v3.
        conn.pragma_update(None, "foreign_keys", false).unwrap();
        conn.execute(
            "INSERT INTO nodes (id, parent_id, kind, title, url, position, created, modified, hidden)
             VALUES (1, 99, 'bookmark', 'orphan', 'https://x', 0, 0, 0, 0)",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 2).unwrap();
        // Must not error/brick.
        migrate(&conn).unwrap();
        // A real root now exists (with parent_id NULL), at some assigned id != 1.
        let s = Store { conn };
        let root = root_id(&s.conn).unwrap();
        assert_ne!(root, 1);
        assert_eq!(s.conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0)).unwrap(), 3);
    }

    #[test]
    fn legacy_copy_appends_after_existing_children() {
        // A hand-edited DB with BOTH a populated `nodes` tree AND a leftover
        // `bookmarks` table: the migrated legacy rows must append after the
        // existing children, not collide on position 0.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(NODES_SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO nodes (id, parent_id, kind, title, url, position, created, modified, hidden)
             VALUES (1, NULL, 'folder', 'hecate', NULL, 0, 0, 0, 0),
                    (2, 1, 'bookmark', 'existing', 'https://e', 0, 0, 0, 0)",
            [],
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TABLE bookmarks (
                 id INTEGER PRIMARY KEY, parent_id INTEGER,
                 title TEXT, url TEXT, created INTEGER);
             INSERT INTO bookmarks (parent_id, title, url, created)
                 VALUES (NULL, 'legacy1', 'https://l1', 1);",
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 2).unwrap();
        migrate(&conn).unwrap();
        let s = Store { conn };
        let t = s.tree(false).unwrap();
        let positions: Vec<i64> = t.children.iter().map(|n| n.position).collect();
        // Contiguous, no collision: existing at 0, legacy appended at 1.
        assert_eq!(positions, vec![0, 1]);
        assert_eq!(t.children.iter().filter(|n| n.position == 0).count(), 1);
    }

    #[test]
    fn concurrent_legacy_migration_stress() {
        // Stress (not deterministic-teeth) check: many processes opening the
        // SAME legacy v1 DB at once must all succeed — exercises the real
        // migrate() concurrency path. The underlying fix (read `has_bookmarks`
        // INSIDE the write txn, re-check version after taking the lock) is
        // correct by construction; this race is too tight to reproduce
        // deterministically on a small DB, so this guards against gross
        // regressions rather than serving as a strict teeth test.
        let dir = std::env::temp_dir().join(format!("hecate_mig_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("m.db");
        let _ = std::fs::remove_file(&path);

        // A real v1 store is already in WAL (milestone-1 set it) and the
        // installer migrates single-threaded via `hecate init`; set WAL here so
        // the test exercises migration-logic contention, not the one-time
        // journal-mode conversion (which is never raced in production).
        {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "journal_mode", "WAL").unwrap();
            conn.execute_batch(
                "CREATE TABLE bookmarks (
                     id INTEGER PRIMARY KEY, parent_id INTEGER,
                     title TEXT NOT NULL, url TEXT NOT NULL, created INTEGER NOT NULL);
                 INSERT INTO bookmarks (parent_id, title, url, created)
                     VALUES (NULL, 'a', 'https://a.example', 1),
                            (NULL, 'b', 'https://b.example', 2);",
            )
            .unwrap();
        }

        const N: usize = 8;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(N));
        let threads: Vec<_> = (0..N)
            .map(|_| {
                let conn = Connection::open(&path).unwrap();
                conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    migrate(&conn).expect("concurrent migration must not fail");
                })
            })
            .collect();
        for th in threads {
            th.join().unwrap();
        }

        // Migrated exactly once: the two legacy bookmarks under root, no dupes.
        let s = Store::from_conn(Connection::open(&path).unwrap()).unwrap();
        assert_eq!(s.tree(false).unwrap().children.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn children_paginates() {
        let s = mem_store();
        let r = root(&s);
        for i in 0..10 {
            s.create_bookmark(Some(r), &format!("b{i}"), "https://x.example", i)
                .unwrap();
        }
        let (page, total) = s.children(None, 3, 0).unwrap();
        assert_eq!(total, 10);
        assert_eq!(page.len(), 3);
        // Stable position order: first page is positions 0,1,2.
        assert_eq!(
            page.iter().map(|n| n.position).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        // Offset slices correctly; last partial page.
        let (page2, _) = s.children(None, 3, 9).unwrap();
        assert_eq!(page2.len(), 1);
        assert_eq!(page2[0].position, 9);
        // Out-of-range offset → empty page, total still accurate.
        let (empty, total2) = s.children(None, 3, 100).unwrap();
        assert!(empty.is_empty());
        assert_eq!(total2, 10);
        // Limit is clamped, not honoured verbatim, but never errors.
        let (big, _) = s.children(None, 999_999, 0).unwrap();
        assert_eq!(big.len(), 10);
    }

    #[test]
    fn search_matches_title_and_url_literally() {
        let s = mem_store();
        let r = root(&s);
        s.create_bookmark(Some(r), "Rust lang", "https://rust-lang.org", 1).unwrap();
        s.create_folder(Some(r), "Reading", 2).unwrap();
        s.create_bookmark(Some(r), "fifty %off", "https://deals.example", 3).unwrap();

        // Title substring, case-insensitive.
        let hits = s.search("rust", 50).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title, "Rust lang");
        // URL substring.
        assert_eq!(s.search("deals.example", 50).unwrap().len(), 1);
        // Folder titles match too.
        assert_eq!(s.search("read", 50).unwrap().len(), 1);
        // `%` is a literal, not a wildcard: matches only the "fifty %off" row,
        // not everything.
        let pct = s.search("%off", 50).unwrap();
        assert_eq!(pct.len(), 1);
        assert_eq!(pct[0].title, "fifty %off");
        // A high-entropy phrase that matches nothing → empty (the unlock
        // fall-through relies on this).
        assert!(s.search("correct horse battery staple xyzzy", 50).unwrap().is_empty());
        // Empty query → empty, never the whole tree.
        assert!(s.search("   ", 50).unwrap().is_empty());
    }

    #[test]
    fn children_page_is_byte_bounded() {
        // 200 fat bookmarks (~8 KB title each) would serialize to ~1.6 MB and
        // blow the native-messaging cap. The page must be byte-trimmed to fit,
        // while `total` still reports the true count so paging advances.
        let s = mem_store();
        let r = root(&s);
        let big = "x".repeat(8 * 1024);
        for i in 0..200 {
            s.create_bookmark(Some(r), &format!("{big}{i}"), "https://x.example", i)
                .unwrap();
        }
        let (page, total) = s.children(None, 1000, 0).unwrap();
        assert_eq!(total, 200, "total must be the true count");
        assert!(page.len() < 200, "page must be trimmed below the full count");
        assert!(!page.is_empty(), "must keep at least one node so paging advances");
        // The serialized page comfortably fits the 1 MiB cap.
        let bytes = serde_json::to_vec(&page).unwrap();
        assert!(bytes.len() < 1024 * 1024, "page serialized to {} bytes", bytes.len());
    }

    #[test]
    fn children_byte_budget_accounts_for_json_escaping() {
        // A raw-length estimate is unsound: serde escapes a control byte to
        // `\u00XX` (6x). Titles of control chars must still produce a page whose
        // ACTUAL serialized size fits the cap — the trim measures real bytes.
        let s = mem_store();
        let r = root(&s);
        // 4 KB of NUL bytes per title → ~24 KB serialized each (  = 6 bytes).
        let ctrl = "\u{0}".repeat(4 * 1024);
        for i in 0..1000 {
            s.create_bookmark(Some(r), &format!("{ctrl}{i}"), "https://x.example", i)
                .unwrap();
        }
        let (page, total) = s.children(None, 1000, 0).unwrap();
        assert_eq!(total, 1000);
        assert!(!page.is_empty());
        let bytes = serde_json::to_vec(&page).unwrap();
        assert!(
            bytes.len() < 1024 * 1024,
            "escaped page serialized to {} bytes — over the cap",
            bytes.len()
        );
    }

    #[test]
    fn children_keeps_one_oversize_node() {
        // A single node larger than the byte budget is still returned (the
        // accepted "giant single node" case) so the folder isn't un-openable.
        let s = mem_store();
        let r = root(&s);
        let huge = "y".repeat(900 * 1024);
        s.create_bookmark(Some(r), &huge, "https://x.example", 1).unwrap();
        let (page, total) = s.children(None, 1000, 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(page.len(), 1);
    }

    #[test]
    fn children_only_direct() {
        // children() returns one level, not the whole subtree.
        let s = mem_store();
        let r = root(&s);
        let f = s.create_folder(Some(r), "f", 1).unwrap();
        s.create_bookmark(Some(f), "deep", "https://d.example", 2).unwrap();
        let (page, total) = s.children(Some(r), 200, 0).unwrap();
        assert_eq!(total, 1); // just `f`, not `deep`
        assert_eq!(page[0].title, "f");
        assert!(page[0].children.is_empty()); // flat, no nested grandchildren
    }

    #[test]
    fn from_vault_rows_roundtrips_and_rejects_corruption() {
        // A clean flat row set loads and dumps back identically.
        let rows = vec![
            NodeRow { id: 1, parent_id: None, kind: NodeKind::Folder, title: "Hidden".into(), url: None, position: 0, created: 0, modified: 0 },
            NodeRow { id: 2, parent_id: Some(1), kind: NodeKind::Bookmark, title: "b".into(), url: Some("https://b.example".into()), position: 0, created: 0, modified: 0 },
        ];
        let s = Store::from_vault_rows(Connection::open_in_memory().unwrap(), &rows).unwrap();
        assert_eq!(s.tree(true).unwrap().children.len(), 1);
        assert_eq!(s.dump_rows().unwrap().len(), 2);

        // No root → corrupt.
        let no_root = vec![NodeRow { id: 2, parent_id: Some(1), kind: NodeKind::Bookmark, title: "x".into(), url: Some("https://x".into()), position: 0, created: 0, modified: 0 }];
        assert!(matches!(
            Store::from_vault_rows(Connection::open_in_memory().unwrap(), &no_root),
            Err(StoreError::CorruptVault(_))
        ));

        // Dangling parent (unreachable node) → corrupt, not silently dropped.
        let dangling = vec![
            NodeRow { id: 1, parent_id: None, kind: NodeKind::Folder, title: "Hidden".into(), url: None, position: 0, created: 0, modified: 0 },
            NodeRow { id: 2, parent_id: Some(999), kind: NodeKind::Bookmark, title: "orphan".into(), url: Some("https://o".into()), position: 0, created: 0, modified: 0 },
        ];
        assert!(matches!(
            Store::from_vault_rows(Connection::open_in_memory().unwrap(), &dangling),
            Err(StoreError::CorruptVault(_))
        ));

        // Two roots → corrupt.
        let two_roots = vec![
            NodeRow { id: 1, parent_id: None, kind: NodeKind::Folder, title: "A".into(), url: None, position: 0, created: 0, modified: 0 },
            NodeRow { id: 2, parent_id: None, kind: NodeKind::Folder, title: "B".into(), url: None, position: 0, created: 0, modified: 0 },
        ];
        assert!(matches!(
            Store::from_vault_rows(Connection::open_in_memory().unwrap(), &two_roots),
            Err(StoreError::CorruptVault(_))
        ));

        // Over-deep chain → CorruptVault (NOT MaxDepthExceeded): every
        // structural failure in a decrypted blob must normalize to one corrupt
        // class so the caller never re-persists it.
        let mut deep = vec![NodeRow { id: 1, parent_id: None, kind: NodeKind::Folder, title: "Hidden".into(), url: None, position: 0, created: 0, modified: 0 }];
        for i in 0..(MAX_DEPTH + 5) {
            deep.push(NodeRow { id: i + 2, parent_id: Some(i + 1), kind: NodeKind::Folder, title: format!("d{i}"), url: None, position: 0, created: 0, modified: 0 });
        }
        assert!(matches!(
            Store::from_vault_rows(Connection::open_in_memory().unwrap(), &deep),
            Err(StoreError::CorruptVault(_))
        ));

        // Duplicate id → CorruptVault, not a raw Sqlite UNIQUE error.
        let dup = vec![
            NodeRow { id: 1, parent_id: None, kind: NodeKind::Folder, title: "Hidden".into(), url: None, position: 0, created: 0, modified: 0 },
            NodeRow { id: 2, parent_id: Some(1), kind: NodeKind::Bookmark, title: "a".into(), url: Some("https://a".into()), position: 0, created: 0, modified: 0 },
            NodeRow { id: 2, parent_id: Some(1), kind: NodeKind::Bookmark, title: "b".into(), url: Some("https://b".into()), position: 1, created: 0, modified: 0 },
        ];
        assert!(matches!(
            Store::from_vault_rows(Connection::open_in_memory().unwrap(), &dup),
            Err(StoreError::CorruptVault(_))
        ));

        // A bookmark as the root → CorruptVault (root must be a folder).
        let bm_root = vec![NodeRow { id: 1, parent_id: None, kind: NodeKind::Bookmark, title: "x".into(), url: Some("https://x".into()), position: 0, created: 0, modified: 0 }];
        assert!(matches!(
            Store::from_vault_rows(Connection::open_in_memory().unwrap(), &bm_root),
            Err(StoreError::CorruptVault(_))
        ));
    }
}
