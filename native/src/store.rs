//! SQLite-backed bookmark store. The native app owns this file; it is the
//! single source of truth for all bookmarks AND the only place tree invariants
//! (no cycles, atomic recursive delete, contiguous ordering) are enforced.
//!
//! Folders and bookmarks live in one `nodes` table distinguished by `kind`.
//! There is a single explicit root row (`parent_id IS NULL`) so the top level
//! is just "children of root" and ordering/move/cycle-check/tree-read can treat
//! it like any other folder. `hidden`/`enc_blob` columns are reserved for the
//! later hidden-encrypted-folder milestone and are never populated here.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

const SCHEMA: &str = "
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeKind {
    Folder,
    Bookmark,
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

fn require_nonempty(s: &str, what: &str) -> Result<(), StoreError> {
    if s.trim().is_empty() {
        Err(StoreError::InvalidArg(format!("{what} must not be empty")))
    } else {
        Ok(())
    }
}

/// Bring the database schema up to the current version.
///
/// - fresh DB: create `nodes` + root, stamp version 2.
/// - legacy v1 (flat `bookmarks` table): create `nodes` + root, copy bookmarks
///   in as children of root preserving created-order, drop `bookmarks`.
///
/// Wrapped in one transaction so a crash leaves the prior version intact, and
/// `user_version` makes it idempotent under concurrent `serve` processes.
fn migrate(conn: &Connection) -> Result<(), StoreError> {
    // Cheap pre-check outside the lock to skip the common already-migrated case.
    if conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))? >= 2 {
        return Ok(());
    }

    let now = migration_now();
    // IMMEDIATE so the write lock is held from the start — concurrent first-run
    // processes serialize cleanly instead of racing the WAL upgrade.
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;

    // Re-read the version INSIDE the transaction. A concurrent process may have
    // migrated (and dropped `bookmarks`) between the pre-check and acquiring the
    // write lock; re-checking here makes the second process a clean no-op
    // instead of running INSERT/DROP against a table that's already gone.
    if tx.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))? >= 2 {
        return Ok(());
    }
    let has_bookmarks: bool = tx.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='bookmarks'",
        [],
        |r| r.get::<_, i64>(0),
    )? > 0;

    tx.execute_batch(SCHEMA)?;

    let root_exists: bool = tx.query_row(
        "SELECT count(*) FROM nodes WHERE parent_id IS NULL",
        [],
        |r| r.get::<_, i64>(0),
    )? > 0;
    if !root_exists {
        tx.execute(
            "INSERT INTO nodes (id, parent_id, kind, title, url, position, created, modified, hidden)
             VALUES (1, NULL, 'folder', 'hecate', NULL, 0, ?1, ?1, 0)",
            [now],
        )?;
    }

    if has_bookmarks {
        // Copy old flat bookmarks under root, preserving order; new ids (old
        // ids were never referenced externally). Be defensive about malformed
        // legacy rows: the genuine v1 schema was NOT NULL on title/url, but an
        // externally-corrupted DB with a NULL title/url would otherwise abort
        // the whole migration and brick the store on every retry. COALESCE a
        // bad row to a placeholder rather than failing hard — never lose data
        // we can salvage, and never wedge the store.
        tx.execute(
            "INSERT INTO nodes (parent_id, kind, title, url, position, created, modified, hidden)
             SELECT 1, 'bookmark',
                    COALESCE(NULLIF(title, ''), '(untitled)'),
                    COALESCE(url, ''),
                    row_number() OVER (ORDER BY created, id) - 1,
                    COALESCE(created, 0), COALESCE(created, 0), 0
             FROM bookmarks",
            [],
        )?;
        tx.execute("DROP TABLE bookmarks", [])?;
    }

    tx.pragma_update(None, "user_version", 2)?;
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
}
