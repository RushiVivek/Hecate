//! SQLite-backed bookmark store. The native app owns this file; it is the
//! single source of truth for all bookmarks.
//!
//! v1 slice: a single flat `bookmarks` table. Folder nesting and encrypted
//! hidden folders are deliberately out of scope here (see the plan).

use std::fmt;
use std::path::PathBuf;

use rusqlite::Connection;
use serde::Serialize;

/// Errors opening the store.
#[derive(Debug)]
pub enum StoreError {
    /// No XDG/OS data directory could be resolved (e.g. HOME unset).
    NoDataDir,
    /// The data directory could not be created.
    Io(std::io::Error),
    /// SQLite failed to open or initialise the database.
    Sqlite(rusqlite::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::NoDataDir => write!(
                f,
                "could not resolve a data directory (is HOME/XDG_DATA_HOME set?)"
            ),
            StoreError::Io(e) => write!(f, "creating data directory: {e}"),
            StoreError::Sqlite(e) => write!(f, "opening database: {e}"),
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

/// One stored bookmark, as returned to callers (CLI and native-messaging).
#[derive(Debug, Serialize)]
pub struct Bookmark {
    pub id: i64,
    pub title: String,
    pub url: String,
    pub created: i64,
}

/// Handle to the open store.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if needed) the store at the default location and ensure
    /// the schema exists.
    pub fn open() -> Result<Self, StoreError> {
        // Fail loudly rather than silently falling back to the current working
        // directory: under native messaging Chrome picks an arbitrary CWD, and
        // a relative DB would let `serve` and the CLI diverge onto different
        // stores. A resolvable data dir is a hard requirement.
        let path = default_db_path().ok_or(StoreError::NoDataDir)?;
        if let Some(parent) = path.parent() {
            // The data dir may not exist on first run.
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        Ok(Self::from_conn(conn)?)
    }

    /// Build a store from an existing connection (used by tests with `:memory:`).
    pub fn from_conn(conn: Connection) -> rusqlite::Result<Self> {
        // The whole point of hecate is one store shared by concurrently-open
        // browsers, and each native-messaging request is its own `serve`
        // process — so multiple connections hitting this file at once is the
        // normal case, not an edge case. WAL lets readers and a writer coexist;
        // busy_timeout makes a contended write wait-and-retry instead of
        // failing immediately with SQLITE_BUSY ("database is locked").
        // (On an in-memory test DB, journal_mode=WAL is a harmless no-op.)
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bookmarks (
                 id        INTEGER PRIMARY KEY,
                 parent_id INTEGER,
                 title     TEXT NOT NULL,
                 url       TEXT NOT NULL,
                 created   INTEGER NOT NULL
             );",
        )?;
        Ok(Self { conn })
    }

    /// Insert a bookmark, returning its new row id.
    pub fn add(&self, title: &str, url: &str, now: i64) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO bookmarks (parent_id, title, url, created)
             VALUES (NULL, ?1, ?2, ?3)",
            (title, url, now),
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// All bookmarks, newest first.
    pub fn list(&self) -> rusqlite::Result<Vec<Bookmark>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, title, url, created FROM bookmarks ORDER BY created DESC, id DESC")?;
        let rows = stmt.query_map([], |row| {
            Ok(Bookmark {
                id: row.get(0)?,
                title: row.get(1)?,
                url: row.get(2)?,
                created: row.get(3)?,
            })
        })?;
        rows.collect()
    }
}

/// `~/.local/share/hecate/hecate.db` (via the XDG/OS data dir). Returns `None`
/// if no data dir can be resolved — callers must treat that as an error rather
/// than guessing a relative path.
fn default_db_path() -> Option<PathBuf> {
    Some(dirs::data_dir()?.join("hecate").join("hecate.db"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_store() -> Store {
        Store::from_conn(Connection::open_in_memory().unwrap()).unwrap()
    }

    #[test]
    fn add_then_list_roundtrips() {
        let s = mem_store();
        let id = s.add("Rust", "https://rust-lang.org", 100).unwrap();
        assert!(id > 0);
        let all = s.list().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].title, "Rust");
        assert_eq!(all[0].url, "https://rust-lang.org");
        assert_eq!(all[0].created, 100);
    }

    #[test]
    fn list_is_newest_first() {
        let s = mem_store();
        s.add("old", "https://a.example", 100).unwrap();
        s.add("new", "https://b.example", 200).unwrap();
        let all = s.list().unwrap();
        assert_eq!(all[0].title, "new");
        assert_eq!(all[1].title, "old");
    }
}
