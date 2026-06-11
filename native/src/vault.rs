//! Hidden encrypted vault — the one secret-folder subtree.
//!
//! Security model (LOCKED, "model b"): the secret phrase IS the key. Nothing
//! that can recover the data is stored — no key, no verifier. A phrase is run
//! through Argon2id (with a stored, cleartext salt + params) to derive a
//! 32-byte key; the whole hidden subtree is serialized to JSON and sealed with
//! XChaCha20-Poly1305 (AEAD, random 24-byte nonce per write). Only the
//! encrypted blob, the nonce, and the KDF params/salt live on disk.
//!
//! Consequences, by design (documented for the user — see README):
//!   * Forget the phrase → the vault is unrecoverable. No escrow.
//!   * Offline-brute-forceable: a disk holder has salt+params+ciphertext, i.e.
//!     a complete offline verifier. The only defense is phrase entropy ×
//!     Argon2id cost. Use a real high-entropy passphrase.
//!   * KEY-OVER-THE-WIRE: `unlock` returns the derived key to the caller (the
//!     extension page holds it in JS memory for its session). This was chosen
//!     deliberately over a persistent key-holding daemon. The security ceiling
//!     is therefore "the browser JS heap is trusted"; a live attacker on the
//!     unlocked page sees the key and plaintext. Host-side `Zeroizing` is
//!     hygiene, not a boundary, because the key copy in JS can't be scrubbed.
//!
//! Wrong phrase, no-vault, and corrupt-blob all surface as the SAME
//! `WrongPhraseOrCorrupt` error *text*, so the reveal box gives no content
//! oracle. Note this is not a constant-TIME guarantee: a wrong phrase against
//! an existing vault runs the full Argon2id (~hundreds of ms) while "no vault"
//! returns immediately, so vault *existence* is observable by latency. That is
//! acceptable here because existence is already non-secret in this model — the
//! `vault_status` op reports it directly and the singleton `vault` table
//! betrays it on disk. What stays hidden without the phrase is the vault's
//! *contents*, which is the property that matters.

use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::store::{NodeRow, Store, StoreError};

/// Plaintext-format version byte (bound into the AEAD associated data).
const FORMAT_VERSION: u8 = 1;

/// Argon2id cost parameters. Targets ~250–500 ms on a typical laptop. Stored in
/// the `kdf` string so they can be reproduced and so future tuning can raise
/// them without breaking old vaults.
const ARGON_M_COST_KIB: u32 = 64 * 1024; // 64 MiB
const ARGON_T_COST: u32 = 3;
const ARGON_P_COST: u32 = 1;
const SALT_LEN: usize = 16;

/// How many times to retry the optimistic-concurrency write before giving up.
const MAX_WRITE_RETRIES: u32 = 8;

#[derive(Debug)]
pub enum VaultError {
    /// Wrong phrase, no vault, or a corrupt/tampered blob — deliberately
    /// indistinguishable so the reveal box leaks nothing.
    WrongPhraseOrCorrupt,
    /// A vault already exists (on create).
    AlreadyExists,
    /// The caller supplied a malformed key (bad base64 / wrong length).
    BadKey,
    /// The decrypted blob is structurally invalid as a tree.
    Corrupt(&'static str),
    /// Too many concurrent writers; the optimistic retry budget was exhausted.
    Contended,
    /// Underlying store/SQLite error.
    Store(StoreError),
    /// KDF / crypto-library failure (not an auth failure).
    Crypto(&'static str),
    /// Bad argument from the caller.
    InvalidArg(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Uniform message — no oracle distinguishing the three causes.
            VaultError::WrongPhraseOrCorrupt => write!(f, "could not unlock the vault"),
            VaultError::AlreadyExists => write!(f, "a hidden vault already exists"),
            VaultError::BadKey => write!(f, "invalid vault key"),
            VaultError::Corrupt(m) => write!(f, "vault corrupt: {m}"),
            VaultError::Contended => write!(f, "vault busy, please retry"),
            VaultError::Store(e) => write!(f, "{e}"),
            VaultError::Crypto(m) => write!(f, "crypto error: {m}"),
            VaultError::InvalidArg(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<StoreError> for VaultError {
    fn from(e: StoreError) -> Self {
        match e {
            // A structurally-bad decrypted blob is a corrupt vault, not a store
            // bug. Surface it as such so we never persist over recoverable data.
            StoreError::CorruptVault(m) => VaultError::Corrupt(m),
            other => VaultError::Store(other),
        }
    }
}

impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        VaultError::Store(StoreError::Sqlite(e))
    }
}

/// The decrypted vault plaintext: a flat row set including the vault's own root.
#[derive(Debug, Serialize, Deserialize)]
struct VaultPlaintext {
    v: u8,
    nodes: Vec<NodeRow>,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Does a vault exist on disk? (Reveals only existence, which the singleton
/// table betrays anyway — not a secret in this model.)
pub fn exists(conn: &Connection) -> Result<bool, VaultError> {
    let n: i64 = conn.query_row("SELECT count(*) FROM vault WHERE id = 1", [], |r| r.get(0))?;
    Ok(n > 0)
}

/// Build the `kdf` cleartext string: `argon2id$v=19$m=..,t=..,p=..$<b64 salt>`.
fn kdf_string(salt: &[u8]) -> String {
    format!(
        "argon2id$v=19$m={ARGON_M_COST_KIB},t={ARGON_T_COST},p={ARGON_P_COST}${}",
        B64.encode(salt)
    )
}

/// Parse a `kdf` string back into (salt, Argon2 params). Strict: anything
/// unexpected → corrupt.
fn parse_kdf(kdf: &str) -> Result<(Vec<u8>, Params), VaultError> {
    // argon2id$v=19$m=..,t=..,p=..$<b64 salt>
    let parts: Vec<&str> = kdf.split('$').collect();
    if parts.len() != 4 || parts[0] != "argon2id" || parts[1] != "v=19" {
        return Err(VaultError::WrongPhraseOrCorrupt);
    }
    let mut m = None;
    let mut t = None;
    let mut p = None;
    for kv in parts[2].split(',') {
        let (k, v) = kv.split_once('=').ok_or(VaultError::WrongPhraseOrCorrupt)?;
        let n: u32 = v.parse().map_err(|_| VaultError::WrongPhraseOrCorrupt)?;
        match k {
            "m" => m = Some(n),
            "t" => t = Some(n),
            "p" => p = Some(n),
            _ => return Err(VaultError::WrongPhraseOrCorrupt),
        }
    }
    let salt = B64
        .decode(parts[3])
        .map_err(|_| VaultError::WrongPhraseOrCorrupt)?;
    // Argon2 itself rejects a salt < 8 bytes with a *distinct* error; reject it
    // here so a disk-tampered/too-short salt funnels through the one uniform
    // WrongPhraseOrCorrupt rather than leaking a different "crypto error" text.
    if salt.len() < 8 {
        return Err(VaultError::WrongPhraseOrCorrupt);
    }
    let m = m.ok_or(VaultError::WrongPhraseOrCorrupt)?;
    let t = t.ok_or(VaultError::WrongPhraseOrCorrupt)?;
    let p = p.ok_or(VaultError::WrongPhraseOrCorrupt)?;
    // Bound the cost params to SANE APPLICATION maxima before calling
    // Params::new. Two reasons the crate's own maxima aren't enough:
    //   * argon2's MAX_M_COST and MAX_T_COST are u32::MAX, so a disk-tampered
    //     m near 4 TiB would pass Params::new and OOM-kill the process when
    //     argon2 tries to allocate the memory block.
    //   * a tampered p near u32::MAX makes Params::new compute `p_cost * 8`,
    //     which overflows u32 and PANICS in a debug build before it can return
    //     an error, tearing down the serve loop.
    // 1 GiB / t=64 / p=64 are far above hecate's real cost (m=64MiB,t=3,p=1)
    // yet reject absurd tampered values, funneling them through the uniform
    // error rather than a crash/OOM.
    const MAX_M_KIB: u32 = 1024 * 1024; // 1 GiB
    const MAX_T: u32 = 64;
    const MAX_P: u32 = 64;
    if !(Params::MIN_M_COST..=MAX_M_KIB).contains(&m)
        || !(Params::MIN_T_COST..=MAX_T).contains(&t)
        || !(Params::MIN_P_COST..=MAX_P).contains(&p)
    {
        return Err(VaultError::WrongPhraseOrCorrupt);
    }
    let params = Params::new(m, t, p, Some(32)).map_err(|_| VaultError::WrongPhraseOrCorrupt)?;
    Ok((salt, params))
}

/// Derive the 32-byte key from a phrase + salt + params. Argon2id.
fn derive_key(phrase: &str, salt: &[u8], params: Params) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(phrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| VaultError::Crypto("argon2 derivation failed"))?;
    Ok(key)
}

/// Associated data bound into every AEAD operation: format version ‖ kdf
/// string. Tampering with the (cleartext) params/salt or version becomes an
/// authentication failure rather than a silent wrong-key.
fn associated_data(kdf: &str) -> Vec<u8> {
    let mut ad = Vec::with_capacity(1 + kdf.len());
    ad.push(FORMAT_VERSION);
    ad.extend_from_slice(kdf.as_bytes());
    ad
}

/// Encode a key for the wire (base64). The caller is responsible for the
/// security implications (see module docs).
fn encode_key(key: &[u8; 32]) -> String {
    B64.encode(key)
}

/// Decode a wire key back to 32 bytes, wrapped for zeroization.
pub fn decode_key(b64: &str) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let bytes = B64.decode(b64).map_err(|_| VaultError::BadKey)?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| VaultError::BadKey)?;
    Ok(Zeroizing::new(arr))
}

/// Encrypt a plaintext row set under `key`, with a fresh random nonce. Returns
/// (nonce, ciphertext).
fn seal(key: &[u8; 32], kdf: &str, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ad = associated_data(kdf);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &ad,
            },
        )
        .map_err(|_| VaultError::Crypto("encryption failed"))?;
    Ok((nonce.to_vec(), ct))
}

/// Decrypt under `key`. Auth failure (wrong key / tampered) → the uniform
/// `WrongPhraseOrCorrupt`.
fn open(key: &[u8; 32], kdf: &str, nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>, VaultError> {
    if nonce.len() != 24 {
        return Err(VaultError::WrongPhraseOrCorrupt);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let ad = associated_data(kdf);
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload { msg: ct, aad: &ad },
        )
        .map_err(|_| VaultError::WrongPhraseOrCorrupt)
}

/// Serialize an in-memory vault store back to plaintext JSON bytes.
fn serialize_store(store: &Store) -> Result<Vec<u8>, VaultError> {
    let rows = store.dump_rows()?;
    let pt = VaultPlaintext {
        v: FORMAT_VERSION,
        nodes: rows,
    };
    serde_json::to_vec(&pt).map_err(|_| VaultError::Crypto("serialize failed"))
}

/// Load decrypted plaintext bytes into an ephemeral in-memory `Store`.
fn load_store(plaintext: &[u8]) -> Result<Store, VaultError> {
    let pt: VaultPlaintext =
        serde_json::from_slice(plaintext).map_err(|_| VaultError::Corrupt("bad plaintext json"))?;
    if pt.v != FORMAT_VERSION {
        return Err(VaultError::Corrupt("unknown vault format version"));
    }
    let conn = Connection::open_in_memory()?;
    Ok(Store::from_vault_rows(conn, &pt.nodes)?)
}

/// Create a brand-new empty vault: fresh salt, derive key, seal a root-only
/// tree. Returns the wire key. Errors if a vault already exists.
pub fn create(conn: &Connection, phrase: &str) -> Result<String, VaultError> {
    if phrase.trim().is_empty() {
        return Err(VaultError::InvalidArg("phrase must not be empty".into()));
    }
    let now = now_secs();
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    if tx.query_row("SELECT count(*) FROM vault WHERE id = 1", [], |r| r.get::<_, i64>(0))? > 0 {
        return Err(VaultError::AlreadyExists);
    }
    let mut salt = [0u8; SALT_LEN];
    use chacha20poly1305::aead::rand_core::RngCore;
    OsRng.fill_bytes(&mut salt);
    let kdf = kdf_string(&salt);
    let (_, params) = parse_kdf(&kdf)?;
    let key = derive_key(phrase, &salt, params)?;

    // A new vault holds just its root folder.
    let root_only = VaultPlaintext {
        v: FORMAT_VERSION,
        nodes: vec![NodeRow {
            id: 1,
            parent_id: None,
            kind: crate::store::NodeKind::Folder,
            title: "Hidden".to_string(),
            url: None,
            position: 0,
            created: now,
            modified: now,
        }],
    };
    let plaintext =
        serde_json::to_vec(&root_only).map_err(|_| VaultError::Crypto("serialize failed"))?;
    let (nonce, ct) = seal(&key, &kdf, &plaintext)?;
    tx.execute(
        "INSERT INTO vault (id, kdf, nonce, ciphertext, version, updated)
         VALUES (1, ?1, ?2, ?3, 0, ?4)",
        (&kdf, &nonce, &ct, now),
    )?;
    tx.commit()?;
    Ok(encode_key(&key))
}

/// The decrypted vault, returned by `unlock`: the wire key plus the loaded
/// in-memory store the caller can read from.
pub struct Unlocked {
    pub key_b64: String,
    pub store: Store,
}

/// Unlock with a phrase: derive the key, decrypt. Wrong phrase / no vault /
/// corrupt blob all return the same `WrongPhraseOrCorrupt`.
pub fn unlock(conn: &Connection, phrase: &str) -> Result<Unlocked, VaultError> {
    let row = read_row(conn)?.ok_or(VaultError::WrongPhraseOrCorrupt)?;
    let (salt, params) = parse_kdf(&row.kdf)?;
    let key = derive_key(phrase, &salt, params)?;
    let plaintext = open(&key, &row.kdf, &row.nonce, &row.ciphertext)?;
    let store = load_store(&plaintext)?;
    Ok(Unlocked {
        key_b64: encode_key(&key),
        store,
    })
}

/// Open an already-unlocked vault using the wire key (no KDF). Used by every
/// follow-up op so Argon2id runs only once per unlock.
pub fn open_with_key(conn: &Connection, key_b64: &str) -> Result<Store, VaultError> {
    let key = decode_key(key_b64)?;
    let row = read_row(conn)?.ok_or(VaultError::WrongPhraseOrCorrupt)?;
    let plaintext = open(&key, &row.kdf, &row.nonce, &row.ciphertext)?;
    load_store(&plaintext)
}

struct VaultRow {
    kdf: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    version: i64,
}

fn read_row(conn: &Connection) -> Result<Option<VaultRow>, VaultError> {
    let row = conn
        .query_row(
            "SELECT kdf, nonce, ciphertext, version FROM vault WHERE id = 1",
            [],
            |r| {
                Ok(VaultRow {
                    kdf: r.get(0)?,
                    nonce: r.get(1)?,
                    ciphertext: r.get(2)?,
                    version: r.get(3)?,
                })
            },
        )
        .optional()
        // A column-type mismatch means the row was tampered/corrupted on disk
        // (e.g. `version` promoted to REAL). Funnel it through the uniform
        // corrupt error rather than leaking a distinct `database error: Invalid
        // column type ...` — keeps the no-oracle contract and matches how every
        // other on-disk tamper is handled.
        .map_err(|e| match e {
            rusqlite::Error::InvalidColumnType(..) => {
                VaultError::WrongPhraseOrCorrupt
            }
            other => VaultError::Store(StoreError::Sqlite(other)),
        })?;
    Ok(row)
}

/// Run a mutation against the vault using the wire key, with optimistic
/// concurrency: read (blob, version) inside a write txn, decrypt, load into an
/// in-memory store, apply `f`, re-serialize, re-encrypt with a FRESH nonce, and
/// `UPDATE ... WHERE version = old`. If another writer slipped in (0 rows
/// affected), re-read and replay, up to a retry budget.
///
/// Two layers protect against the whole-blob last-writer-wins clobber: the
/// `BEGIN IMMEDIATE` lock is the primary serializer (a second writer blocks at
/// BEGIN until the first commits, then reads fresh state), and the `version`
/// predicate is belt-and-suspenders for any path where the read snapshot and
/// the write could diverge. `f` returns a value passed back to the caller.
pub fn with_vault_mut<T>(
    conn: &Connection,
    key_b64: &str,
    mut f: impl FnMut(&Store) -> Result<T, StoreError>,
) -> Result<T, VaultError> {
    let key = decode_key(key_b64)?;
    let now = now_secs();
    for _ in 0..MAX_WRITE_RETRIES {
        let tx =
            rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
        let row = read_row(&tx)?.ok_or(VaultError::WrongPhraseOrCorrupt)?;
        let plaintext = open(&key, &row.kdf, &row.nonce, &row.ciphertext)?;
        let store = load_store(&plaintext)?;

        let result = f(&store)?;

        let new_plaintext = serialize_store(&store)?;
        let (nonce, ct) = seal(&key, &row.kdf, &new_plaintext)?;
        // Compute the next version in Rust with wrapping, then bind it
        // explicitly — never `version + 1` in SQL, which would overflow an
        // i64::MAX (tampered) version, promote the column to REAL, and brick
        // every future read.
        let next_version = row.version.wrapping_add(1);
        let affected = tx.execute(
            "UPDATE vault SET nonce = ?1, ciphertext = ?2, version = ?3, updated = ?4
             WHERE id = 1 AND version = ?5",
            (&nonce, &ct, next_version, now, row.version),
        )?;
        if affected == 1 {
            tx.commit()?;
            return Ok(result);
        }
        // Lost the optimistic race; the IMMEDIATE lock means this is rare, but
        // a concurrent process could have committed between our read and write.
        // Drop the txn (rollback) and replay against the fresh state.
        drop(tx);
    }
    Err(VaultError::Contended)
}

/// Re-key the vault under a new phrase (fresh salt + params), preserving
/// contents. Requires the current wire key. Returns the new wire key.
pub fn change_phrase(
    conn: &Connection,
    key_b64: &str,
    new_phrase: &str,
) -> Result<String, VaultError> {
    if new_phrase.trim().is_empty() {
        return Err(VaultError::InvalidArg("phrase must not be empty".into()));
    }
    let old_key = decode_key(key_b64)?;
    let now = now_secs();
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let row = read_row(&tx)?.ok_or(VaultError::WrongPhraseOrCorrupt)?;
    let plaintext = open(&old_key, &row.kdf, &row.nonce, &row.ciphertext)?;
    // Validate the decrypted contents load cleanly before re-keying.
    let _ = load_store(&plaintext)?;

    let mut salt = [0u8; SALT_LEN];
    use chacha20poly1305::aead::rand_core::RngCore;
    OsRng.fill_bytes(&mut salt);
    let kdf = kdf_string(&salt);
    let (_, params) = parse_kdf(&kdf)?;
    let new_key = derive_key(new_phrase, &salt, params)?;
    let (nonce, ct) = seal(&new_key, &kdf, &plaintext)?;
    // Explicit wrapping increment (see with_vault_mut) — never `version + 1` in
    // SQL, to avoid an i64-overflow REAL-promotion that would brick the vault.
    let next_version = row.version.wrapping_add(1);
    let affected = tx.execute(
        "UPDATE vault SET kdf = ?1, nonce = ?2, ciphertext = ?3, version = ?4, updated = ?5
         WHERE id = 1 AND version = ?6",
        (&kdf, &nonce, &ct, next_version, now, row.version),
    )?;
    if affected != 1 {
        return Err(VaultError::Contended);
    }
    tx.commit()?;
    Ok(encode_key(&new_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    // Cheap KDF params so the test suite stays fast. (Production uses the real
    // ARGON_* constants; these tests exercise structure, not cost.)
    fn fast_create(conn: &Connection, phrase: &str) -> String {
        // Reuse the real create() — Argon2 at 64 MiB is ~tens of ms in release,
        // acceptable in debug tests too (a handful of calls).
        create(conn, phrase).unwrap()
    }

    fn store_conn() -> Connection {
        // A real on-disk-shaped store gives us the vault table via migrate().
        let conn = Connection::open_in_memory().unwrap();
        // Build the full schema by going through Store::from_conn, then reuse
        // its connection. from_conn consumes the conn, so make a fresh one and
        // run migrate-equivalent by opening a Store and pulling its conn out is
        // awkward; instead just create the tables directly the way migrate does.
        let s = Store::from_conn(conn).unwrap();
        s.into_conn()
    }

    #[test]
    fn create_unlock_roundtrip() {
        let conn = store_conn();
        let key = fast_create(&conn, "right phrase");
        let u = unlock(&conn, "right phrase").unwrap();
        assert_eq!(u.key_b64, key); // same phrase+salt → same key
        let root = u.store.tree(true).unwrap();
        assert_eq!(root.title, "Hidden");
        assert!(root.children.is_empty());
    }

    /// Assert an `unlock` failed with the uniform no-oracle error (without
    /// requiring `Unlocked: Debug` for `unwrap_err`).
    fn assert_unlock_uniform_err(conn: &Connection, phrase: &str) {
        match unlock(conn, phrase) {
            Err(VaultError::WrongPhraseOrCorrupt) => {}
            Err(other) => panic!("expected WrongPhraseOrCorrupt, got {other:?}"),
            Ok(_) => panic!("expected unlock to fail"),
        }
    }

    #[test]
    fn wrong_phrase_is_uniform_error() {
        let conn = store_conn();
        fast_create(&conn, "right phrase");
        assert_unlock_uniform_err(&conn, "wrong phrase");
    }

    #[test]
    fn unlock_with_no_vault_is_uniform_error() {
        let conn = store_conn();
        // No vault created — must be indistinguishable from a wrong phrase.
        assert_unlock_uniform_err(&conn, "anything");
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let conn = store_conn();
        fast_create(&conn, "pw");
        // Flip a byte of the ciphertext. (Do it in Rust — SQLite's `||` coerces
        // BLOBs to text and would corrupt the round-trip rather than flip a
        // byte cleanly.)
        let mut ct: Vec<u8> = conn
            .query_row("SELECT ciphertext FROM vault WHERE id=1", [], |r| r.get(0))
            .unwrap();
        ct[0] ^= 0xff;
        conn.execute("UPDATE vault SET ciphertext=?1 WHERE id=1", [ct])
            .unwrap();
        assert_unlock_uniform_err(&conn, "pw");
    }

    #[test]
    fn tampered_kdf_params_fail_auth() {
        let conn = store_conn();
        fast_create(&conn, "pw");
        // Downgrade t-cost in the cleartext kdf string. It's bound as AAD, so
        // even though parse still succeeds, decryption must fail to authenticate
        // (and the derived key differs anyway).
        let kdf: String = conn
            .query_row("SELECT kdf FROM vault WHERE id=1", [], |r| r.get(0))
            .unwrap();
        let tampered = kdf.replace("t=3", "t=2");
        assert_ne!(kdf, tampered);
        conn.execute("UPDATE vault SET kdf=?1 WHERE id=1", [tampered])
            .unwrap();
        assert_unlock_uniform_err(&conn, "pw");
    }

    #[test]
    fn tampered_short_salt_is_uniform_error() {
        // A disk-tampered kdf with an empty/short salt must still surface the
        // uniform error, not a distinct "crypto error" that acts as an oracle.
        let conn = store_conn();
        fast_create(&conn, "pw");
        conn.execute(
            "UPDATE vault SET kdf='argon2id$v=19$m=65536,t=3,p=1$' WHERE id=1",
            [],
        )
        .unwrap();
        assert_unlock_uniform_err(&conn, "pw");
    }

    #[test]
    fn tampered_overflow_params_dont_panic() {
        // A disk-tampered kdf with p near u32::MAX would make argon2's
        // Params::new compute p*8 and panic-on-overflow in debug builds,
        // tearing down serve. parse_kdf must reject it as the uniform error,
        // never panic. (This test would PANIC, not fail, if the guard regressed.)
        let conn = store_conn();
        fast_create(&conn, "pw");
        conn.execute(
            "UPDATE vault SET kdf='argon2id$v=19$m=65536,t=3,p=4294967295$AAAAAAAAAAAAAAAA' WHERE id=1",
            [],
        )
        .unwrap();
        assert_unlock_uniform_err(&conn, "pw");
        // Also a huge m and t.
        conn.execute(
            "UPDATE vault SET kdf='argon2id$v=19$m=4294967295,t=4294967295,p=1$AAAAAAAAAAAAAAAA' WHERE id=1",
            [],
        )
        .unwrap();
        assert_unlock_uniform_err(&conn, "pw");
    }

    #[test]
    fn version_overflow_does_not_brick() {
        // A tampered version near i64::MAX must not, on the next write, overflow
        // (SQL `version+1` would promote the column to REAL and brick all future
        // reads). The explicit wrapping increment keeps it an INTEGER.
        let conn = store_conn();
        let key = fast_create(&conn, "pw");
        conn.execute("UPDATE vault SET version = ?1", [i64::MAX]).unwrap();
        // A mutation triggers the increment; must succeed and stay readable.
        with_vault_mut(&conn, &key, |s| s.create_folder(None, "f", 1)).unwrap();
        let typ: String = conn
            .query_row("SELECT typeof(version) FROM vault", [], |r| r.get(0))
            .unwrap();
        assert_eq!(typ, "integer", "version column must stay INTEGER");
        // Still unlockable after the wrap.
        let u = unlock(&conn, "pw").unwrap();
        assert_eq!(u.store.tree(true).unwrap().children[0].title, "f");
    }

    #[test]
    fn non_integer_version_is_uniform_error() {
        // A disk tamper that makes `version` a non-integer must surface the
        // uniform corrupt error, not a distinct "Invalid column type" oracle.
        let conn = store_conn();
        fast_create(&conn, "pw");
        conn.execute("UPDATE vault SET version = 3.5", []).unwrap();
        assert_unlock_uniform_err(&conn, "pw");
    }

    #[test]
    fn cannot_create_twice() {
        let conn = store_conn();
        fast_create(&conn, "pw");
        assert!(matches!(
            create(&conn, "pw2").unwrap_err(),
            VaultError::AlreadyExists
        ));
    }

    #[test]
    fn mutation_persists_and_fresh_nonce_each_write() {
        let conn = store_conn();
        let key = fast_create(&conn, "pw");
        let nonce0: Vec<u8> = conn
            .query_row("SELECT nonce FROM vault WHERE id=1", [], |r| r.get(0))
            .unwrap();

        let id = with_vault_mut(&conn, &key, |s| s.create_folder(None, "f", 1)).unwrap();
        assert!(id > 1);
        let nonce1: Vec<u8> = conn
            .query_row("SELECT nonce FROM vault WHERE id=1", [], |r| r.get(0))
            .unwrap();
        assert_ne!(nonce0, nonce1, "nonce must be fresh per write");

        // A second write yields yet another nonce and the version increments.
        with_vault_mut(&conn, &key, |s| s.create_bookmark(Some(id), "b", "https://b.example", 2))
            .unwrap();
        let (nonce2, version): (Vec<u8>, i64) = conn
            .query_row("SELECT nonce, version FROM vault WHERE id=1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_ne!(nonce1, nonce2);
        assert_eq!(version, 2); // created=0 → +1 → +1

        // Re-open and confirm contents survived the encrypt/decrypt cycle.
        let u = unlock(&conn, "pw").unwrap();
        let root = u.store.tree(true).unwrap();
        assert_eq!(root.children.len(), 1);
        assert_eq!(root.children[0].title, "f");
        assert_eq!(root.children[0].children[0].title, "b");
    }

    #[test]
    fn vault_reuses_tree_invariants() {
        let conn = store_conn();
        let key = fast_create(&conn, "pw");
        let a = with_vault_mut(&conn, &key, |s| s.create_folder(None, "a", 1)).unwrap();
        let b = with_vault_mut(&conn, &key, |s| s.create_folder(Some(a), "b", 2)).unwrap();
        // Cycle prevention works inside the vault too: move a into its child b.
        let err = with_vault_mut(&conn, &key, |s| s.move_node(a, b, None, 3));
        assert!(matches!(
            err,
            Err(VaultError::Store(StoreError::CycleDetected))
        ));
    }

    #[test]
    fn open_with_wrong_key_fails() {
        let conn = store_conn();
        fast_create(&conn, "pw");
        // A validly-shaped but wrong key.
        let bogus = B64.encode([7u8; 32]);
        assert!(matches!(
            open_with_key(&conn, &bogus).unwrap_err(),
            VaultError::WrongPhraseOrCorrupt
        ));
        // A malformed key is a distinct, non-oracle error class.
        assert!(matches!(decode_key("not-base64!!"), Err(VaultError::BadKey)));
    }

    #[test]
    fn concurrent_vault_writes_dont_clobber() {
        // The version guard must prevent two writers from silently losing one
        // another's whole-blob edit. Use a temp-file DB so two connections
        // genuinely share state.
        let dir = std::env::temp_dir().join(format!("hecate_vault_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.db");
        let _ = std::fs::remove_file(&path);

        let key = {
            let s = Store::from_conn(Connection::open(&path).unwrap()).unwrap();
            create(s.conn(), "pw").unwrap()
        };

        // Two threads each add a distinct folder concurrently.
        let threads: Vec<_> = ["alpha", "beta"]
            .iter()
            .map(|name| {
                let path = path.clone();
                let key = key.clone();
                let name = name.to_string();
                std::thread::spawn(move || {
                    let s = Store::from_conn(Connection::open(&path).unwrap()).unwrap();
                    with_vault_mut(s.conn(), &key, |vs| vs.create_folder(None, &name, 1)).unwrap();
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        // BOTH folders must survive — neither write clobbered the other.
        let s = Store::from_conn(Connection::open(&path).unwrap()).unwrap();
        let u = unlock(s.conn(), "pw").unwrap();
        let titles: Vec<String> = u
            .store
            .tree(true)
            .unwrap()
            .children
            .iter()
            .map(|n| n.title.clone())
            .collect();
        assert_eq!(titles.len(), 2, "both concurrent edits must persist, got {titles:?}");
        assert!(titles.contains(&"alpha".to_string()));
        assert!(titles.contains(&"beta".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn change_phrase_rekeys() {
        let conn = store_conn();
        let key = fast_create(&conn, "old phrase");
        with_vault_mut(&conn, &key, |s| s.create_folder(None, "keep", 1)).unwrap();
        let new_key = change_phrase(&conn, &key, "new phrase").unwrap();
        assert_ne!(key, new_key);
        // Old phrase no longer unlocks; new phrase does and content survived.
        assert!(unlock(&conn, "old phrase").is_err());
        let u = unlock(&conn, "new phrase").unwrap();
        assert_eq!(u.key_b64, new_key);
        assert_eq!(u.store.tree(true).unwrap().children[0].title, "keep");
    }
}
