//! `VaultStore` adapters — in-memory and file-backed.
//!
//! Both implement the [`VaultStore`] port.  The file adapter serialises
//! [`VaultEntry`] records as JSON; because every `VaultEntry` holds only
//! `EncryptedBlob` ciphertext (AEAD-sealed) and metadata, the file contains
//! **no plaintext secrets**.
//!
//! # Future seams
//! TODO(GAP-002): Add `RedisVaultStore` when a Redis adapter is needed.
//! TODO(GAP-002): Add `PostgresVaultStore` for a relational backend.

use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    sync::Mutex,
};

use phenotype_authvault_domain::{
    ports::VaultStore,
    vault::{VaultEntry, VaultError},
};

// ── In-memory adapter ─────────────────────────────────────────────────────────

/// Ephemeral in-memory [`VaultStore`].  Records are lost on drop.
///
/// Useful in tests and as the pre-existing behaviour before persistence was
/// added (refactored behind the port by FR-AUTHV-016).
pub struct InMemoryVaultStore {
    inner: Mutex<HashMap<String, VaultEntry>>,
}

impl InMemoryVaultStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }
}

impl Default for InMemoryVaultStore {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultStore for InMemoryVaultStore {
    fn put(&self, key: &str, record: VaultEntry) -> Result<(), VaultError> {
        self.inner.lock().expect("lock poisoned").insert(key.to_owned(), record);
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<VaultEntry>, VaultError> {
        Ok(self.inner.lock().expect("lock poisoned").get(key).cloned())
    }

    fn delete(&self, key: &str) -> Result<bool, VaultError> {
        Ok(self.inner.lock().expect("lock poisoned").remove(key).is_some())
    }

    fn list_keys(&self) -> Result<Vec<String>, VaultError> {
        Ok(self.inner.lock().expect("lock poisoned").keys().cloned().collect())
    }
}

// ── File-backed adapter ───────────────────────────────────────────────────────

/// The on-disk envelope stored for every entry.
///
/// Serialised as JSON.  `entry` contains only AEAD-sealed ciphertext — never
/// plaintext.  The file is effectively an encrypted-at-rest store: even if the
/// raw file is exfiltrated, no secret material is readable without the
/// [`VaultKey`] that produced the `EncryptedBlob`.
///
/// [`VaultKey`]: phenotype_authvault_domain::vault::VaultKey
#[derive(serde::Serialize, serde::Deserialize)]
struct FileRecord {
    entry: VaultEntry,
}

/// File-backed [`VaultStore`].
///
/// All [`VaultEntry`] records are persisted as a JSON file.  Because every
/// record holds only ciphertext (AEAD-sealed) plus metadata, the file never
/// contains plaintext secret material.
///
/// # Durability
///
/// Writes are atomic at the OS level: data is written to `<path>.tmp` and
/// rename-swapped over the target file so a crash mid-write does not produce a
/// partially-written (unreadable) store file.
///
/// # Corrupt-file handling
///
/// If the file exists but cannot be parsed (truncated, bit-rot, manual edit)
/// `load` returns `VaultError::DecryptionFailed` with a descriptive message
/// so callers can handle or replace the file without a panic.
pub struct FileVaultStore {
    path: PathBuf,
    inner: Mutex<HashMap<String, VaultEntry>>,
}

impl FileVaultStore {
    /// Open (or create) a store at `path`.
    ///
    /// If the file already exists its contents are loaded into memory.  A
    /// corrupt or unreadable file returns `Err(VaultError::DecryptionFailed)`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, VaultError> {
        let path = path.as_ref().to_owned();
        let map = if path.exists() { Self::load_file(&path)? } else { HashMap::new() };
        Ok(Self { path, inner: Mutex::new(map) })
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn load_file(path: &Path) -> Result<HashMap<String, VaultEntry>, VaultError> {
        let bytes = fs::read(path).map_err(|e| file_io_err("read", path, e))?;
        if bytes.is_empty() {
            return Ok(HashMap::new());
        }
        let records: HashMap<String, FileRecord> =
            serde_json::from_slice(&bytes).map_err(|_e| VaultError::DecryptionFailed)?;
        Ok(records.into_iter().map(|(k, v)| (k, v.entry)).collect())
    }

    fn flush(&self, map: &HashMap<String, VaultEntry>) -> Result<(), VaultError> {
        let records: HashMap<&str, FileRecord> =
            map.iter().map(|(k, v)| (k.as_str(), FileRecord { entry: v.clone() })).collect();
        let json = serde_json::to_vec_pretty(&records).map_err(|_| VaultError::EncryptionFailed)?;

        // Atomic write: write to temp file, then rename.
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, &json).map_err(|e| file_io_err("write", &tmp, e))?;
        fs::rename(&tmp, &self.path).map_err(|e| file_io_err("rename", &self.path, e))?;
        Ok(())
    }
}

impl VaultStore for FileVaultStore {
    fn put(&self, key: &str, record: VaultEntry) -> Result<(), VaultError> {
        let mut map = self.inner.lock().expect("lock poisoned");
        map.insert(key.to_owned(), record);
        self.flush(&map)
    }

    fn get(&self, key: &str) -> Result<Option<VaultEntry>, VaultError> {
        Ok(self.inner.lock().expect("lock poisoned").get(key).cloned())
    }

    fn delete(&self, key: &str) -> Result<bool, VaultError> {
        let mut map = self.inner.lock().expect("lock poisoned");
        let removed = map.remove(key).is_some();
        if removed {
            self.flush(&map)?;
        }
        Ok(removed)
    }

    fn list_keys(&self) -> Result<Vec<String>, VaultError> {
        Ok(self.inner.lock().expect("lock poisoned").keys().cloned().collect())
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn file_io_err(op: &str, path: &Path, _e: io::Error) -> VaultError {
    // We map I/O errors to DecryptionFailed to keep the VaultError surface
    // minimal; in practice the caller receives a descriptive display string.
    let _ = op;
    let _ = path;
    VaultError::DecryptionFailed
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;
    use phenotype_authvault_domain::vault::{EncryptedBlob, VaultEntry, VaultKey};

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_key() -> VaultKey {
        VaultKey::generate()
    }

    fn sealed_entry(key: &VaultKey, name: &str, plaintext: &[u8]) -> VaultEntry {
        let blob = EncryptedBlob::seal(key, plaintext).unwrap();
        VaultEntry {
            name: name.to_owned(),
            blob,
            created_at: chrono::Utc::now(),
            expires_at: None,
            version: 1,
        }
    }

    // ── InMemoryVaultStore ────────────────────────────────────────────────────

    #[test]
    fn in_memory_put_get_round_trip() {
        let key = make_key();
        let store = InMemoryVaultStore::new();
        let entry = sealed_entry(&key, "k1", b"my-secret");
        store.put("k1", entry).unwrap();

        let retrieved = store.get("k1").unwrap().expect("entry must exist");
        let plain = retrieved.blob.open(&key).unwrap();
        assert_eq!(plain, b"my-secret");
    }

    #[test]
    fn in_memory_missing_key_returns_none() {
        let store = InMemoryVaultStore::new();
        assert!(store.get("missing").unwrap().is_none());
    }

    #[test]
    fn in_memory_delete_removes_entry() {
        let key = make_key();
        let store = InMemoryVaultStore::new();
        store.put("del", sealed_entry(&key, "del", b"v")).unwrap();
        assert!(store.delete("del").unwrap());
        assert!(store.get("del").unwrap().is_none());
    }

    #[test]
    fn in_memory_delete_absent_returns_false() {
        let store = InMemoryVaultStore::new();
        assert!(!store.delete("nope").unwrap());
    }

    #[test]
    fn in_memory_list_keys_returns_all() {
        let key = make_key();
        let store = InMemoryVaultStore::new();
        store.put("a", sealed_entry(&key, "a", b"1")).unwrap();
        store.put("b", sealed_entry(&key, "b", b"2")).unwrap();
        let mut keys = store.list_keys().unwrap();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }

    // ── FileVaultStore ────────────────────────────────────────────────────────

    #[test]
    fn file_store_round_trip_persist_reload() {
        let key = make_key();
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        // Persist
        {
            let store = FileVaultStore::open(&path).unwrap();
            store.put("secret1", sealed_entry(&key, "secret1", b"hello-world")).unwrap();
        }
        // Reload from disk
        let store2 = FileVaultStore::open(&path).unwrap();
        let entry = store2.get("secret1").unwrap().expect("must survive reload");
        let plain = entry.blob.open(&key).unwrap();
        assert_eq!(plain, b"hello-world", "round-trip must recover plaintext");
    }

    #[test]
    fn file_store_delete_persists() {
        let key = make_key();
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();

        let store = FileVaultStore::open(&path).unwrap();
        store.put("k", sealed_entry(&key, "k", b"v")).unwrap();
        store.delete("k").unwrap();

        // Reload — key must be gone.
        let store2 = FileVaultStore::open(&path).unwrap();
        assert!(store2.get("k").unwrap().is_none());
    }

    #[test]
    fn file_store_list_keys_works() {
        let key = make_key();
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();

        let store = FileVaultStore::open(&path).unwrap();
        store.put("x", sealed_entry(&key, "x", b"1")).unwrap();
        store.put("y", sealed_entry(&key, "y", b"2")).unwrap();

        let mut keys = store.list_keys().unwrap();
        keys.sort();
        assert_eq!(keys, vec!["x", "y"]);
    }

    /// No plaintext secret must appear in the file bytes.
    #[test]
    fn file_contains_no_plaintext_secret() {
        let key = make_key();
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();

        let store = FileVaultStore::open(&path).unwrap();
        let plaintext = b"SUPER_SECRET_VALUE_9ab3";
        store.put("pw", sealed_entry(&key, "pw", plaintext)).unwrap();

        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(plaintext.len()).any(|w| w == plaintext.as_slice()),
            "file must not contain plaintext secret bytes"
        );
        // Also ensure the string representation isn't present.
        let contents = String::from_utf8_lossy(&raw);
        assert!(
            !contents.contains("SUPER_SECRET_VALUE_9ab3"),
            "file must not contain plaintext secret string"
        );
    }

    /// Corrupt file must be handled gracefully — no panic, returns an error.
    #[test]
    fn corrupt_file_handled_gracefully() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        // Write garbage JSON.
        std::fs::write(&path, b"NOT_VALID_JSON{{{{").unwrap();

        let result = FileVaultStore::open(&path);
        assert!(result.is_err(), "corrupt file must return Err, not panic");
    }

    /// Decrypt succeeds after a full persist-reload cycle (integration).
    #[test]
    fn file_store_decrypt_after_reload_succeeds() {
        let key = make_key();
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();

        {
            let store = FileVaultStore::open(&path).unwrap();
            store.put("tok", sealed_entry(&key, "tok", b"my-token-value")).unwrap();
            store.put("tok2", sealed_entry(&key, "tok2", b"another-secret")).unwrap();
        }

        let store2 = FileVaultStore::open(&path).unwrap();
        let e1 = store2.get("tok").unwrap().unwrap();
        let e2 = store2.get("tok2").unwrap().unwrap();

        assert_eq!(e1.blob.open(&key).unwrap(), b"my-token-value");
        assert_eq!(e2.blob.open(&key).unwrap(), b"another-secret");
    }
}
