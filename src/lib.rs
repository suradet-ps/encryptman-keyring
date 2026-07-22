//! # encryptman-keyring
//!
//! OS keychain-backed master key storage for
//! [encryptman](https://crates.io/crates/encryptman).
//!
//! This crate eliminates the need to manage raw key files by storing the
//! master key in the operating system's native credential store:
//!
//! - **Windows** — Credential Manager
//! - **macOS** — Keychain Services
//! - **Linux** — Secret Service (DBus)
//!
//! ## Quick Start
//!
//! ```no_run
//! use encryptman_keyring::Vault;
//!
//! // First call: generates a new master key and stores it in the OS keychain.
//! // Subsequent calls: loads the existing key from the keychain.
//! let vault = Vault::new("my-app").unwrap();
//!
//! // Encrypt
//! let ciphertext = vault.encrypt("my_database_password").unwrap();
//!
//! // Decrypt
//! let plaintext = vault.decrypt(&ciphertext).unwrap();
//! assert_eq!(plaintext, "my_database_password");
//! ```
//!
//! ## Design
//!
//! ```text
//! Vault::new("my-app")
//!     │
//!     ├── keyring::Entry::new("my-app", "master-key")
//!     │       │
//!     │       ├── get_secret() → OK → MasterKey::from_bytes()
//!     │       └── get_secret() → NoEntry → generate + set_secret()
//!     │
//!     └── encryptman::encrypt / decrypt using the master key
//! ```
//!
//! The `service` name passed to [`Vault::new`] is used as both the keyring
//! service identifier **and** the HKDF context for encryptman, providing
//! domain isolation between different applications.
//!
//! ## Migration from file-based keys
//!
//! Use [`Vault::migrate_from_file`] to import an existing `.tb_key` file
//! into the OS keychain and delete the file:
//!
//! ```no_run
//! use encryptman_keyring::Vault;
//!
//! let vault = Vault::migrate_from_file("my-app", std::path::Path::new("/path/to/.tb_key")).unwrap();
//! ```
//!
//! ## When NOT to use this crate
//!
//! - **Headless / CI environments** — the OS keychain may not be available.
//!   Use file-based key storage instead.
//! - **Multi-user servers** — keyring entries are per-user; consider a
//!   shared secret store like Vault or AWS Secrets Manager.

use encryptman::MasterKey;
use thiserror::Error;

/// The keyring username used to store the master key.
const KEY_USERNAME: &str = "master-key";

/// Errors that can occur during vault operations.
#[derive(Debug, Error)]
pub enum Error {
    /// The OS keychain returned an error.
    #[error("keychain error: {0}")]
    Keychain(#[from] keyring::Error),

    /// The master key stored in the keychain is corrupted or has the wrong length.
    #[error("invalid master key in keychain: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    /// A file-based migration source could not be read.
    #[error("failed to read key file: {0}")]
    FileRead(#[from] std::io::Error),

    /// The file-based key has the wrong length.
    #[error("invalid key file: expected 32 bytes, got {0}")]
    InvalidFileKeyLength(usize),

    /// Encryption or decryption failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] encryptman::CryptoError),
}

/// A vault that stores its master key in the OS keychain and delegates
/// encryption/decryption to `encryptman`.
///
/// Each `Vault` instance is bound to a **service name** (and optionally a
/// **target username**) that identifies the keychain entry. The same service
/// name is also used as the HKDF context in `encryptman`, so different
/// service names produce different encryption keys from the same underlying
/// keychain entry.
///
/// # Examples
///
/// ```no_run
/// use encryptman_keyring::Vault;
///
/// let vault = Vault::new("my-app").unwrap();
/// let ct = vault.encrypt("secret").unwrap();
/// let pt = vault.decrypt(&ct).unwrap();
/// assert_eq!(pt, "secret");
/// Vault::delete("my-app").unwrap();
/// ```
pub struct Vault {
    service: String,
    master_key: MasterKey,
}

impl Vault {
    /// Create or open a vault with the given service name.
    ///
    /// On first call, a new random master key is generated and stored in the
    /// OS keychain. On subsequent calls, the existing key is loaded.
    ///
    /// The `service` is used as the keyring service name and as the encryptman
    /// HKDF context (`"encryptman:{service}"`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keychain`] if the OS keychain is unavailable.
    pub fn new(service: &str) -> Result<Self, Error> {
        Self::new_with_target(service, KEY_USERNAME)
    }

    /// Create or open a vault with a custom target (username) in the keyring.
    ///
    /// This is useful when multiple independent vaults are needed within the
    /// same service namespace.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keychain`] if the OS keychain is unavailable.
    pub fn new_with_target(service: &str, target: &str) -> Result<Self, Error> {
        let entry = keyring::Entry::new(service, target)?;
        let master_key = match entry.get_secret() {
            Ok(bytes) => MasterKey::try_from(bytes.as_slice())
                .map_err(|_| Error::InvalidKeyLength(bytes.len()))?,
            Err(keyring::Error::NoEntry) => {
                let key = MasterKey::generate();
                entry.set_secret(key.as_bytes())?;
                key
            }
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            service: service.to_string(),
            master_key,
        })
    }

    /// Migrate a file-based key into the OS keychain.
    ///
    /// Reads a 32-byte key from `key_path`, stores it in the keychain under
    /// the given `service` name, and deletes the file on success.
    ///
    /// Returns the vault ready for use.
    ///
    /// # Errors
    ///
    /// - [`Error::FileRead`] if the file cannot be read.
    /// - [`Error::InvalidFileKeyLength`] if the file is not exactly 32 bytes.
    /// - [`Error::Keychain`] if the OS keychain is unavailable.
    pub fn migrate_from_file(service: &str, key_path: &std::path::Path) -> Result<Self, Error> {
        Self::migrate_from_file_with_target(service, KEY_USERNAME, key_path)
    }

    /// Migrate a file-based key with a custom target (username).
    ///
    /// See [`Vault::migrate_from_file`] for details.
    pub fn migrate_from_file_with_target(
        service: &str,
        target: &str,
        key_path: &std::path::Path,
    ) -> Result<Self, Error> {
        let raw = std::fs::read(key_path)?;
        if raw.len() != 32 {
            return Err(Error::InvalidFileKeyLength(raw.len()));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);

        let entry = keyring::Entry::new(service, target)?;
        entry.set_secret(&bytes)?;

        // Delete the file after successful migration
        std::fs::remove_file(key_path)?;

        let master_key = MasterKey::from_bytes(bytes);
        Ok(Self {
            service: service.to_string(),
            master_key,
        })
    }

    /// Encrypt a plaintext string using the vault's master key.
    ///
    /// Delegates to `encryptman::encrypt`. Each call produces a unique
    /// ciphertext (random nonce).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if encryption fails.
    pub fn encrypt(&self, plaintext: &str) -> Result<String, Error> {
        Ok(encryptman::encrypt(&self.master_key, plaintext)?)
    }

    /// Decrypt a ciphertext string using the vault's master key.
    ///
    /// Delegates to `encryptman::decrypt`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if decryption fails (wrong key, corrupted
    /// data, or invalid base64).
    pub fn decrypt(&self, ciphertext: &str) -> Result<String, Error> {
        Ok(encryptman::decrypt(&self.master_key, ciphertext)?)
    }

    /// Encrypt with a custom HKDF context.
    ///
    /// The `context` is appended to `"encryptman:"` to derive a
    /// domain-specific AES key from the master key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if encryption fails.
    pub fn encrypt_with_context(&self, context: &str, plaintext: &str) -> Result<String, Error> {
        Ok(encryptman::encrypt_with_context(
            &self.master_key,
            context,
            plaintext,
        )?)
    }

    /// Decrypt with a custom HKDF context.
    ///
    /// The `context` must match the one used during encryption.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if decryption fails.
    pub fn decrypt_with_context(&self, context: &str, ciphertext: &str) -> Result<String, Error> {
        Ok(encryptman::decrypt_with_context(
            &self.master_key,
            context,
            ciphertext,
        )?)
    }

    /// Return a reference to the underlying master key.
    ///
    /// This is useful when you need direct access to the key for advanced
    /// use cases (e.g., custom encryption contexts or binary data).
    pub fn master_key(&self) -> &MasterKey {
        &self.master_key
    }

    /// Encrypt arbitrary bytes using the vault's master key.
    ///
    /// Delegates to `encryptman::encrypt_bytes_with_context` using the
    /// vault's service name as context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if encryption fails.
    pub fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(encryptman::encrypt_bytes_with_context(
            &self.master_key,
            &self.service,
            plaintext,
        )?)
    }

    /// Decrypt arbitrary bytes using the vault's master key.
    ///
    /// Delegates to `encryptman::decrypt_bytes_with_context` using the
    /// vault's service name as context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if decryption fails.
    pub fn decrypt_bytes(&self, packed: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(encryptman::decrypt_bytes_with_context(
            &self.master_key,
            &self.service,
            packed,
        )?)
    }

    /// Encrypt arbitrary bytes with a custom HKDF context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if encryption fails.
    pub fn encrypt_bytes_with_context(
        &self,
        context: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Ok(encryptman::encrypt_bytes_with_context(
            &self.master_key,
            context,
            plaintext,
        )?)
    }

    /// Decrypt arbitrary bytes with a custom HKDF context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if decryption fails.
    pub fn decrypt_bytes_with_context(
        &self,
        context: &str,
        packed: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Ok(encryptman::decrypt_bytes_with_context(
            &self.master_key,
            context,
            packed,
        )?)
    }

    /// Delete the master key from the OS keychain.
    ///
    /// This is an associated function because deletion only requires the
    /// service name — no vault instance (or master key) is needed.
    ///
    /// **Warning**: This is destructive. All encrypted data will become
    /// unrecoverable unless you have a backup of the key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keychain`] if the keychain entry cannot be deleted.
    pub fn delete(service: &str) -> Result<(), Error> {
        Self::delete_with_target(service, KEY_USERNAME)
    }

    /// Delete the master key with a custom target from the OS keychain.
    ///
    /// This is an associated function — no vault instance needed.
    ///
    /// See [`Vault::delete`] for details.
    pub fn delete_with_target(service: &str, target: &str) -> Result<(), Error> {
        let entry = keyring::Entry::new(service, target)?;
        entry.delete_credential()?;
        Ok(())
    }
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("service", &self.service)
            .field("master_key", &"***")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn encrypt_decrypt_roundtrip() {
        let vault = Vault::new("test-encryptman-keyring").unwrap();
        let original = "my_secret_password_123!";
        let encrypted = vault.encrypt(original).unwrap();
        let decrypted = vault.decrypt(&encrypted).unwrap();
        assert_eq!(original, decrypted);
        let _ = Vault::delete("test-encryptman-keyring");
    }

    #[test]
    #[serial]
    fn encrypt_produces_different_output_each_time() {
        let vault = Vault::new("test-encryptman-keyring-ne").unwrap();
        let a = vault.encrypt("same_password").unwrap();
        let b = vault.encrypt("same_password").unwrap();
        assert_ne!(a, b);
        let _ = Vault::delete("test-encryptman-keyring-ne");
    }

    #[test]
    #[serial]
    fn wrong_key_fails() {
        let vault1 = Vault::new("test-encryptman-keyring-wk1").unwrap();
        let vault2 = Vault::new("test-encryptman-keyring-wk2").unwrap();
        let encrypted = vault1.encrypt("secret").unwrap();
        assert!(vault2.decrypt(&encrypted).is_err());
        let _ = Vault::delete("test-encryptman-keyring-wk1");
        let _ = Vault::delete("test-encryptman-keyring-wk2");
    }

    #[test]
    #[serial]
    fn unicode_roundtrip() {
        let vault = Vault::new("test-encryptman-keyring-unicode").unwrap();
        let original = "รหัสผ่านภาษาไทย 🔐";
        let encrypted = vault.encrypt(original).unwrap();
        let decrypted = vault.decrypt(&encrypted).unwrap();
        assert_eq!(original, decrypted);
        let _ = Vault::delete("test-encryptman-keyring-unicode");
    }

    #[test]
    #[serial]
    fn context_isolation() {
        let vault = Vault::new("test-encryptman-keyring-ctx").unwrap();
        let enc_a = vault.encrypt_with_context("ctx-a", "same").unwrap();
        let enc_b = vault.encrypt_with_context("ctx-b", "same").unwrap();
        assert_ne!(enc_a, enc_b);
        assert!(vault.decrypt_with_context("ctx-b", &enc_a).is_err());
        let _ = Vault::delete("test-encryptman-keyring-ctx");
    }

    #[test]
    #[serial]
    fn debug_does_not_leak_key() {
        let vault = Vault::new("test-encryptman-keyring-debug").unwrap();
        let debug = format!("{:?}", vault);
        assert_eq!(
            debug,
            "Vault { service: \"test-encryptman-keyring-debug\", master_key: \"***\" }"
        );
        let _ = Vault::delete("test-encryptman-keyring-debug");
    }

    #[test]
    #[serial]
    fn new_with_target() {
        let vault =
            Vault::new_with_target("test-encryptman-keyring-target", "custom-user").unwrap();
        let ct = vault.encrypt("hello").unwrap();
        let pt = vault.decrypt(&ct).unwrap();
        assert_eq!(pt, "hello");
        let _ = Vault::delete_with_target("test-encryptman-keyring-target", "custom-user");
    }

    #[test]
    #[serial]
    fn migrate_from_file() {
        use std::fs;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join(".tb_key");
        let key_bytes = [42u8; 32];
        fs::write(&key_path, key_bytes).unwrap();

        let vault = Vault::migrate_from_file("test-encryptman-keyring-migrate", &key_path).unwrap();
        assert_eq!(vault.master_key().as_bytes(), &key_bytes);
        assert!(
            !key_path.exists(),
            "key file should be deleted after migration"
        );

        let ct = vault.encrypt("migrated").unwrap();
        let pt = vault.decrypt(&ct).unwrap();
        assert_eq!(pt, "migrated");
        let _ = Vault::delete("test-encryptman-keyring-migrate");
    }

    #[test]
    #[serial]
    fn migrate_from_file_wrong_length() {
        use std::fs;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join(".tb_key");
        fs::write(&key_path, [1u8; 16]).unwrap();

        let result = Vault::migrate_from_file("test-encryptman-keyring-migrate-err", &key_path);
        assert!(result.is_err());
        assert!(key_path.exists());
    }

    #[test]
    #[serial]
    fn encrypt_bytes_roundtrip() {
        let vault = Vault::new("test-encryptman-keyring-bytes").unwrap();
        let data = b"binary secret data";
        let encrypted = vault.encrypt_bytes(data).unwrap();
        assert_ne!(encrypted, data.to_vec());
        let decrypted = vault.decrypt_bytes(&encrypted).unwrap();
        assert_eq!(decrypted, data);
        let _ = Vault::delete("test-encryptman-keyring-bytes");
    }

    #[test]
    #[serial]
    fn encrypt_bytes_produces_different_output_each_time() {
        let vault = Vault::new("test-encryptman-keyring-bytes-ne").unwrap();
        let data = b"same data";
        let a = vault.encrypt_bytes(data).unwrap();
        let b = vault.encrypt_bytes(data).unwrap();
        assert_ne!(a, b);
        let _ = Vault::delete("test-encryptman-keyring-bytes-ne");
    }

    #[test]
    #[serial]
    fn encrypt_bytes_context_isolation() {
        let vault = Vault::new("test-encryptman-keyring-bytes-ctx").unwrap();
        let data = b"same data";
        let a = vault.encrypt_bytes_with_context("ctx-a", data).unwrap();
        let b = vault.encrypt_bytes_with_context("ctx-b", data).unwrap();
        assert_ne!(a, b);
        assert!(vault.decrypt_bytes_with_context("ctx-b", &a).is_err());
        let _ = Vault::delete("test-encryptman-keyring-bytes-ctx");
    }

    #[test]
    #[serial]
    fn delete_as_associated_function() {
        let vault = Vault::new("test-encryptman-keyring-del").unwrap();
        let ct = vault.encrypt("test").unwrap();
        Vault::delete("test-encryptman-keyring-del").unwrap();
        assert!(
            Vault::new("test-encryptman-keyring-del")
                .unwrap()
                .decrypt(&ct)
                .is_err()
        );
    }
}
