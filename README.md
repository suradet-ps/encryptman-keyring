# encryptman-keyring

[![Crates.io](https://img.shields.io/crates/v/encryptman-keyring.svg)](https://crates.io/crates/encryptman-keyring)
[![Documentation](https://docs.rs/encryptman-keyring/badge.svg)](https://docs.rs/encryptman-keyring)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

OS keychain-backed master key storage for [encryptman](https://crates.io/crates/encryptman).

## Features

- **Zero file management** — master key stored in OS keychain, no `.key` files on disk
- **Cross-platform** — Windows Credential Manager, macOS Keychain, Linux Secret Service
- **One-call setup** — `Vault::new("my-app")` generates or loads the key automatically
- **File migration** — `Vault::migrate_from_file()` imports existing key files and deletes them
- **Domain isolation** — service name used as HKDF context for encryptman
- **Secure by default** — `MasterKey` with zeroize-on-drop, never written to disk

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
encryptman-keyring = "0.1"
```

## Quick Start

```rust
use encryptman_keyring::Vault;

// First call: generates key → stores in OS keychain
// Later calls: loads existing key from keychain
let vault = Vault::new("my-app").unwrap();

let encrypted = vault.encrypt("my_database_password").unwrap();
let decrypted = vault.decrypt(&encrypted).unwrap();

assert_eq!(decrypted, "my_database_password");

// Delete the key from the keychain when no longer needed
Vault::delete("my-app").unwrap();
```

## Usage

### Binary data

```rust
use encryptman_keyring::Vault;

let vault = Vault::new("my-app").unwrap();

let data = b"binary secret data";
let encrypted = vault.encrypt_bytes(data).unwrap();
let decrypted = vault.decrypt_bytes(&encrypted).unwrap();

assert_eq!(decrypted, data);
```

### Multiple contexts with one vault

```rust
use encryptman_keyring::Vault;

let vault = Vault::new("my-app").unwrap();

let db_secret = vault.encrypt_with_context("database", "postgres://...").unwrap();
let api_secret = vault.encrypt_with_context("api-keys", "sk-12345").unwrap();

// Same plaintext, different contexts → different ciphertext
assert_ne!(db_secret, api_secret);

// Decrypt with the matching context
let db_plain = vault.decrypt_with_context("database", &db_secret).unwrap();
```

### Custom target (username)

```rust
use encryptman_keyring::Vault;

// Store separate keys for different users / environments
let dev_vault = Vault::new_with_target("my-app", "development").unwrap();
let prod_vault = Vault::new_with_target("my-app", "production").unwrap();
```

### Migrating from file-based keys

```rust
use encryptman_keyring::Vault;

// Reads .key → stores in keychain → deletes the file
let vault = Vault::migrate_from_file("my-app", std::path::Path::new("/path/to/.key")).unwrap();
```

## How It Works

```text
Vault::new("my-app")
    │
    ├── keyring::Entry::new("my-app", "master-key")
    │       │
    │       ├── get_secret() → OK → MasterKey::from_bytes()
    │       └── get_secret() → NoEntry → MasterKey::generate() → set_secret()
    │
    └── encryptman::encrypt / decrypt using the master key
```

- **Key Storage**: Master key (32 bytes) stored in the OS native credential store.
- **Key Derivation**: encryptman uses HKDF-SHA256 with `"encryptman:{service}"` as context.
- **Encryption**: AES-256-GCM with random 12-byte nonces.

## Platform Notes

| Platform | Credential Store | Notes |
|----------|-----------------|-------|
| Windows | Credential Manager | Requires Windows Vista or later |
| macOS | Keychain | May prompt for keychain unlock on first access |
| Linux | Secret Service (DBus) | Requires a Secret Service provider (GNOME Keyring, KeePassXC) |

## When NOT to use this crate

- **Headless / CI environments** — the OS keychain may not be available.
- **Multi-user servers** — keyring entries are per-user; consider a shared
  secret store like Vault or AWS Secrets Manager.

## Minimum Supported Rust Version

MSRV: **1.85** (edition 2024)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
