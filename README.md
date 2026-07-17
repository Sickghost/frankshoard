# Frankshoard

A secure, offline password vault written in Rust.

---

## About

`frankshoard` is a local password manager built as a hands-on Rust learning project, with a deliberate focus on getting the security design right from the ground up. Rather than relying on external frameworks for the security-critical components, the vault is designed with well-understood, modern cryptographic primitives chosen for their security properties.

---

## Building

```bash
git clone https://github.com/Sickghost/frankshoard
cd frankshoard
cargo build
```

Requires Rust stable (1.85+).

---

## Usage

Assuming the binary is in your path, invoke help on it.

```bash
frankshoard --help
```

Note that when executing a command, by default it will look for a config file in `~/.config/frankshoard`.  You can provide a path to the config file via the CLI. If no configuration file are present, a default one is created. The default setting uses 2 GiB (2097152 KiB) of memory to derive the key. Even on a good computer this can take quite some time so you may want to change the default to something more reasonable.

See `config/config.example.toml` to create and customize your own.

## Design

Security decisions are documented here:

**Key Derivation**
- Master password is never stored directly
- Keys are derived using **Argon2id** 
- Argon2id is preferred over PBKDF2 or bcrypt due to its memory-hardness, which significantly raises the cost of GPU-based brute-force attacks

**Vault Encryption**
- Vault contents are encrypted using **AES-256-GCM** (Authenticated Encryption with Associated Data)
- AES-GCM provides both confidentiality and integrity — any tampering with the ciphertext is detectable
- A unique nonce is generated per encryption operation

**Nonce Handling**
The nonce is handled by the encryption/decryption algorithm.  It is prepended to the encrypted data and is part
of the blob returned by the encryption function. This way, it is entirely managed by `crypto.rs` and it becomes easier to ensure that it is only ever used once.

**AAD binding**
The magic, format version, and salt are authenticated as associated data, so header tampering and version-downgrade attempts fail decryption.

**Secrecy Crate**
- The secrecy crate is not used by choice. I wanted to build the zeroizing discipline by hand as the learning exercise.

### CLI
The CLI is intended as an example of how the library should be used and not as a truly secure interface. Second it's not properly scripting ready either, that would require TTY detection. I may add that in the future if the fancy takes me (or if, against all odds, some random person asks for the feature)

---

## Motivation

This project serves two purposes:

1. **Learning Rust** — particularly ownership, borrowing, error handling, and working with low-level cryptographic libraries in a safe systems language
2. **Applying security engineering principles** — designing a system where security is a foundational constraint, not an afterthought

The combination of Rust's memory safety guarantees and carefully chosen cryptographic primitives makes this a practical exercise in building software that is both correct and secure.

---
## Known Limitations

- This library does not prevent memory swap of cleartext.  This means that cleartext is zeroized after use, copies of it could live in swapped-out pages somewhere.  We intend to protect against that (with mlock) at some point, but so far it's not on the road map.
- The master key is zeroized, but the AES cipher object's expanded key schedule may not be.  This requires more investigation.

## Roadmap

- [x] Project structure and configuration layer
- [x] Vault storage and entry management
- [x] Argon2id key derivation
- [x] AES-256-GCM encryption/decryption
- [x] Public API layer (Master password change with vault re-encryption, list, add, delete, edit)
- [x] CLI interface
- [x] Add "silent mode"
- [x] Integration Test Suite
- [ ] Add a TUI (ratatui)
- [ ] Add a threaded timer to manage master_key lifecycle. (tokio)

---


## License

BSD-3-Clause
