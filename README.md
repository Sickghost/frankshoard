# frankshoard

A secure, offline-first password vault written in Rust.

**Status:** Work in progress — check develop branch for updates.  Won't merge into main until I have a minimally working version.

---

## About

`frankshoard` is a local password manager built as a hands-on Rust learning project, with a deliberate focus on getting the security design right from the ground up. Rather than relying on external frameworks for the security-critical components, the vault is designed with well-understood, modern cryptographic primitives chosen for their security properties, not just their availability.

The name is a portmanteau of *Frank* (the author) and *hoard* — a personal stash of secrets, kept offline and under your control.

---

## Security Design

Security decisions are made deliberately and documented here:

**Key Derivation**
- Master password is never stored directly
- Keys are derived using **Argon2id** — the winner of the Password Hashing Competition and the current recommended standard for password-based key derivation
- Argon2id is preferred over PBKDF2 or bcrypt due to its memory-hardness, which significantly raises the cost of GPU-based brute-force attacks

**Vault Encryption**
- Vault contents are encrypted using **AES-256-GCM** (Authenticated Encryption with Associated Data)
- AES-GCM provides both confidentiality and integrity — any tampering with the ciphertext is detectable
- A unique nonce is generated per encryption operation

**Offline First**
- No network calls, no cloud sync, no third-party servers
- Your vault never leaves your machine

---

## Architecture

The project is structured around the following modules:

- **config** — handles application configuration, paths, and user preferences
- **vault** — core vault storage, entry management, and serialization *(in progress)*
- **crypto** — cryptographic primitives: Argon2id key derivation and AES-GCM encryption/decryption *(planned)*
- **cli** — command-line interface for interacting with the vault *(planned)*

---

## Motivation

This project serves two purposes:

1. **Learning Rust** — particularly ownership, borrowing, error handling, and working with low-level cryptographic libraries in a safe systems language
2. **Applying security engineering principles** — designing a system where security is a foundational constraint, not an afterthought

The combination of Rust's memory safety guarantees and carefully chosen cryptographic primitives makes this a practical exercise in building software that is both correct and secure.

---

## Roadmap

- [x] Project structure and configuration layer
- [ ] Vault storage and entry management
- [ ] Argon2id key derivation
- [ ] AES-256-GCM encryption/decryption
- [ ] CLI interface
- [ ] Master password change with vault re-encryption
- [ ] Export/backup functionality

---

## Building

```bash
git clone https://github.com/Sickghost/frankshoard
cd frankshoard
cargo build
```

Requires Rust stable (1.70+).

---

## License

BSD-3-Clause
