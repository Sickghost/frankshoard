# Tech Debt

Issues found during a code review (2026-09-29), most important first. Line numbers refer to the code at commit `e1d296e`.

## Design issues

### 1. Argon2 settings live in the config file, not in the vault
`crypto.rs:39-48`, `config/config.example.toml:8`

The key depends on memory, iterations and parallelism, but those are read from `config.toml` on every run. Two ways this locks users out:
- The README suggests lowering the 2 GiB default. Anyone who does that after `init` can no longer open their vault.
- If the config file is lost, `build_config` recreates it with the current defaults. If the defaults ever change, older vaults won't open.

**Fix:** write the settings into the vault header next to the salt and add them to the authenticated header data. Use the config values only when creating a vault or changing the password. This changes the file format, so bump `FORMAT_VERSION`. It also makes it possible to raise a vault's settings later through the password-change path.

### 2. Serializing the vault leaves plaintext copies in freed memory
`vault.rs:309`

`postcard::to_allocvec` builds its output by growing a `Vec`. Each time it grows, the old buffer (serialized plaintext, secrets included) is freed without being zeroed. Only the final buffer is wrapped in `Zeroizing`.

**Fix:** compute the size first (e.g. `postcard::experimental::serialized_size`), then serialize with `to_slice` into a `Zeroizing<Vec<u8>>` allocated at exactly that size.

### 3. The hand-written zeroing loop in `SecretBuf` can be optimized away
`secretbuf.rs:45-49`

`self.0.iter_mut().for_each(|b| *b = 0)` is an ordinary store that the compiler may remove. The `zeroize` crate uses volatile writes to prevent this. The drop path appears to be fine, because the derived `ZeroizeOnDrop` zeroes the `Box<[u8]>` field with the crate's own implementation. Explicit calls such as `self.password.zeroize()` in the `set_*` methods use this loop, though.

**Fix:** change the body to `self.0.zeroize()`. The explicit `zeroize()` calls before reassignment in the `set_*` methods are also redundant: dropping the old value already zeroes it.

### 4. AES key schedule may not be zeroized (known limitation)
The README already lists this as a known limitation. `aes-gcm` 0.10 appears to have a `zeroize` feature. Check whether it also covers the inner `aes` key schedule.

## CLI issues (`main.rs`)

### 5. `add site --note` takes the secret as a command-line argument
`main.rs:118-120`. The secret ends up in shell history and is visible in `ps`. Prompt for it the same way as the password.

### 6. `add note` echoes the secret as you type
`main.rs:267`. `Input::interact_text` shows the text on screen and only accepts a single line.

### 7. "Entry not found" exits with status 0
Affects `remove`, `entry` and the `entry-*` commands. With `--silent`, a script can't tell success from failure.

### 8. A mistyped `--config` path creates a new default config
`main.rs:444-456`. Only auto-create the config at the default location. Fail if a path given explicitly doesn't exist.

### 9. `add` prints the new id before saving
`main.rs:245`. If the save fails, the user has an id for an entry that doesn't exist.

### 10. `lock_in_mem()` in read-only commands does unneeded work
It re-encrypts the vault and then throws the result away. Dropping the `UnlockedHoard` already zeroes everything.

## Smaller points

- **Default Argon2 settings:** 2 GiB is far above the usual recommendations (roughly 19–64 MiB with 2–3 iterations for interactive use) and could run out of memory on smaller machines. Once #1 is fixed, a lower default is safe to change later.
- **Temp file name:** `path.with_extension("tmp")` (`vault.rs:396`) produces the same path as the vault itself if the vault is named `*.tmp`, and the save is then no longer atomic. Append a suffix instead (e.g. `vault.db.tmp`).
- **Rollback edge case in `change_password`:** if the rename succeeds but the directory fsync fails, the in-memory state rolls back while the new vault is already on disk.
- **Serialization format stability:** postcard encodes enum variants by position and fields by order. Reordering `Entry` variants or struct fields will break existing vaults, so bump `FORMAT_VERSION` whenever you do that.
- **Unix only:** `std::os::unix` is used in `config.rs` and `vault.rs`, so the crate won't compile on Windows. Document this in the README.
- **Unused pieces:** `UIConf.session_timeout_seconds`, `MasterKey.creation_time`, and the `MasterPasswordError`, `IllegalState` and `NotImplemented` error variants aren't used yet.

## Tests

### Read-only directory tests can leave temp folders behind
`tests/lib_tests.rs`: `lock_and_save_failed_return_vault` and `change_password_failed_save_preserve_old_vault`.

Both tests make the vault directory read-only so saving fails, then make it writable again so `TempDir` can delete it. If anything panics between those two steps (e.g. `unwrap_err()` because the save unexpectedly succeeded), write access is never restored. `TempDir`'s cleanup then fails silently, and the folder stays in the system temp directory. This only happens when a test is already failing.

**Fix:** use a guard type whose `Drop` restores the permissions. Rust has no `finally`, but `Drop` also runs while a panic unwinds the stack (a failed `assert!` is a panic), so it plays the same role.

```rust
struct ReadOnlyDir<'a>(&'a Path);

impl<'a> ReadOnlyDir<'a> {
    fn new(path: &'a Path) -> Self {
        // set read-only here
        ReadOnlyDir(path)
    }
}

impl Drop for ReadOnlyDir<'_> {
    fn drop(&mut self) {
        // set writable again here; ignore errors, never panic inside drop
    }
}
```

In each test, `let _readonly = ReadOnlyDir::new(vault_dir.path());` replaces both permission blocks. Details:
- Bind it to a name like `_readonly`, not `_`: `let _ = ...` drops the guard immediately.
- Locals are dropped in reverse declaration order, so the guard (declared after `vault_dir`) restores write access before `TempDir` deletes the folder.
- Don't `unwrap()` inside `drop`: panicking while already unwinding aborts the test run.
- Alternative: the `scopeguard` crate's `defer!` macro.
