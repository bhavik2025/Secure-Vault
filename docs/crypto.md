# SecureVault cryptographic design

> **SecureVault is NOT a zero-knowledge system.** The server holds the key-encryption keys (KEKs) and
> can decrypt every secret. Protection comes from encryption at rest, strict authorization, device and
> lockdown gates, and audit. A person with control of the running server *and* its key configuration can
> read secrets. This is a deliberate, documented decision (Phase 1, decision 1).

## 1. Envelope encryption

```
secret --AES-256-GCM(DEK, fresh 12-byte nonce, AAD)--> payload
DEK    --AES-256-GCM(KEK_v, fresh 12-byte nonce, AAD)--> wrapped_dek       (v = kek_version, stored)
```

| Item | Detail |
|---|---|
| Cipher | AES-256-GCM from the audited `cryptography` library. No custom primitives. |
| DEK | New random 256-bit key **per encryption** (so per create and per rotation). A DEK never encrypts two values. |
| Nonce | 12 random bytes from `os.urandom` for **every** AES-GCM operation (payload and wrap). The single choke point is `_new_nonce()`. |
| KEK | 256-bit, versioned (`VAULT_KEK_V1`, `V2`, ...), loaded from the environment. New data uses the *active* version. |
| Blind-index key | A **separate** 256-bit secret (`VAULT_BLIND_INDEX_KEY`). Config validation rejects a blind key equal to any KEK. |
| Audit HMAC key | A third, unrelated secret (`AUDIT_HMAC_KEY`) for the audit hash chain. |

### Stored format (v1) — identical for `payload` and `wrapped_dek`
```
byte 0       format version (0x01)
bytes 1-12   nonce
bytes 13-28  GCM authentication tag (16)
bytes 29-    ciphertext (same length as plaintext)
```
Per record the database holds: the payload blob (`password_enc` / `content_enc`), `wrapped_dek` (61 bytes),
`kek_version`, `enc_format`. The record's `uid` (UUID) is generated before the first save.

### Associated data (AAD) — stops copy/paste attacks
Both layers authenticate their context, so moving ciphertext in the database does not yield plaintext:

- payload AAD = `SV1|payload|<purpose>|<organization id>|<record uid>`
- wrapped-DEK AAD = `SV1|dek|<purpose>|<organization id>|<record uid>|kek<version>`

`purpose` is `credential.password` or `secure_note.content`. Copying a ciphertext (or wrapped key) to another
record, field or organization fails authentication. Both layers are tested independently.

### Error behaviour
Tampered ciphertext, tag, nonce, format byte, truncation, wrong context or wrong key -> `DecryptionError`
(a single generic message). Missing or malformed key configuration -> `CryptoConfigError` and **nothing is
encrypted or decrypted** (fails closed). Error messages never contain key material or plaintext.

## 2. Blind index (password-reuse detection)
`blind_index = HMAC-SHA-256(blind_key, "SV1|blind|credential.password|<org id>|" + NFC(password))`.

**Why it exists:** to tell *the same owner* that two of their own credentials share a password, without
decrypting. **It is exposed only as `reused_in_my_vault` and only within the owner's own vault.**
Never across users: an org-wide "is this reused?" answer would let anyone test guesses (create a credential
with a guess and see whether a colleague holds it).

**Limitations (be ready to explain these):**
1. *Deterministic:* equal passwords give equal indexes, so anyone who can read the table sees which of a
   user's (and across users, which of the organization's) credentials share a password, even without any key.
2. *Offline guessing:* if the blind-index key leaks, low-entropy passwords can be brute-forced against the indexes.
3. *Equality only:* no prefix, substring, case-insensitive or fuzzy search. Titles, usernames and tags
   are plaintext metadata and are searched directly.
4. *Rotation is expensive:* changing the blind key means decrypting and re-indexing every credential
   (no command exists yet; planned with the reveal pipeline).
5. It is not used for secure notes, and the index value is never returned by the API or logged.

## 3. Key management

### Generate (once, at setup)
```powershell
cd backend
.\.venv\Scripts\python.exe manage.py generate_vault_keys
```
Paste the three lines into `.env` (git-ignored). Never commit keys. `manage.py check` validates the
configuration (warning if absent, error if invalid).

### Store
- Development: `.env` file. Test settings use obviously fake fixed keys.
- **Production requires a KMS or HSM** (for example AWS KMS, Azure Key Vault, GCP KMS or HashiCorp Vault).
  The KEK should never sit in an environment file next to the application. A KMS/HSM also gives
  access policy, audit of key use, and hardware protection. Plan: KMS-backed `unwrap` replaces the
  environment lookup in `load_keyring()`. **Not implemented in this MVP.**
- Keep the three secrets separate from each other and from database backups.

### Rotate a KEK (cheap; plaintext is never touched)
```powershell
.\.venv\Scripts\python.exe manage.py generate_vault_keys --kek-version 2   # add VAULT_KEK_V2 to the environment
# set VAULT_KEK_ACTIVE_VERSION=2 and restart; new data now uses v2
.\.venv\Scripts\python.exe manage.py rewrap_vault_keys --dry-run
.\.venv\Scripts\python.exe manage.py rewrap_vault_keys
# only after it reports 0 remaining and a backup exists: remove VAULT_KEK_V1
```
Re-wrapping decrypts only the 32-byte DEK; the payload is not rewritten. It is idempotent and
per-record transactional. If an old KEK was removed too early it fails loudly and changes nothing.

### Backup and recovery
- **Losing the KEKs means losing every secret permanently.** Back them up (encrypted, offline or in the KMS)
  *separately* from database backups. A database backup alone is useless to a thief, which is the point;
  storing keys inside the same backup defeats it.
- Restore procedure: restore the database, provide the KEK versions referenced by `kek_version` in the data,
  run `manage.py check`, then spot-check a record via the (future) authorized reveal path.
- Retain every KEK version still referenced until `rewrap_vault_keys` has moved all records off it.

## 4. Limits and assumptions
- Random 96-bit nonces under one key are safe up to roughly 2^32 operations. Each KEK wraps one DEK
  per create/rotation; rotate the KEK long before that bound (billions of operations).
- Python cannot reliably wipe memory: plaintext may remain in process memory until garbage-collected.
  Functions that handle plaintext are marked `@sensitive_variables` so Django debug pages hide their locals.
- Entropy figures stored with a credential (`entropy_bits`) are heuristic estimates and reveal approximate
  strength to anyone with database read access.
- `username` is stored in plaintext by design (display and search).
- No reveal path exists yet. `services.unseal_for_reveal` is internal; no route calls it. It will be exposed only
  through the full authorization pipeline (authn -> status -> permission/grant -> device -> anomaly -> lockdown -> audit).
- Responses from vault endpoints carry `Cache-Control: no-store`. The browser must not persist secrets in
  localStorage/sessionStorage/IndexedDB (frontend rule for the UI phase).
- Not yet implemented: KMS/HSM integration, blind-index key rotation, envelope format migration tooling
  (the format byte makes it possible).
