# cTLS Core Architecture

Cross-platform certificate isolation toolkit: scan → vault → enforce.
CLI-only workspace (no desktop UI). Windows and Linux are the active
development targets; mobile store support is incomplete.

## Workspace

The CLI currently owns config discovery and command orchestration. Before
adding a panel or remote API, move these operations into a service library
with centralized authentication, authorization and status transitions. The
admin endpoint currently exposes status only, over loopback mTLS.

The gateway validates a separate preflight TLS connection using allowed Vault
roots and hostname checks. Its CONNECT data connection is an independent raw
tunnel, and the actual handshake is not inspected. A server can present a
different certificate between these connections. It is experimental and
cannot be relied on as a trust enforcement boundary. Trust is snapshotted at
gateway startup, so policy changes require restart.

| Crate | Role |
|---|---|
| `ctls-core` | X.509 parse, SHA-1/SHA-256 fingerprints, `CaRecord`, PEM/DER importer (partial PKCS#7 support), policy engine + `policy.json` schema, SPKI pin helper, official-CA cache schema (`official-ca.json`) |
| `ctls-platform` | Cross-platform `PlatformStore` trait + per-OS backends (windows/linux/android/ios), `current_store()` |
| `ctls-platform-win` | Windows CertStore reader/exporter/install/remove, backup/restore, purger, watchdog (consumed by `ctls-platform` on Windows) |
| `ctls-sync` | CCADB downloader: `AllIncludedRootCertsCSV` + `MozillaTLSServerAuthenticationCSV`, CSV parse, atomic cache, stale-if-error |
| `ctls-scanner` | Classification (OFFICIAL/CURATED/THIRD-PARTY/UNKNOWN) + AV-style heuristics + allow/block lists + scan profiles (strict/default/lenient) |
| `ctls-vault` | SQLite vault; DER encrypted with AES-256-GCM; key backend abstraction (TPM → DPAPI → 0600 file, recorded, never switched silently) + seal/unseal; status column + **hash-chained, HMAC-signed audit_log** with `verify_audit_chain` |
| `ctls-repo` | `rca.gov.ir` HTML client; SSRF-guarded download (https + host allowlist + redirect policy) |
| `ctls-enforce` | Local HTTP CONNECT verify-proxy (gateway) + **localhost mTLS admin channel** (internal CA, sealed key, SPKI pin) + system proxy helpers (Windows registry; stub elsewhere) |
| `ctls-cli` | Command-line front-end (`ctls` binary), incl. policy/drift/reeval commands, **server mode** (`ctls run` + `config.json`) |

Data dir: `%USERPROFILE%\.ctls\` (`$HOME/.ctls` on Unix; override `CTLS_DATA_DIR`
or `config.data_dir`).

- `vault.db` — encrypted vault
- `official-ca.json` — CCADB official-root cache (written by `ctls sync`)
- `allowlist.json` / `blocklist.json` — scanner lists (no BOM)
- `policy.json` — optional Policy-as-Code rules (see below)
- `drift-baseline.json` — optional drift snapshot (`ctls drift init`)
- `internal-ca/` — internal CA for the mTLS admin channel:
  `ca.crt.der` (public), `ca.key.sealed` (CA key sealed by the vault
  master key), `admin.spki.sha256` (served-leaf pin)
- `backups/` — full store dumps before purge/restore *(Windows)*
- `config.json` — optional server config in the data dir (discovered
  after `/etc/ctls/config.json`; see “Server mode” below)

## Official-CA sync (`ctls-sync`)

```
ctls sync [--force] [--max-age-days N] [--status]
ctls scan --sync          # refresh if cache older than 7 days (non-fatal on error)
```

1. Sources (https, in order): `AllIncludedRootCertsCSV`,
   `MozillaTLSServerAuthenticationCSV`.
2. CSV → SHA-256 fingerprints (column matched by normalized header
   `*sha256*fingerprint*`; quoted multi-line PEM cells handled by the `csv`
   crate; SHA-1/short values rejected).
3. Union of successful sources → `OfficialCaCache` → atomic write
   (`official-ca.json.tmp` + rename).
4. **Stale-if-error**: downloads failed but cache exists → old cache kept,
   report `stale=true`; no cache at all → `SyncError::NoData`.
5. Fresh cache (`< max_age_days`) short-circuits unless `--force`.

## Scan pipeline

1. Enumerate system stores via `ctls_platform::current_store()`:
   - Windows: `COMMON_STORES` (CurrentUser/LocalMachine × Root, CA, My,
     AuthRoot, …).
   - Linux: `/etc/ssl/certs`, `/usr/share/ca-certificates`,
     `/usr/local/share/ca-certificates` + bundles (`ca-certificates.crt`, …).
   - Android: `/system/etc/security/cacerts` (+ user dir when readable).
   - iOS: empty (sandbox).
2. Parse DER → `CaRecord` (subject, issuer, validity, key, sigalg).
3. `scan_record(&record, &lists)` → `TrustLevel` + `CaClassification` +
   reasons, in order:
   - **hard rules**: fingerprint blocklist → Blocked; subject/issuer name rule
     (`diginotar`, `superfish`) → Blocked
   - **validity**: expired or not-yet-valid → Suspicious even when listed;
     provenance classification remains independent of this verdict
   - **positive lists**: SHA-256 ∈ official cache → Safe+OFFICIAL;
     SHA-1 ∈ allowlist → Safe+CURATED
   - **heuristics** (any hit → Suspicious): weak SHA1/MD5 signature, small
     key (<2048 RSA / <256 EC), self-signed without CA constraint,
     implausible validity, **recent self-signed root** (<180 days)
   - clean but unlisted: self-signed → Suspicious+THIRD-PARTY,
     issued → Unknown+UNKNOWN
   - `scan_record_profiled(.., profile)` applies a **scan profile** on
     top of the base verdict: `strict` promotes Unknown→Suspicious,
     `lenient` demotes Suspicious→Unknown (classification and hard
     blocks are never changed by a profile).
4. Classification is computed independently of the verdict — a user-blocked
   official root still shows `OFFICIAL`.
5. CLI can promote a store cert into the Vault (`accept-sha1`).

Priority: **isolation first**, validation second (lightweight AV-style first
pass); the CCADB set provides the authoritative "official" signal.

## Vault

- One SQLite row per cert; unique SHA-1.
- DER ciphertext: AES-256-GCM (random nonce per row).
- Master key: 32 bytes, held in `Zeroizing`; protection per OS
  (`ctls_vault::key_backend`, name recorded in `meta` and in audit; an
  existing vault **always** unwraps with its recorded backend — a failure
  is a hard error, never a silent re-encrypt):
  - **Windows**: TPM ("Microsoft Platform Crypto Provider", non-exportable
    RSA-2048 wrap key, OAEP-SHA256) → on failure DPAPI (user scope) with
    `degraded=true` noted in audit. New keys are self-tested (canary blob)
    before use.
  - **Unix/Linux**: identity wrap + db/dir modes `0600`/`0700`.
    The master key is stored without cryptographic wrapping on Unix:
    filesystem ownership and permissions are its protection. Android
    Keystore / iOS Keychain integration is planned.
  - Legacy blobs without a backend name open with the platform default
    and record one `key.backend (legacy)` audit row.
- `status` column (policy): `ALLOW` | `QUARANTINE` | `BLOCK` | `PENDING`.
  - Migration backfills legacy `BLOCKED` rows to `BLOCK`; other `PENDING`
    rows remain isolated. Existing explicit statuses remain unchanged.
  - Duplicate imports preserve the original row and status. SQLite transactions
    couple vault mutations with audit writes and serialize open/migration.
  - `allowed_fingerprints()` returns **only** `status='ALLOW'` (fail-safe).
  - `quarantined_fingerprints()` returns `QUARANTINE|PENDING|BLOCK`.
- `audit_log` table: append-only (SQLite triggers abort UPDATE/DELETE) and
  **hash-chained**: each row stores `prev_hash`, `entry_hash` =
  `sha256(prev ‖ "ctls-audit-v1" ‖ fields)` and `sig` =
  `HMAC-SHA256(master_key, entry_hash)`. Backfill of legacy rows happens
  on open (`migrate_audit_chain`); `verify_audit_chain()` reports
  totals/hmac failures and powers `ctls vault verify-audit` (exit 2 on
  tamper).
  - records import / remove / set-status / install / purge / reeval /
    drift with actor + detail; the vault-open row records the key backend.
- `set_status(sha1, status)` — policy transition, audited.
- `seal(bytes)` / `unseal(blob)` — AEAD-wrap arbitrary secrets (e.g. the
  internal CA key) under the same master key.

### Policy engine (`ctls_core::policy`)

| Status | `PolicyAction` |
|---|---|
| `ALLOW` | `ApplyToSystem` |
| `QUARANTINE` / `PENDING` | `KeepIsolatedOnly` |
| `BLOCK` | `Purge` |

- `status_from_trust(level)`: Safe→Allow, Blocked→Block, Suspicious/Unknown→Quarantine.
- `status_for_explicit_import(level)`: user accept may promote non-blocked → Allow;
  Blocked stays Block.
- File, URL and repository imports default to Quarantine (Block when flagged),
  unless a validated policy explicitly grants Allow. `accept-sha1` represents
  an explicit user approval.
- **Policy as Code** — optional `policy.json` in the data dir:

```json
{
  "version": 1,
  "default_action": null,
  "rules": [
    { "name": "block-superfish", "match": { "name_contains": "superfish" }, "action": "BLOCK" },
    { "name": "quarantine-3p",   "match": { "classification": "THIRD-PARTY" }, "action": "QUARANTINE" }
  ]
}
```

  - `PolicyFile::load_from(data_dir)`: missing file → `Ok(None)` (built-in
    mapping stays); broken file → `Err` (fail closed — the command stops).
  - `decide(subject, issuer, level, classification)` → first matching rule,
    then `default_action`, then `None` (caller falls back to the built-in
    mapping). Fields match case-insensitively.
  - Validation rejects empty matches, unknown classification/level values,
    and `ALLOW` granted by classification/level alone (ALLOW must name a
    subject/issuer pattern).
  - Applied on every import path. File, URL and repository imports fall
    back to Quarantine; `accept-sha1` is explicit user approval and uses
    `status_for_explicit_import`. Re-evaluation uses `status_from_trust`.
  - **Invariant**: the scanner blacklist / hard blocks always run *before*
    policy — a policy can never un-Block what the scanner blocked, and a
    rule can only *worsen* a status automatically (upgrades are suggested
    by reeval, never applied).
- **Drift** (`ctls-cli/src/drift.rs`): `drift init` snapshots
  (sha1, subject, status, trust_level) to `drift-baseline.json`;
  `drift check` diffs added/removed/status-changed and exits `2` on
  drift (both audited).

## Purger

- Target store: **only** `LocalMachine\Root`.
- Two-pass: READ-ONLY enumerate → decision, then single READ-WRITE open → delete by SHA-1.
- `preview_purge(allowed)` — dry-run counts (`ctls preview-purge`).
- `purge_untrusted` (real):
  - requires **admin** (`is_admin`)
  - always `backup_all` first under `~\.ctls\backups\pre-purge`
  - removes certs whose SHA-1 ∉ vault `ALLOW` set
  - writes `audit_log` entry
- Real purge is CLI only (`ctls purge`) after explicit user action.
  Restore: `ctls restore <dir>` (admin).

## PlatformStore (`ctls-platform`)

```rust
pub trait PlatformStore: Send + Sync {
    fn platform_name(&self) -> &'static str;              // windows|linux|android|ios
    fn list_system_cas(&self) -> Result<Vec<CaRecord>, PlatformError>;
    fn export_der(&self, sha1: &str) -> Result<Vec<u8>, PlatformError>;
    fn install_ca(&self, der: &[u8], store: &str, loc: StoreLocation) -> Result<(), PlatformError>;
    fn remove_ca(&self, sha1: &str, store: &str, loc: StoreLocation) -> Result<bool, PlatformError>;
    fn can_modify(&self) -> bool;
}
```

| OS | backend | list | install/remove |
|---|---|---|---|
| Windows | `ctls-platform-win` (CertStore) | yes | yes (admin for LocalMachine) |
| Linux | `/etc/ssl/certs` + bundles + `/usr/local/share/ca-certificates` | yes | yes (root; runs `update-ca-certificates`/`update-ca-trust`) |
| Android | `/system/etc/security/cacerts` | yes | `NotSupported` (apps can't write system trust; mobile UI will use DevicePolicyManager) |
| iOS | sandbox stub | empty | `NotSupported` (MDM profiles) |

- Callers (CLI, future UIs) never touch CertStore APIs / paths directly.
- CLI: `ctls install-sha1 <sha1> [Store] [Loc]` (audited).
- **Optional** — Gateway does not require installing certs into the OS store.

## Gateway (no content MITM)

```
App ──HTTP CONNECT──► Gateway :127.0.0.1:18080
                        │
                        ├─(1) separate rustls client → target
                        │      verify hostname + chain against ALLOW roots
                        │
                        ├─(2) if ALLOW → fresh raw TCP splice (app ⇄ target)
                        │      bytes never decrypted
                        └─(3) if DENY  → close both sides
```

Trust check (Vault-backed): rustls validates the preflight TLS handshake,
certificate signatures, validity period and hostname against CA certificates
with Vault status `ALLOW`. An invalid allowed DER prevents gateway startup.
The tunneled connection remains unverified by the gateway (see limitation
above).

Notes:

- rustls crypto provider forced to `ring` (`ensure_crypto_provider`) because
  feature unification may also enable `aws-lc-rs`.
- Bytes after `\r\n\r\n` in CONNECT headers (pipelined TLS ClientHello) are
  replayed to upstream.
- Upstream connect failure → HTTP 502 (then socket shutdown).
- Optional WinINET system proxy (`ProxyEnable`/`ProxyServer` in HKCU);
  disabled again on gateway stop (`ctls_enforce::disable_system_proxy`).
- **Gateway never installs certificates into the OS store** — it only reads the vault.
- Apps with pinning or private trust stores (e.g. Firefox) bypass the OS
  store and this proxy’s enforcement path for their own decisions.

### Admin endpoint (mTLS, localhost only)

```
ctls gateway status ──mTLS──► Gateway :127.0.0.1:18081 /status (JSON)
        │                         │
        │  (1) client cert must chain to the internal CA
        │  (2) client pins the served leaf's SPKI (admin.spki.sha256)
        └── internal-ca/ca.key.sealed is unwrapped by the Vault master key
```

- First gateway start generates an internal CA (ECDSA P-256, 20-year
  validity); its private key is **sealed** with the vault master key — no
  raw CA key on disk.
- Per run: a fresh short-lived leaf (1 day) is issued for
  `localhost`/`127.0.0.1` with `serverAuth+clientAuth` EKUs; its SPKI
  pin is written to `internal-ca/admin.spki.sha256`.
- The server requires a client certificate (`WebPkiClientVerifier` rooted
  *only* at the internal CA); the client refuses a leaf whose SPKI does
  not match the pin — both directions are pinned.
- `GET /status` returns JSON: proxy/admin listen addrs, allowed/
  quarantined/total counts, `mtls` version tag, key backend name.
- Admin setup failure aborts gateway startup (**fail closed**); disable
  with `ctls gateway --no-admin`.
- No certificate is ever installed into the OS trust store.

CLI:

```powershell
ctls gateway [port] [--admin-port N] [--no-admin]   # default 18080 + admin 18081
ctls gateway status [addr]                          # fetch /status over mTLS
```

## Server mode (`ctls run` + `config.json`)

xray-style entry point for service deployments (install layout + systemd
unit: [SERVER.md](SERVER.md)):

```
ctls run [-c config.json] [--test]    # foreground server (systemd-friendly)
ctls config init [-c path] [--force]  # write default config.json
ctls config show                      # effective config + resolved paths
ctls version
```

- Config discovery (first hit wins): `-c/--config` > `$CTLS_CONFIG` >
  `/etc/ctls/config.json` > `<data>/config.json` > built-in defaults.
- Data dir: `$CTLS_DATA_DIR` > `config.data_dir` > `$HOME/.ctls`; the
  resolved dir is pinned once per invocation (`DATA_OVERRIDE`) so every
  command in that invocation agrees on it.
- `ServerConfig` (`ctls-cli/src/config.rs`) is strict —
  `serde(deny_unknown_fields)` — and validated: `listen` must be
  `ip:port`, `admin.listen` **must be loopback** (the status API never
  leaves localhost) and may not collide with `listen`; `data_dir` must be
  absolute. A present-but-broken config fails **every** command
  (fail closed); `version`/`help` bypass it.
- `--test` runs the same pre-flight as `run` (config + `policy.json` +
  vault + internal CA/pin build) and exits without serving.

## Repo client SSRF guard (`ctls-repo`)

- `validate_download_url`: **https only** + host allowlist
  (`DEFAULT_ALLOWED_HOSTS = rca.gov.ir, www.rca.gov.ir`; extend via
  `RcaClient::with_allowed_hosts`).
- Custom redirect policy: max 3 hops; each hop must stay https + allowlisted host.
- `connect_timeout(10s)`, overall timeout 30s.
- `download_and_verify(url, sha1?)` parses via `ctls_core::load_certificates`
  (PEM bundle / DER; PKCS#7 `.p7b` support is incomplete).

## CLI commands

See `ctls help` and [GUIDE.md](GUIDE.md).

| Area | Commands |
|---|---|
| Scan | `scan [--sync] [--profile strict\|default\|lenient] [Store] [Loc]`, `scan-system`, `count` |
| Sync | `sync [--force] [--max-age-days N] [--status]` |
| Vault | `vault list`, `vault count`, `vault set-status`, `vault audit`, `vault verify-audit`, `vault reeval [--profile …]` |
| Policy | `policy show`, `policy validate` |
| Drift | `drift init [--force]`, `drift check` (exit 2 on drift) |
| Import | `import-file`, `import-url`, `accept-sha1`, `repo list`, `repo pull` |
| Install | `install-sha1`, `export-sha1` |
| Purger *(Windows)* | `backup`, `restore`, `preview-purge`, `purge` |
| Gateway | `gateway [port] [--admin-port N] [--no-admin]`, `gateway status [addr]` |
| Server | `run [-c file] [--test]`, `config init [-c file] [--force]`, `config show`, `version` |
| Watch *(Windows)* | `watch [seconds]` |

Non-Windows builds report `Windows-only in this build` for purger/watch
commands instead of failing deep inside FFI.

## Build / install

```powershell
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# optional global install
cargo install --path crates/ctls-cli
```

## Safety invariants

1. Never mutate system stores without a full backup.
2. Purge needs admin + backup; preview never writes.
3. Gateway does not decrypt application traffic and does not install certs.
4. The Vault master key is unwrapped in process memory and wiped with
   `Zeroizing`. On Windows it uses TPM or DPAPI; on Unix it is stored
   unwrapped in the database and protected by owner-only filesystem modes.
   An existing vault only unwraps with its recorded backend.
5. Fail-safe policy: only explicit `status='ALLOW'` leaves isolation.
6. `audit_log` is append-only (SQLite triggers) **and** hash-chained +
   HMAC-signed — `ctls vault verify-audit` exits 2 on any tamper.
7. Repo downloads: https + host allowlist + redirect guard + 8 MiB cap.
   DNS rebinding and trust in explicitly added hosts need separate review.
8. CCADB sync: https only, atomic cache write, stale-if-error — a failed
   download never wipes a good local snapshot.
9. The gateway admin endpoint is localhost-only, requires an internal-CA
   client certificate, and clients pin the served leaf's SPKI; admin
   setup failure aborts gateway startup (fail closed).
10. Scanner hard blocks beat policy. A policy can explicitly grant ALLOW
    on import; re-evaluation only auto-downgrades existing statuses and
    suggests upgrades for manual review.
11. Server config is fail-closed: unknown fields are rejected, a
    present-but-broken `config.json` stops operational commands (`help`,
    `version`, and `config init` bypass discovery), and
    `admin.listen` is validated to be loopback — a config typo can never
    expose the admin endpoint to a network.
