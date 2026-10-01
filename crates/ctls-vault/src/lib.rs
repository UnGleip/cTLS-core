use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use ctls_core::CaRecord;

mod key_backend;

const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("sqlite: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("key backend: {0}")]
    Backend(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: i64,
    pub subject: String,
    pub issuer: String,
    pub sha1_fingerprint: String,
    pub sha256_fingerprint: String,
    pub not_before: String,
    pub not_after: String,
    pub is_ca: bool,
    pub self_signed: bool,
    pub trust_level: String,
    pub source: String,
    pub added_at: String,
    pub der_len: usize,
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: String,
    pub actor: Option<String>,
    pub action: String,
    pub detail: Option<String>,
}

/// Result of [`Vault::verify_audit_chain`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditChainReport {
    pub total: usize,
    pub chained: usize,
    /// Legacy rows written before chain tracking (should be 0 after open).
    pub unchained: usize,
    pub hmac_failures: usize,
    pub first_error: Option<String>,
}

impl AuditChainReport {
    pub fn valid(&self) -> bool {
        self.first_error.is_none() && self.hmac_failures == 0 && self.unchained == 0
    }
}

/// Result of `load_or_create_key`: `(master_key, backend_name, open_event)`.
type LoadedMasterKey = (Zeroizing<[u8; 32]>, &'static str, Option<String>);

pub struct Vault {
    conn: Connection,
    key: Zeroizing<[u8; 32]>,
    path: PathBuf,
    backend_name: &'static str,
}

impl Vault {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, VaultError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            harden_dir(parent)?;
        }
        let mut conn = Connection::open(&path)?;
        harden_file(&path)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT NOT NULL,
                issuer TEXT NOT NULL,
                sha1 TEXT NOT NULL UNIQUE,
                sha256 TEXT NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                is_ca INTEGER NOT NULL,
                self_signed INTEGER NOT NULL,
                trust_level TEXT NOT NULL,
                source TEXT NOT NULL,
                added_at TEXT NOT NULL,
                der_len INTEGER NOT NULL,
                nonce BLOB NOT NULL,
                der_enc BLOB NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING'
            );
            CREATE TABLE IF NOT EXISTS meta (
                k TEXT PRIMARY KEY,
                v BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor TEXT,
                action TEXT NOT NULL,
                detail TEXT,
                prev_hash TEXT NOT NULL DEFAULT '',
                entry_hash TEXT NOT NULL DEFAULT '',
                sig TEXT NOT NULL DEFAULT ''
            );
            "#,
        )?;
        // WAL creates sidecar files; keep their modes private as well.
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{}", path.display(), suffix));
            if sidecar.exists() {
                harden_file(&sidecar)?;
            }
        }
        // Migration: add status column on older DBs, then backfill.
        // Serialize opening/migration across processes, including key creation.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::migrate_status(&tx)?;

        let (key, backend_name, backend_event) = Self::load_or_create_key(&tx)?;
        // Hash-chain migration (reinstalls the append-only triggers after the
        // backfill UPDATE) — must run before the first audit write.
        Self::migrate_audit_chain(&tx, &key)?;
        tx.commit()?;

        let vault = Self {
            conn,
            key,
            path,
            backend_name,
        };
        if let Some(event) = backend_event {
            vault.audit("key.backend", &event)?;
        }
        Ok(vault)
    }

    fn migrate_status(conn: &Connection) -> Result<(), VaultError> {
        let has_col: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('vault') WHERE name='status'",
            [],
            |r| r.get(0),
        )?;
        if has_col == 0 {
            conn.execute_batch(
                "ALTER TABLE vault ADD COLUMN status TEXT NOT NULL DEFAULT 'PENDING';",
            )?;
        }
        // Backfill: explicit vault rows were user-approved unless blocked.
        conn.execute_batch(
            "UPDATE vault SET status='BLOCK' WHERE trust_level='BLOCKED' AND (status='PENDING' OR status='');",
        )?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns `(master_key, backend_name, open_event_for_audit)`.
    /// Existing vaults unwrap with exactly their recorded backend (fail
    /// closed); new keys prefer the TPM on Windows and degrade to DPAPI
    /// with a logged note when it is unavailable.
    fn load_or_create_key(conn: &Connection) -> Result<LoadedMasterKey, VaultError> {
        let stored: Option<String> = conn
            .query_row("SELECT v FROM meta WHERE k='key_backend'", [], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()?
            .map(|bytes| {
                String::from_utf8(bytes)
                    .map_err(|e| VaultError::Backend(format!("invalid backend name: {e}")))
            })
            .transpose()?;

        if let Some(blob) = conn
            .query_row("SELECT v FROM meta WHERE k='key'", [], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()?
        {
            let recorded = stored
                .clone()
                .unwrap_or_else(|| key_backend::platform_default_name().to_string());
            let name = key_backend::canonical(&recorded).ok_or_else(|| {
                VaultError::Backend(format!("unknown key backend recorded: {recorded}"))
            })?;
            let raw = Zeroizing::new(key_backend::unprotect_existing(name, &blob)?);
            if raw.len() != 32 {
                return Err(VaultError::Backend(format!(
                    "master key length {} != 32",
                    raw.len()
                )));
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&raw);
            let event = if stored.is_none() {
                // Legacy vault: record the backend that actually opened it.
                conn.execute(
                    "INSERT OR REPLACE INTO meta(k, v) VALUES('key_backend', ?1)",
                    params![name.as_bytes()],
                )?;
                Some(format!("name={name} degraded=false recorded=legacy"))
            } else {
                None
            };
            Ok((key, name, event))
        } else {
            let existing: i64 = conn.query_row(
                "SELECT (SELECT COUNT(*) FROM vault) + (SELECT COUNT(*) FROM audit_log)",
                [],
                |r| r.get(0),
            )?;
            if existing > 0 || stored.is_some() {
                return Err(VaultError::Backend(
                    "master key missing from existing vault".into(),
                ));
            }
            let mut key = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut key[..]);
            let (name, protected, note) = key_backend::protect_new(&key[..])?;
            conn.execute(
                "INSERT INTO meta(k, v) VALUES('key', ?1)",
                params![protected],
            )?;
            conn.execute(
                "INSERT OR REPLACE INTO meta(k, v) VALUES('key_backend', ?1)",
                params![name.as_bytes()],
            )?;
            let event = Some(match &note {
                Some(n) => format!("name={name} degraded=true created note={n}"),
                None => format!("name={name} degraded=false created"),
            });
            Ok((key, name, event))
        }
    }

    /// Ensure the audit hash-chain columns exist, backfill legacy rows and
    /// (re)install the append-only triggers. Must run before the first
    /// `audit()` call of this process.
    fn migrate_audit_chain(conn: &Connection, key: &[u8; 32]) -> Result<(), VaultError> {
        // The backfill needs UPDATE; drop the append-only triggers first and
        // recreate them afterwards.
        conn.execute_batch(
            "DROP TRIGGER IF EXISTS audit_log_no_update;
             DROP TRIGGER IF EXISTS audit_log_no_delete;",
        )?;
        for col in ["prev_hash", "entry_hash", "sig"] {
            let has_col: i64 = conn.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('audit_log') WHERE name=?1",
                params![col],
                |r| r.get(0),
            )?;
            if has_col == 0 {
                conn.execute(
                    &format!("ALTER TABLE audit_log ADD COLUMN {col} TEXT NOT NULL DEFAULT ''"),
                    [],
                )?;
            }
        }
        // Walk in id order; chain unchained rows under the running hash.
        let rows = {
            let mut stmt = conn.prepare(
                "SELECT id, ts, actor, action, detail, entry_hash FROM audit_log ORDER BY id ASC",
            )?;
            let mapped = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })?;
            let mut v = Vec::new();
            for row in mapped {
                v.push(row?);
            }
            v
        };
        let mut prev = String::new();
        for (id, ts, actor, action, detail, entry_hash) in rows {
            if entry_hash.is_empty() {
                let entry =
                    entry_hash_for(&prev, &ts, actor.as_deref(), &action, detail.as_deref());
                let sig = hmac_hex(key, &entry);
                conn.execute(
                    "UPDATE audit_log SET prev_hash=?1, entry_hash=?2, sig=?3 WHERE id=?4",
                    params![prev, entry.clone(), sig, id],
                )?;
                prev = entry;
            } else {
                prev = entry_hash;
            }
        }
        conn.execute_batch(
            r#"
            CREATE TRIGGER IF NOT EXISTS audit_log_no_update
            BEFORE UPDATE ON audit_log
            BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
            BEFORE DELETE ON audit_log
            BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
            "#,
        )?;
        Ok(())
    }

    fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key[..]));
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, data)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        Ok((nonce_bytes.to_vec(), ct))
    }

    fn decrypt(&self, nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>, VaultError> {
        if nonce.len() != NONCE_LEN {
            return Err(VaultError::Crypto("bad nonce length".into()));
        }
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key[..]));
        let nonce = Nonce::from_slice(nonce);
        cipher
            .decrypt(nonce, ct)
            .map_err(|e| VaultError::Crypto(e.to_string()))
    }

    pub fn contains_sha1(&self, sha1: &str) -> Result<bool, VaultError> {
        let n = ctls_core::normalize_fingerprint(sha1);
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM vault WHERE sha1=?1",
            params![n],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn add(
        &self,
        rec: &CaRecord,
        der: &[u8],
        trust_level: &str,
        source: &str,
    ) -> Result<i64, VaultError> {
        self.add_with_status(rec, der, trust_level, source, None)
    }

    /// Insert once; repeated imports return the existing ID and preserve its status.
    /// Without an explicit status, entries stay isolated (or blocked).
    pub fn add_with_status(
        &self,
        rec: &CaRecord,
        der: &[u8],
        trust_level: &str,
        source: &str,
        status: Option<&str>,
    ) -> Result<i64, VaultError> {
        let sha1 = ctls_core::normalize_fingerprint(&rec.sha1_fingerprint);
        let status = status.map(|s| s.to_string()).unwrap_or_else(|| {
            let level = match trust_level {
                "SAFE" => ctls_core::TrustLevel::Safe,
                "BLOCKED" => ctls_core::TrustLevel::Blocked,
                "SUSPICIOUS" => ctls_core::TrustLevel::Suspicious,
                _ => ctls_core::TrustLevel::Unknown,
            };
            match level {
                ctls_core::TrustLevel::Blocked => "BLOCK",
                _ => "QUARANTINE",
            }
            .to_string()
        });
        let (nonce, enc) = self.encrypt(der)?;
        let added_at = now_iso();
        let tx = self.conn.unchecked_transaction()?;
        let inserted = tx.execute(
            r#"INSERT OR IGNORE INTO vault(
                subject, issuer, sha1, sha256, not_before, not_after,
                is_ca, self_signed, trust_level, source, added_at, der_len, nonce, der_enc, status
            ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
            "#,
            params![
                rec.subject,
                rec.issuer,
                sha1,
                rec.sha256_fingerprint,
                rec.not_before,
                rec.not_after,
                rec.is_ca as i64,
                rec.self_signed as i64,
                trust_level,
                source,
                added_at,
                rec.der_len as i64,
                nonce,
                enc,
                status
            ],
        )?;
        let id: i64 = tx.query_row("SELECT id FROM vault WHERE sha1=?1", params![sha1], |r| {
            r.get(0)
        })?;
        if inserted > 0 {
            self.audit_on(
                &tx,
                "import",
                &format!("sha1={sha1} level={trust_level} status={status} source={source}"),
            )?;
        }
        tx.commit()?;
        Ok(id)
    }

    /// Append-only, hash-chained audit record.
    /// `entry_hash = sha256(prev_entry_hash ‖ domain ‖ ts ‖ actor ‖ action ‖ detail)`,
    /// `sig = HMAC-SHA256(master_key, entry_hash)`. Rows can neither be
    /// updated nor deleted (SQLite triggers), and any tampering with history
    /// breaks the chain or fails HMAC verification (see
    /// [`Vault::verify_audit_chain`]).
    pub fn audit(&self, action: &str, detail: &str) -> Result<(), VaultError> {
        let tx = self.conn.unchecked_transaction()?;
        self.audit_on(&tx, action, detail)?;
        tx.commit()?;
        Ok(())
    }

    fn audit_on(&self, conn: &Connection, action: &str, detail: &str) -> Result<(), VaultError> {
        let ts = now_iso();
        let actor = std::env::var("USER").unwrap_or_default();
        let prev = conn
            .query_row(
                "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_default();
        let entry = entry_hash_for(&prev, &ts, Some(&actor), action, Some(detail));
        let sig = hmac_hex(&self.key, &entry);
        conn.execute(
            "INSERT INTO audit_log(ts, actor, action, detail, prev_hash, entry_hash, sig)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![ts, actor, action, detail, prev, entry, sig],
        )?;
        Ok(())
    }

    /// Recompute the whole audit chain + HMACs with the current master key.
    /// Any row edited, inserted out of order or deleted is reported.
    pub fn verify_audit_chain(&self) -> Result<AuditChainReport, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, actor, action, detail, prev_hash, entry_hash, sig
             FROM audit_log ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
            ))
        })?;
        let mut report = AuditChainReport::default();
        let mut prev = String::new();
        for row in rows {
            let (id, ts, actor, action, detail, row_prev, entry, sig) = row?;
            report.total += 1;
            if entry.is_empty() {
                // Unchained (legacy) row: counted, but it breaks linkage for
                // anything written after it without a backfill.
                report.unchained += 1;
                continue;
            }
            report.chained += 1;
            if report.first_error.is_none() && row_prev != prev {
                report.first_error =
                    Some(format!("row {id}: chain break (prev_hash does not link)"));
            }
            let expected =
                entry_hash_for(&row_prev, &ts, actor.as_deref(), &action, detail.as_deref());
            if report.first_error.is_none() && expected != entry {
                report.first_error = Some(format!("row {id}: entry_hash mismatch (row modified?)"));
            }
            if !hmac_hex(&self.key, &entry).eq_ignore_ascii_case(&sig) {
                report.hmac_failures += 1;
                if report.first_error.is_none() {
                    report.first_error =
                        Some(format!("row {id}: HMAC invalid (forged or other key)"));
                }
            }
            prev = entry;
        }
        Ok(report)
    }

    /// Seal arbitrary bytes under the vault master key
    /// (nonce-prefixed: `nonce ‖ AES-256-GCM(ciphertext)`).
    pub fn seal(&self, data: &[u8]) -> Result<Vec<u8>, VaultError> {
        let (nonce, ct) = self.encrypt(data)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>, VaultError> {
        if blob.len() < NONCE_LEN {
            return Err(VaultError::Crypto("sealed blob too short".into()));
        }
        self.decrypt(&blob[..NONCE_LEN], &blob[NONCE_LEN..])
    }

    /// The backend protecting this vault's master key (`windows-tpm`,
    /// `windows-dpapi`, `unix-file-0600`).
    pub fn key_backend_name(&self) -> &'static str {
        self.backend_name
    }

    pub fn audit_tail(&self, limit: i64) -> Result<Vec<AuditEntry>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, actor, action, detail FROM audit_log ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            Ok(AuditEntry {
                id: r.get(0)?,
                ts: r.get(1)?,
                actor: r.get(2)?,
                action: r.get(3)?,
                detail: r.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn get_der_by_sha1(&self, sha1: &str) -> Result<Vec<u8>, VaultError> {
        let n = ctls_core::normalize_fingerprint(sha1);
        let row = self
            .conn
            .query_row(
                "SELECT nonce, der_enc FROM vault WHERE sha1=?1",
                params![n],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
            .ok_or_else(|| VaultError::NotFound(n.clone()))?;
        self.decrypt(&row.0, &row.1)
    }

    pub fn list(&self) -> Result<Vec<VaultEntry>, VaultError> {
        let mut stmt = self.conn.prepare(
            r#"SELECT id, subject, issuer, sha1, sha256, not_before, not_after,
                      is_ca, self_signed, trust_level, source, added_at, der_len, status
               FROM vault ORDER BY added_at DESC"#,
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(VaultEntry {
                id: r.get(0)?,
                subject: r.get(1)?,
                issuer: r.get(2)?,
                sha1_fingerprint: r.get(3)?,
                sha256_fingerprint: r.get(4)?,
                not_before: r.get(5)?,
                not_after: r.get(6)?,
                is_ca: r.get::<_, i64>(7)? != 0,
                self_signed: r.get::<_, i64>(8)? != 0,
                trust_level: r.get(9)?,
                source: r.get(10)?,
                added_at: r.get(11)?,
                der_len: r.get::<_, i64>(12)? as usize,
                status: r.get::<_, String>(13).unwrap_or_else(|_| "PENDING".into()),
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn remove_by_sha1(&self, sha1: &str) -> Result<(), VaultError> {
        let n = ctls_core::normalize_fingerprint(sha1);
        let tx = self.conn.unchecked_transaction()?;
        let affected = tx.execute("DELETE FROM vault WHERE sha1=?1", params![n])?;
        if affected > 0 {
            self.audit_on(&tx, "remove", &format!("sha1={n}"))?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn count(&self) -> Result<i64, VaultError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM vault", [], |r| r.get(0))?)
    }

    /// Update policy status for one entry. Values: ALLOW | QUARANTINE | BLOCK | PENDING.
    pub fn set_status(&self, sha1: &str, status: &str) -> Result<(), VaultError> {
        let n = ctls_core::normalize_fingerprint(sha1);
        let st = ctls_core::CaStatus::parse(status).as_str().to_string();
        let tx = self.conn.unchecked_transaction()?;
        let affected = tx.execute("UPDATE vault SET status=?1 WHERE sha1=?2", params![st, n])?;
        if affected == 0 {
            return Err(VaultError::NotFound(n));
        }
        self.audit_on(&tx, "set-status", &format!("sha1={n} status={st}"))?;
        tx.commit()?;
        Ok(())
    }

    /// Fingerprints trusted for system enforcement (purge keep-set, gateway).
    /// Fail-safe: only status=ALLOW — Quarantine/Pending stay isolated.
    pub fn allowed_fingerprints(&self) -> Result<std::collections::BTreeSet<String>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT sha1 FROM vault WHERE status='ALLOW'")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut set = std::collections::BTreeSet::new();
        for row in rows {
            set.insert(row?);
        }
        Ok(set)
    }

    /// Fingerprints held isolated (not trusted by gateway/purge keep-set).
    pub fn quarantined_fingerprints(
        &self,
    ) -> Result<std::collections::BTreeSet<String>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT sha1 FROM vault WHERE status IN ('QUARANTINE','PENDING','BLOCK')")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut set = std::collections::BTreeSet::new();
        for row in rows {
            set.insert(row?);
        }
        Ok(set)
    }
}

fn now_iso() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

/// Domain separator so audit hashes can never collide with other sha256 use.
const AUDIT_DOMAIN: &str = "ctls-audit-v1";

/// Canonical encoding of one audit row (after the chain prefix).
fn audit_canon(ts: &str, actor: &str, action: &str, detail: &str) -> String {
    format!("{AUDIT_DOMAIN}\x1f{ts}\x1f{actor}\x1f{action}\x1f{detail}")
}

fn entry_hash_for(
    prev: &str,
    ts: &str,
    actor: Option<&str>,
    action: &str,
    detail: Option<&str>,
) -> String {
    let canon = audit_canon(
        ts,
        actor.unwrap_or_default(),
        action,
        detail.unwrap_or_default(),
    );
    ctls_core::sha256_hex(format!("{prev}\x1f{canon}").as_bytes())
}

fn hmac_hex(key: &[u8; 32], entry_hex: &str) -> String {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(entry_hex.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Owner-only permissions on unix (0700 dir, 0600 file). No-op elsewhere —
/// Windows relies on the user profile ACL + DPAPI.
#[cfg(unix)]
fn harden_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(unix)]
fn harden_file(file: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn harden_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn harden_file(_file: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> CaRecord {
        CaRecord {
            subject: "CN=Test".into(),
            issuer: "CN=Test".into(),
            serial_hex: "01".into(),
            sha1_fingerprint: "aabbcc".into(),
            sha256_fingerprint: "ddeeff".into(),
            not_before: "2024-01-01T00:00:00Z".into(),
            not_after: "2034-01-01T00:00:00Z".into(),
            is_ca: true,
            self_signed: true,
            signature_algorithm: "sha256WithRSAEncryption".into(),
            public_key_algorithm: "RSA".into(),
            public_key_bits: 2048,
            store_name: "Root".into(),
            store_location: "LocalMachine".into(),
            der_len: 4,
        }
    }

    #[test]
    fn vault_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ctls_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let v = Vault::open(dir.join("vault.db")).unwrap();
        let rec = sample_record();
        v.add(&rec, b"test-der-bytes", "SAFE", "import").unwrap();
        assert!(v.contains_sha1("AABBCC").unwrap());
        let der = v.get_der_by_sha1("aa:bb:cc").unwrap();
        assert_eq!(der, b"test-der-bytes");
        assert_eq!(v.count().unwrap(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn repeated_import_preserves_status_and_id() {
        let dir = std::env::temp_dir().join(format!("ctls_repeat_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let v = Vault::open(dir.join("vault.db")).unwrap();
        let rec = sample_record();
        let id = v.add(&rec, b"original", "SAFE", "file").unwrap();
        assert_eq!(v.list().unwrap()[0].status, "QUARANTINE");
        v.set_status("aabbcc", "BLOCK").unwrap();
        let again = v
            .add_with_status(&rec, b"different", "SAFE", "url", Some("ALLOW"))
            .unwrap();
        assert_eq!(id, again);
        assert_eq!(v.count().unwrap(), 1);
        assert_eq!(v.list().unwrap()[0].status, "BLOCK");
        assert_eq!(v.get_der_by_sha1("aabbcc").unwrap(), b"original");
        assert!(v.verify_audit_chain().unwrap().valid());
        drop(v);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_imports_keep_audit_chain_valid() {
        let dir = std::env::temp_dir().join(format!("ctls_concurrent_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("vault.db");
        let initial = Vault::open(&path).unwrap();
        drop(initial);
        let workers: Vec<_> = (0..4)
            .map(|n| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let v = Vault::open(path).unwrap();
                    let mut rec = sample_record();
                    rec.sha1_fingerprint = format!("{n:040x}");
                    v.add(&rec, b"der", "UNKNOWN", "test").unwrap();
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        let v = Vault::open(&path).unwrap();
        assert_eq!(v.count().unwrap(), 4);
        assert!(v.verify_audit_chain().unwrap().valid());
        drop(v);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_chain_verifies_and_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("ctls_chain_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let backend;
        {
            let v = Vault::open(dir.join("vault.db")).unwrap();
            backend = v.key_backend_name().to_string();
            v.add(&sample_record(), b"der", "SAFE", "import").unwrap();
            v.set_status("aabbcc", "QUARANTINE").unwrap();
            let rep = v.verify_audit_chain().unwrap();
            assert!(rep.first_error.is_none(), "{:?}", rep.first_error);
            assert_eq!(rep.hmac_failures, 0);
            assert_eq!(rep.unchained, 0);
            assert!(rep.total >= 3, "total={}", rep.total);
            assert!(rep.valid());
        }
        // reopen: loads key through the recorded backend, chain still valid
        let v = Vault::open(dir.join("vault.db")).unwrap();
        assert_eq!(v.key_backend_name(), backend);
        let rep = v.verify_audit_chain().unwrap();
        assert!(rep.valid(), "{rep:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_tamper_is_detected() {
        let dir = std::env::temp_dir().join(format!("ctls_tamper_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let v = Vault::open(dir.join("vault.db")).unwrap();
        v.add(&sample_record(), b"der", "SAFE", "import").unwrap();
        assert!(v.verify_audit_chain().unwrap().valid());

        // Simulate an attacker editing history below the app layer:
        // drop the append-only trigger, modify a row, reinstall nothing.
        {
            let raw = Connection::open(dir.join("vault.db")).unwrap();
            raw.execute_batch("DROP TRIGGER IF EXISTS audit_log_no_update;")
                .unwrap();
            raw.execute("UPDATE audit_log SET detail='tampered' WHERE id=1", [])
                .unwrap();
        }
        let rep = v.verify_audit_chain().unwrap();
        assert!(!rep.valid(), "{rep:?}");
        assert!(rep.first_error.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ctls_seal_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let v = Vault::open(dir.join("vault.db")).unwrap();
        let sealed = v.seal(b"internal-ca-private-key").unwrap();
        assert_ne!(sealed, b"internal-ca-private-key");
        assert_eq!(v.unseal(&sealed).unwrap(), b"internal-ca-private-key");
        assert!(v.unseal(b"short").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
