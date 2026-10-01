use anyhow::{bail, Context, Result};
use ctls_core::{OfficialCaCache, PolicyFile, TrustLevel};
use ctls_platform::{current_store, StoreLocation};
use ctls_repo::RcaClient;
use ctls_scanner::{scan_record_profiled, FingerprintLists, ScanProfile};
use ctls_vault::Vault;
use std::path::PathBuf;
use std::sync::OnceLock;

mod config;
mod drift;

#[cfg(windows)]
mod ctrlc;

/// Set once per invocation from the resolved config (env > config > default),
/// so every command (scan/status/run) operates on the same data dir.
static DATA_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

fn set_data_override(dir: PathBuf) {
    std::fs::create_dir_all(&dir).ok();
    let _ = DATA_OVERRIDE.set(dir);
}

fn data_dir() -> PathBuf {
    let base = match DATA_OVERRIDE.get() {
        Some(p) => p.clone(),
        None => {
            let env = std::env::var("CTLS_DATA_DIR").unwrap_or_default();
            if env.is_empty() {
                config::default_data_dir()
            } else {
                PathBuf::from(env)
            }
        }
    };
    std::fs::create_dir_all(&base).ok();
    base
}

/// First value of `flag` in `args` (e.g. `-c file` / `--config file`).
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn open_vault() -> Result<Vault> {
    Vault::open(data_dir().join("vault.db")).context("open vault")
}

fn load_lists() -> FingerprintLists {
    FingerprintLists::load_for_data_dir(&data_dir())
}

/// `--profile strict|default|lenient` (default: strict for scan is NOT set —
/// the built-in default verdict behavior applies unless a profile is given).
fn parse_profile(args: &[String]) -> Result<ScanProfile> {
    let raw = args
        .iter()
        .position(|a| a == "--profile")
        .and_then(|i| args.get(i + 1));
    match raw {
        None => Ok(ScanProfile::Default),
        Some(s) => ScanProfile::parse(s)
            .with_context(|| format!("unknown profile: {s} (strict|default|lenient)")),
    }
}

/// Load `policy.json` if present. A broken policy fails the command (closed).
fn load_policy() -> Result<Option<PolicyFile>> {
    PolicyFile::load_from(&data_dir()).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Worsening rank: higher rank = stricter. Allow=0 < Pending=1 < Quarantine=2 < Block=3.
fn status_rank(status: &str) -> u8 {
    match status.to_ascii_uppercase().as_str() {
        "ALLOW" => 0,
        "PENDING" => 1,
        "QUARANTINE" => 2,
        "BLOCK" => 3,
        _ => 1,
    }
}

/// Importing bytes alone does not authorize trust. Policy may explicitly grant
/// it; otherwise new entries remain isolated.
fn import_status(
    policy: &Option<PolicyFile>,
    rec: &ctls_core::CaRecord,
    level: TrustLevel,
    classification: &str,
) -> ctls_core::CaStatus {
    policy
        .as_ref()
        .and_then(|p| p.decide(&rec.subject, &rec.issuer, level.as_str(), classification))
        .unwrap_or(match level {
            TrustLevel::Blocked => ctls_core::CaStatus::Block,
            _ => ctls_core::CaStatus::Quarantine,
        })
}

fn parse_loc(s: &str) -> Result<StoreLocation> {
    match s.to_lowercase().as_str() {
        "currentuser" | "cu" => Ok(StoreLocation::CurrentUser),
        "localmachine" | "lm" => Ok(StoreLocation::LocalMachine),
        other => bail!("unknown location: {other}"),
    }
}

/// `scan --sync`: refresh the official CCADB cache if older than 7 days.
/// Network failure is non-fatal (scan continues with whatever is cached).
fn maybe_sync(args: &[String]) {
    if !args.iter().any(|a| a == "--sync") {
        return;
    }
    match ctls_sync::sync(&data_dir(), false, ctls_sync::DEFAULT_MAX_AGE_DAYS) {
        Ok(r) if r.refreshed => eprintln!(
            "sync: {} official roots from {} source(s)",
            r.count,
            r.sources.len()
        ),
        Ok(r) => eprintln!("sync: using local cache ({} roots)", r.count),
        Err(e) => eprintln!("sync: failed ({e}) — scanning with local lists"),
    }
}

fn print_usage() {
    let platform = current_store().platform_name();
    println!(
        "cTLS CLI ({platform})\n\
         \n\
         USAGE:\n\
         \x20 ctls run [-c config.json] [--test]\n\
         \x20                             # run server from config.json (xray-style)\n\
         \x20                             # --test = validate config/policy/vault then exit\n\
         \x20 ctls config init [-c file] [--force]  # write default config.json\n\
         \x20 ctls config show           # print effective config + resolved paths\n\
         \x20 ctls version               # version / target / build\n\
         \x20 ctls scan [--sync] [--profile strict|default|lenient] [Store] [Loc]\n\
         \x20                             # scan trust stores + heuristics\n\
         \x20 ctls count                 # count certificates per store\n\
         \x20 ctls sync [--force] [--max-age-days N] [--status]\n\
         \x20                             # refresh official CCADB root list (cached)\n\
         \x20 ctls vault list            # list vault entries (trust|status)\n\
         \x20 ctls vault count           # vault size\n\
         \x20 ctls vault set-status <sha1> <ALLOW|QUARANTINE|BLOCK|PENDING>\n\
         \x20 ctls vault audit [n]       # last n audit_log entries (default 20)\n\
         \x20 ctls vault verify-audit    # verify audit hash-chain (exit 2 if broken)\n\
         \x20 ctls vault reeval [--profile strict|default|lenient]\n\
         \x20                             # re-evaluate statuses (downgrade only, suggest upgrades)\n\
         \x20 ctls policy show           # show policy.json (or built-in mapping)\n\
         \x20 ctls policy validate       # validate policy.json\n\
         \x20 ctls drift init [--force]  # snapshot vault to drift-baseline.json\n\
         \x20 ctls drift check           # diff vs baseline (exit 2 on drift)\n\
         \x20 ctls import-file <path>    # import PEM/DER/.p7b (multi-cert OK)\n\
         \x20 ctls import-url <url> [sha1]  # download https cert + import (allowlisted hosts)\n\
         \x20 ctls accept-sha1 <sha1>    # add store cert to vault by SHA-1\n\
         \x20 ctls install-sha1 <sha1> [Store] [Loc]  # install vault cert to OS store (admin for LM)\n\
         \x20 ctls export-sha1 <sha1> <out.der>\n\
         \x20 ctls repo list             # list certs published on rca.gov.ir\n\
         \x20 ctls repo pull <url> [sha1]  # download + verify + import to vault\n\
         \x20 ctls gateway [port] [--admin-port N] [--no-admin]\n\
         \x20                             # run local TLS verify-proxy (default 18080)\n\
         \x20                             # admin endpoint (mTLS) on 127.0.0.1:18081\n\
         \x20 ctls gateway status [addr] # fetch admin status over mTLS (SPKI-pinned)\n\
         \n\
         Windows-only:\n\
         \x20 ctls backup [dir] | restore <dir> | preview-purge | purge | watch [seconds]\n\
         \n\
         Config: -c/--config > $CTLS_CONFIG > /etc/ctls/config.json > <data>/config.json > defaults\n\
         Loc: CurrentUser | LocalMachine (CU/LM)"
    );
}

fn load_der_any(path: &str) -> Result<Vec<Vec<u8>>> {
    let raw = std::fs::read(path).with_context(|| format!("read {path}"))?;
    let ders = ctls_core::load_certificates(&raw).context("parse certificates")?;
    if ders.is_empty() {
        anyhow::bail!("no certificates in {path}");
    }
    Ok(ders)
}

fn scan_and_report(
    records: &[ctls_core::CaRecord],
    lists: &FingerprintLists,
    profile: ScanProfile,
) {
    let mut safe = 0usize;
    let mut suspicious = 0usize;
    let mut blocked = 0usize;
    let mut unknown = 0usize;
    let mut official = 0usize;
    let mut curated = 0usize;
    let mut third_party = 0usize;
    let mut unclassified = 0usize;

    for r in records {
        let res = scan_record_profiled(r, lists, profile);
        match res.level {
            TrustLevel::Safe => safe += 1,
            TrustLevel::Suspicious => suspicious += 1,
            TrustLevel::Blocked => blocked += 1,
            TrustLevel::Unknown => unknown += 1,
        }
        match res.classification {
            ctls_scanner::CaClassification::OfficialRoot => official += 1,
            ctls_scanner::CaClassification::Curated => curated += 1,
            ctls_scanner::CaClassification::ThirdParty => third_party += 1,
            ctls_scanner::CaClassification::Unknown => unclassified += 1,
        }
        println!(
            "[{:>11}] {:<11} {:>15} | {} | {}",
            res.level.as_str(),
            res.classification.as_str(),
            r.store_location,
            r.sha1_fingerprint,
            r.subject
        );
        if !res.reasons.is_empty() && res.level != TrustLevel::Safe {
            println!("             reasons: {}", res.reasons.join("; "));
        }
    }

    eprintln!(
        "\nTotal: {} | Safe: {} | Suspicious: {} | Blocked: {} | Unknown: {}",
        records.len(),
        safe,
        suspicious,
        blocked,
        unknown
    );
    eprintln!("profile: {}", profile.as_str());
    eprintln!(
        "Origin: official: {official} | curated: {curated} | third-party: {third_party} | unknown: {unclassified}"
    );
    if official == 0 && !records.is_empty() {
        eprintln!("hint: official set empty — run `ctls sync` to import the CCADB root list");
    }
}

fn run_sync(args: &[String]) -> Result<()> {
    let force = args.iter().any(|a| a == "--force");
    let status_only = args.iter().any(|a| a == "--status");
    let max_age_days: u64 = args
        .iter()
        .position(|a| a == "--max-age-days")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(ctls_sync::DEFAULT_MAX_AGE_DAYS);
    let data = data_dir();

    if status_only {
        match OfficialCaCache::load_from(&data) {
            None => println!("no official-ca.json yet — run: ctls sync"),
            Some(c) => {
                println!("official roots: {}", c.sha256.len());
                println!("updated_at:     {}", c.updated_at);
                println!(
                    "stale (>{}d):    {}",
                    max_age_days,
                    c.is_stale(max_age_days)
                );
                for s in &c.sources {
                    println!("source:         {s}");
                }
            }
        }
        return Ok(());
    }

    let report = ctls_sync::sync(&data, force, max_age_days)?;
    for (src, n) in &report.source_counts {
        println!("  {n:>4} roots  {src}");
    }
    if report.refreshed {
        println!(
            "synced: {} official roots at {}",
            report.count, report.updated_at
        );
    } else if report.stale {
        eprintln!(
            "warning: downloads failed — kept stale cache ({} roots, updated {})",
            report.count, report.updated_at
        );
    } else {
        println!(
            "cache fresh: {} roots (updated {}); use --force to refresh",
            report.count, report.updated_at
        );
    }
    for w in &report.warnings {
        eprintln!("warning: {w}");
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    // Resolve config.json once for this invocation (fail closed on a
    // present-but-broken file) and pin the effective data dir for every
    // command. `version`/`help` and `config init` bypass discovery.
    let cmd = args[1].as_str();
    let config_init = cmd == "config" && args.get(2).map(|s| s.as_str()) == Some("init");
    let resolved = if config_init
        || matches!(
            cmd,
            "version" | "--version" | "-version" | "help" | "--help" | "-h"
        ) {
        None
    } else {
        let explicit = flag_value(&args, "-c").or_else(|| flag_value(&args, "--config"));
        let r = config::resolve(explicit.as_deref())?;
        set_data_override(r.data_dir.clone());
        Some(r)
    };

    match args[1].as_str() {
        "scan" | "scan-system" => {
            maybe_sync(&args);
            let profile = parse_profile(&args)?;
            let lists = load_lists();
            let store = current_store();
            let all = store.list_system_cas().context("list system CAs")?;
            let records = if args.len() >= 4 && !args[2].starts_with('-') {
                let name = args[2].clone();
                let loc = parse_loc(&args[3])?;
                let loc_s = loc.as_str();
                all.into_iter()
                    .filter(|r| {
                        r.store_name.eq_ignore_ascii_case(&name) && r.store_location == loc_s
                    })
                    .collect::<Vec<_>>()
            } else {
                all
            };
            scan_and_report(&records, &lists, profile);
        }
        "count" => {
            let records = current_store().list_system_cas()?;
            let mut by_store: std::collections::BTreeMap<String, usize> = Default::default();
            for r in records {
                let k = format!("{}\\{}", r.store_location, r.store_name);
                *by_store.entry(k).or_default() += 1;
            }
            for (k, v) in by_store {
                println!("{v:>4}  {k}");
            }
        }
        "sync" => run_sync(&args)?,
        "vault" => {
            let sub = args.get(2).map(|s| s.as_str()).unwrap_or("list");
            let vault = open_vault()?;
            match sub {
                "list" => {
                    for e in vault.list()? {
                        println!(
                            "[{}|{}] {} | {} | {} -> {}",
                            e.trust_level,
                            e.status,
                            e.sha1_fingerprint,
                            e.source,
                            e.subject,
                            e.added_at
                        );
                    }
                    eprintln!("vault entries: {}", vault.count()?);
                }
                "count" => println!("{}", vault.count()?),
                "set-status" => {
                    let sha1 = args.get(3).context("missing sha1")?;
                    let status = args
                        .get(4)
                        .context("missing status (ALLOW|QUARANTINE|BLOCK|PENDING)")?;
                    vault.set_status(sha1, status)?;
                    println!(
                        "{} => {}",
                        ctls_core::normalize_fingerprint(sha1),
                        ctls_core::CaStatus::parse(status).as_str()
                    );
                }
                "audit" => {
                    let n: i64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(20);
                    for e in vault.audit_tail(n)? {
                        println!(
                            "{} | {} | {} | {}",
                            e.ts,
                            e.action,
                            e.actor.unwrap_or_default(),
                            e.detail.unwrap_or_default()
                        );
                    }
                }
                "verify-audit" => {
                    let r = vault.verify_audit_chain()?;
                    println!("entries:       {}", r.total);
                    println!("chained:       {}", r.chained);
                    println!("unchained:     {}", r.unchained);
                    println!("hmac_failures: {}", r.hmac_failures);
                    if let Some(err) = &r.first_error {
                        println!("first_error:   {err}");
                    }
                    if !r.valid() {
                        eprintln!("audit chain: INVALID");
                        std::process::exit(2);
                    }
                    println!("audit chain: OK");
                }
                "reeval" => {
                    let profile = parse_profile(&args)?;
                    let policy = load_policy()?;
                    let lists = load_lists();
                    let entries = vault.list()?;
                    let mut downgraded = 0usize;
                    let mut suggested = 0usize;
                    let mut unchanged = 0usize;
                    let mut skipped = 0usize;
                    const MAX_SUGGESTIONS: usize = 20;
                    for e in &entries {
                        let der = match vault.get_der_by_sha1(&e.sha1_fingerprint) {
                            Ok(d) => d,
                            Err(_) => {
                                skipped += 1;
                                continue;
                            }
                        };
                        let rec = match ctls_core::parse_der_bytes(&der) {
                            Ok(r) => r,
                            Err(_) => {
                                skipped += 1;
                                continue;
                            }
                        };
                        let res = scan_record_profiled(&rec, &lists, profile);
                        if res.level == TrustLevel::Blocked {
                            // scanner blacklist always wins — force BLOCK
                            let current = ctls_core::CaStatus::parse(&e.status);
                            if status_rank(current.as_str()) < status_rank("BLOCK") {
                                vault.set_status(&e.sha1_fingerprint, "BLOCK")?;
                                downgraded += 1;
                                println!(
                                    "[downgrade] {} {} -> BLOCK | {} (scanner blacklist)",
                                    e.sha1_fingerprint,
                                    current.as_str(),
                                    e.subject
                                );
                            } else {
                                unchanged += 1;
                            }
                            continue;
                        }
                        let candidate = policy
                            .as_ref()
                            .and_then(|p| {
                                p.decide(
                                    &rec.subject,
                                    &rec.issuer,
                                    res.level.as_str(),
                                    res.classification.as_str(),
                                )
                            })
                            .unwrap_or_else(|| ctls_core::status_from_trust(res.level));
                        let current = ctls_core::CaStatus::parse(&e.status);
                        let (c_rank, cur_rank) = (
                            status_rank(candidate.as_str()),
                            status_rank(current.as_str()),
                        );
                        if c_rank > cur_rank {
                            vault.set_status(&e.sha1_fingerprint, candidate.as_str())?;
                            downgraded += 1;
                            println!(
                                "[downgrade] {} {} -> {} | {}",
                                e.sha1_fingerprint,
                                current.as_str(),
                                candidate.as_str(),
                                e.subject
                            );
                        } else if c_rank < cur_rank {
                            suggested += 1;
                            if suggested <= MAX_SUGGESTIONS {
                                println!(
                                    "[suggest]   {} {} -> {} | {} (apply: ctls vault set-status {} {})",
                                    e.sha1_fingerprint,
                                    current.as_str(),
                                    candidate.as_str(),
                                    e.subject,
                                    e.sha1_fingerprint,
                                    candidate.as_str()
                                );
                            }
                        } else {
                            unchanged += 1;
                        }
                    }
                    if suggested > MAX_SUGGESTIONS {
                        println!(
                            "[suggest]   ... and {} more (re-run to see all)",
                            suggested - MAX_SUGGESTIONS
                        );
                    }
                    vault.audit(
                        "reeval",
                        &format!(
                            "profile={} downgraded={} suggested={} unchanged={} skipped={}",
                            profile.as_str(),
                            downgraded,
                            suggested,
                            unchanged,
                            skipped
                        ),
                    )?;
                    println!(
                        "reeval done: downgraded={downgraded} suggested={suggested} \
                         unchanged={unchanged} skipped={skipped}"
                    );
                }
                other => bail!("unknown vault subcommand: {other}"),
            }
        }
        "policy" => {
            let sub = args.get(2).map(|s| s.as_str()).unwrap_or("show");
            let path = data_dir().join(ctls_core::policy::POLICY_FILE_NAME);
            match sub {
                "show" => match load_policy()? {
                    None => {
                        println!("no {} — using built-in mapping", path.display());
                        println!("imports: BLOCKED -> BLOCK, otherwise QUARANTINE");
                        println!("accept-sha1 explicitly approves a non-blocked system CA");
                        println!("create one at {} — see docs/GUIDE.md", path.display());
                    }
                    Some(p) => {
                        println!("file:            {}", path.display());
                        println!("version:         {}", p.version);
                        println!(
                            "default_action:  {}",
                            p.default_action
                                .map(|s| s.as_str())
                                .unwrap_or("(built-in mapping)")
                        );
                        if p.rules.is_empty() {
                            println!("rules:           (none)");
                        }
                        for r in &p.rules {
                            let m = &r.matcher;
                            let mut parts = Vec::new();
                            if let Some(v) = &m.name_contains {
                                parts.push(format!("name~\"{v}\""));
                            }
                            if let Some(v) = &m.issuer_contains {
                                parts.push(format!("issuer~\"{v}\""));
                            }
                            if let Some(v) = &m.classification {
                                parts.push(format!("class={v}"));
                            }
                            if let Some(v) = &m.level {
                                parts.push(format!("level={v}"));
                            }
                            println!(
                                "  [{:<24}] {} -> {}",
                                r.name,
                                parts.join(", "),
                                r.action.as_str()
                            );
                        }
                        match p.validate() {
                            Ok(()) => println!("validation: OK"),
                            Err(e) => {
                                println!("validation: FAILED");
                                eprintln!("{e}");
                            }
                        }
                    }
                },
                "validate" => {
                    if !path.exists() {
                        bail!("no {} — nothing to validate", path.display());
                    }
                    match PolicyFile::load_from(&data_dir())? {
                        None => bail!("no {} — nothing to validate", path.display()),
                        Some(p) => {
                            println!(
                                "policy OK: {} rule(s), version {}",
                                p.rules.len(),
                                p.version
                            );
                        }
                    }
                }
                other => bail!("unknown policy subcommand: {other}"),
            }
        }
        "drift" => {
            let sub = args.get(2).map(|s| s.as_str()).unwrap_or("check");
            let vault = open_vault()?;
            let path = data_dir().join(drift::BASELINE_FILE);
            match sub {
                "init" => {
                    let force = args.iter().any(|a| a == "--force");
                    if path.exists() && !force {
                        bail!(
                            "baseline exists at {} — use --force to overwrite",
                            path.display()
                        );
                    }
                    let entries = vault.list()?;
                    let now = time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default();
                    let base = drift::baseline_from_entries(&entries, &now);
                    drift::write(&path, &base)?;
                    vault.audit(
                        "drift.init",
                        &format!("entries={} file={}", base.entries.len(), path.display()),
                    )?;
                    println!(
                        "baseline written: {} ({} entries)",
                        path.display(),
                        base.entries.len()
                    );
                }
                "check" => {
                    if !path.exists() {
                        bail!("no baseline at {} — run: ctls drift init", path.display());
                    }
                    let base = drift::read(&path)?;
                    let entries = vault.list()?;
                    let report = drift::diff(&base, &entries);
                    report.print();
                    vault.audit(
                        "drift.check",
                        &format!(
                            "drift={} added={} removed={} status_changed={}",
                            report.is_drift(),
                            report.added.len(),
                            report.removed.len(),
                            report.status_changed.len()
                        ),
                    )?;
                    if report.is_drift() {
                        eprintln!("drift detected (baseline: {})", base.created_at);
                        std::process::exit(2);
                    }
                    println!("no drift (baseline: {})", base.created_at);
                }
                other => bail!("unknown drift subcommand: {other}"),
            }
        }
        "import-file" => {
            let path = args.get(2).context("missing path")?;
            let ders = load_der_any(path)?;
            let lists = load_lists();
            let vault = open_vault()?;
            let policy = load_policy()?;
            let mut imported = 0usize;
            for der in &ders {
                let rec = match ctls_core::parse_der_bytes(der) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("skip unparseable cert: {e}");
                        continue;
                    }
                };
                let res = scan_record_profiled(&rec, &lists, ScanProfile::Default);
                if res.level == TrustLevel::Blocked {
                    eprintln!(
                        "blocked by scanner: {} ({})",
                        rec.sha1_fingerprint,
                        res.reasons.join("; ")
                    );
                    continue;
                }
                let status = import_status(&policy, &rec, res.level, res.classification.as_str());
                let id = vault.add_with_status(
                    &rec,
                    der,
                    res.level.as_str(),
                    "file",
                    Some(status.as_str()),
                )?;
                println!(
                    "imported id={} level={} status={} origin={} sha1={}",
                    id,
                    res.level.as_str(),
                    status.as_str(),
                    res.classification.as_str(),
                    rec.sha1_fingerprint
                );
                imported += 1;
            }
            if imported == 0 {
                bail!("no certificates imported from {path}");
            }
            eprintln!("imported {imported} certificate(s)");
        }
        "import-url" => {
            let url = args.get(2).context("missing url")?;
            let sha1 = args.get(3).map(|s| s.as_str());
            let client = RcaClient::new().context("client")?;
            let (rec, der) = client
                .download_and_verify(url, sha1)
                .context("download/verify")?;
            let lists = load_lists();
            let res = scan_record_profiled(&rec, &lists, ScanProfile::Default);
            if res.level == TrustLevel::Blocked {
                bail!("blocked by scanner: {}", res.reasons.join("; "));
            }
            let vault = open_vault()?;
            let policy = load_policy()?;
            let status = import_status(&policy, &rec, res.level, res.classification.as_str());
            let id = vault.add_with_status(
                &rec,
                &der,
                res.level.as_str(),
                "url",
                Some(status.as_str()),
            )?;
            println!(
                "imported id={} level={} status={} origin={} sha1={} subject={}",
                id,
                res.level.as_str(),
                status.as_str(),
                res.classification.as_str(),
                rec.sha1_fingerprint,
                rec.subject
            );
        }
        "install-sha1" => {
            let sha1 = args.get(2).context("missing sha1")?;
            let store = args.get(3).map(|s| s.as_str()).unwrap_or("Root");
            let loc = parse_loc(args.get(4).map(|s| s.as_str()).unwrap_or("LocalMachine"))?;
            let vault = open_vault()?;
            let der = vault.get_der_by_sha1(sha1)?;
            current_store()
                .install_ca(&der, store, loc)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            vault.audit(
                "install",
                &format!(
                    "sha1={} store={}\\{}",
                    ctls_core::normalize_fingerprint(sha1),
                    loc.as_str(),
                    store
                ),
            )?;
            println!(
                "installed {} into {}\\{}",
                ctls_core::normalize_fingerprint(sha1),
                loc.as_str(),
                store
            );
        }
        "accept-sha1" => {
            let sha1 = args.get(2).context("missing sha1")?;
            let store = current_store();
            let records = store.list_system_cas()?;
            let target = records
                .iter()
                .find(|r| {
                    ctls_core::normalize_fingerprint(&r.sha1_fingerprint)
                        == ctls_core::normalize_fingerprint(sha1)
                })
                .context("sha1 not found in system stores")?
                .clone();
            let der = store
                .export_der(&target.sha1_fingerprint)
                .map_err(|e| anyhow::anyhow!("export der: {e}"))?;
            let lists = load_lists();
            let res = scan_record_profiled(&target, &lists, ScanProfile::Default);
            let vault = open_vault()?;
            let policy = load_policy()?;
            let status = if res.level == TrustLevel::Blocked {
                ctls_core::CaStatus::Block
            } else {
                policy
                    .as_ref()
                    .and_then(|p| {
                        p.decide(
                            &target.subject,
                            &target.issuer,
                            res.level.as_str(),
                            res.classification.as_str(),
                        )
                    })
                    .unwrap_or_else(|| ctls_core::status_for_explicit_import(res.level))
            };
            let id = vault.add_with_status(
                &target,
                &der,
                res.level.as_str(),
                "system-store",
                Some(status.as_str()),
            )?;
            println!(
                "accepted id={} level={} status={} origin={} sha1={}",
                id,
                res.level.as_str(),
                status.as_str(),
                res.classification.as_str(),
                target.sha1_fingerprint
            );
        }
        "export-sha1" => {
            let sha1 = args.get(2).context("missing sha1")?;
            let out = args.get(3).context("missing out path")?;
            let vault = open_vault()?;
            let der = vault.get_der_by_sha1(sha1)?;
            std::fs::write(out, der)?;
            println!("wrote {out}");
        }
        "repo" => {
            let sub = args.get(2).map(|s| s.as_str()).unwrap_or("list");
            let client = RcaClient::new().context("repo client")?;
            match sub {
                "list" => {
                    let html = client.fetch_repository_page().context("fetch rca page")?;
                    let certs = client.parse_repository_page(&html)?;
                    for c in &certs {
                        println!("{}\n    {}", c.name, c.url);
                    }
                    eprintln!("total: {}", certs.len());
                }
                "pull" => {
                    let url = args.get(3).context("missing url")?;
                    let sha1 = args.get(4).map(|s| s.as_str());
                    let (rec, der) = client
                        .download_and_verify(url, sha1)
                        .context("download/verify")?;
                    let lists = load_lists();
                    let res = scan_record_profiled(&rec, &lists, ScanProfile::Default);
                    if res.level == TrustLevel::Blocked {
                        bail!("blocked by scanner: {}", res.reasons.join("; "));
                    }
                    let vault = open_vault()?;
                    let policy = load_policy()?;
                    let status =
                        import_status(&policy, &rec, res.level, res.classification.as_str());
                    let id = vault.add_with_status(
                        &rec,
                        &der,
                        res.level.as_str(),
                        "rca.gov.ir",
                        Some(status.as_str()),
                    )?;
                    println!(
                        "imported id={} level={} status={} origin={} sha1={} subject={}",
                        id,
                        res.level.as_str(),
                        status.as_str(),
                        res.classification.as_str(),
                        rec.sha1_fingerprint,
                        rec.subject
                    );
                }
                other => bail!("unknown repo subcommand: {other}"),
            }
        }
        #[cfg(windows)]
        "backup" => {
            let dir = args
                .get(2)
                .map(PathBuf::from)
                .unwrap_or_else(|| ctls_platform_win::default_backup_dir().join("manual"));
            let m = ctls_platform_win::backup_all(&dir).context("backup failed")?;
            println!(
                "backed up {} certs from {} stores -> {}",
                m.total_certs,
                m.stores.len(),
                m.path
            );
        }
        #[cfg(windows)]
        "restore" => {
            let dir = args.get(2).context("missing backup dir")?;
            let n = ctls_platform_win::restore_backup(dir).context("restore failed")?;
            println!("restored {n} certificate contexts (admin may be required)");
        }
        #[cfg(windows)]
        "preview-purge" => {
            let vault = open_vault()?;
            let allowed = vault.allowed_fingerprints()?;
            let (keep, drop) = ctls_platform_win::preview_purge(&allowed)?;
            println!(
                "LocalMachine\\Root => keep: {keep}, would remove: {drop} (allow={} status=ALLOW)",
                allowed.len()
            );
        }
        #[cfg(windows)]
        "purge" => {
            let vault = open_vault()?;
            let allowed = vault.allowed_fingerprints()?;
            if allowed.is_empty() {
                bail!("vault has no ALLOW entries — refusing to purge everything");
            }
            let dir = ctls_platform_win::default_backup_dir().join("pre-purge");
            println!("creating backup at {} ...", dir.display());
            let report = ctls_platform_win::purge_untrusted(&allowed, &dir)
                .context("purge failed (admin required)")?;
            vault.audit(
                "purge",
                &format!(
                    "removed={} kept={} backup={}",
                    report.removed, report.kept, report.backup.path
                ),
            )?;
            println!(
                "purge done: removed={}, kept={}, backup={}",
                report.removed, report.kept, report.backup.path
            );
            println!("restore with: ctls restore {}", report.backup.path);
        }
        #[cfg(windows)]
        "watch" => {
            let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
            println!("watching stores every {secs}s (Ctrl+C to stop)...");
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop2 = stop.clone();
            ctrlc::ctrlc_set(move || stop2.store(true, std::sync::atomic::Ordering::SeqCst));
            ctls_platform_win::watch_loop(std::time::Duration::from_secs(secs), stop, |ev| {
                println!(
                    "[{}] {}\\{} {} {}",
                    ev.kind, ev.store_location, ev.store_name, ev.sha1, ev.subject
                );
            })
            .context("watch failed")?;
        }
        #[cfg(not(windows))]
        cmd @ ("backup" | "restore" | "preview-purge" | "purge" | "watch") => {
            bail!("`{cmd}` is Windows-only in this build — use `ctls scan` / `ctls gateway` here");
        }
        "gateway" => {
            if args.get(2).map(|s| s.as_str()) == Some("status") {
                let addr = match args.get(3).map(|s| s.as_str()) {
                    Some(s) if !s.starts_with('-') => s.to_string(),
                    _ => "127.0.0.1:18081".to_string(),
                };
                let vault = open_vault()?;
                let rt = tokio::runtime::Runtime::new()?;
                let body = rt
                    .block_on(ctls_enforce::mtls::fetch_admin_status(
                        &addr,
                        &data_dir(),
                        &vault,
                    ))
                    .map_err(|e| anyhow::anyhow!("admin status: {e}"))?;
                println!("{body}");
                return Ok(());
            }

            let mut port: u16 = 18080;
            let mut admin_port: u16 = 18081;
            let mut admin = true;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--no-admin" => admin = false,
                    "-c" | "--config" => {
                        // consumed globally (sets the data dir); use `ctls run` for config-driven servers
                        i += 1;
                    }
                    "--admin-port" => {
                        admin_port = args
                            .get(i + 1)
                            .and_then(|s| s.parse().ok())
                            .context("bad --admin-port value")?;
                        i += 1;
                    }
                    s if !s.starts_with('-') => {
                        port = s.parse().context("bad port")?;
                    }
                    other => bail!("unknown gateway flag: {other}"),
                }
                i += 1;
            }

            let vault = open_vault()?;
            let cfg = ctls_enforce::GatewayConfig {
                listen: format!("127.0.0.1:{port}"),
                admin: admin.then(|| ctls_enforce::AdminConfig {
                    listen: format!("127.0.0.1:{admin_port}"),
                    data_dir: data_dir(),
                }),
            };
            let gw = ctls_enforce::Gateway::from_vault(&vault, cfg)
                .map_err(|e| anyhow::anyhow!("gateway startup (fail-closed): {e}"))?;
            println!(
                "cTLS gateway on http://{} (system proxy not auto-set; use browser proxy manually)",
                gw.listen_addr()
            );
            if let Some(admin_addr) = gw.admin_addr() {
                match ctls_enforce::mtls::InternalCa::pin_summary(&data_dir()) {
                    Ok(pin) => {
                        println!("admin (mTLS):  https://{admin_addr}/status (leaf spki: {pin})")
                    }
                    Err(e) => eprintln!("admin pin: {e}"),
                }
                println!("status with:  ctls gateway status {admin_addr}");
            } else {
                println!("admin endpoint disabled (--no-admin)");
            }
            println!(
                "allowed vault fingerprints: {}",
                vault.allowed_fingerprints()?.len()
            );
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                // map GatewayError into anyhow via string
                match gw.run().await {
                    Ok(()) => Ok(()),
                    Err(e) => Err(anyhow::anyhow!("{e}")),
                }
            })?;
        }
        "version" | "--version" | "-version" => {
            println!("ctls {} (cTLS Core)", env!("CARGO_PKG_VERSION"));
            println!("target:  {}", current_store().platform_name());
            println!(
                "build:   {}",
                if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                }
            );
        }
        "config" => {
            let sub = args.get(2).map(|s| s.as_str()).unwrap_or("show");
            match sub {
                "init" => {
                    let force = args.iter().any(|a| a == "--force");
                    let explicit =
                        flag_value(&args, "-c").or_else(|| flag_value(&args, "--config"));
                    let path = match explicit {
                        Some(p) => PathBuf::from(p),
                        None => data_dir().join(config::CONFIG_FILE_NAME),
                    };
                    config::ServerConfig::write_default(&path, force)?;
                    println!("wrote {}", path.display());
                    if path
                        .parent()
                        .map(|p| p == std::path::Path::new("/etc/ctls"))
                        .unwrap_or(false)
                    {
                        println!(
                            "data dir: set \"data_dir\": \"/var/lib/ctls\" for a service install"
                        );
                    } else {
                        println!(
                            "hint: server-wide install: ctls config init -c {}",
                            config::SYSTEM_CONFIG_PATH
                        );
                    }
                }
                "show" => {
                    let r = resolved.as_ref().context("config not resolved")?;
                    r.config.validate()?;
                    println!("{}", serde_json::to_string_pretty(&r.config)?);
                    println!();
                    println!("source:   {}", r.source_label());
                    println!("data_dir: {}", r.data_dir.display());
                    println!("validate: OK");
                }
                other => bail!("unknown config subcommand: {other} (init|show)"),
            }
        }
        "run" => {
            let r = resolved.as_ref().context("config not resolved")?;
            let cfg = &r.config;
            let test_only = args.iter().any(|a| a == "--test" || a == "-test");

            let vault = open_vault()?;
            let policy = load_policy()?;
            if let Some(p) = &policy {
                p.validate()
                    .map_err(|e| anyhow::anyhow!("policy.json invalid: {e}"))?;
            }
            let gcfg = ctls_enforce::GatewayConfig {
                listen: cfg.listen.clone(),
                admin: cfg.admin.enabled.then(|| ctls_enforce::AdminConfig {
                    listen: cfg.admin.listen.clone(),
                    data_dir: data_dir(),
                }),
            };
            let gw = ctls_enforce::Gateway::from_vault(&vault, gcfg)
                .map_err(|e| anyhow::anyhow!("gateway startup (fail-closed): {e}"))?;

            let admin_line = match gw.admin_addr() {
                Some(a) => {
                    let pin = ctls_enforce::mtls::InternalCa::pin_summary(&data_dir())
                        .map(|p| format!("spki: {p}"))
                        .unwrap_or_else(|e| format!("pin unavailable: {e}"));
                    format!("https://{a}/status (mTLS, {pin})")
                }
                None => "disabled".to_string(),
            };

            if test_only {
                println!("config OK: {}", r.source_label());
                println!("listen:    {}", gw.listen_addr());
                println!("admin:     {admin_line}");
                println!("data:      {}", data_dir().display());
                println!(
                    "vault:     {} allowed / {} entries (policy: {})",
                    vault.allowed_fingerprints()?.len(),
                    vault.count()?,
                    policy
                        .as_ref()
                        .map(|p| format!("{} rule(s)", p.rules.len()))
                        .unwrap_or_else(|| "built-in".to_string())
                );
                return Ok(());
            }

            println!(
                "ctls {} server — config: {}",
                env!("CARGO_PKG_VERSION"),
                r.source_label()
            );
            println!("  data:  {}", data_dir().display());
            println!(
                "  proxy: http://{} (CONNECT verify-proxy)",
                gw.listen_addr()
            );
            println!("  admin: {admin_line}");
            if let Some(a) = gw.admin_addr() {
                println!("         status: ctls gateway status {a}");
            }
            println!(
                "  vault: {} allowed / {} entries",
                vault.allowed_fingerprints()?.len(),
                vault.count()?
            );
            println!("listening — Ctrl+C to stop");
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                match gw.run().await {
                    Ok(()) => Ok(()),
                    Err(e) => Err(anyhow::anyhow!("{e}")),
                }
            })?;
        }
        "help" | "--help" | "-h" => print_usage(),
        other => bail!("unknown command: {other}"),
    }

    Ok(())
}
