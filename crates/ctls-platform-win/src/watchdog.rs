use ctls_core::CaRecord;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::store::{read_store, StoreError, COMMON_STORES};

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WatchEvent {
    pub kind: String,
    pub store_name: String,
    pub store_location: String,
    pub sha1: String,
    pub subject: String,
}

struct Snapshot {
    set: std::collections::BTreeSet<String>,
    meta: std::collections::BTreeMap<String, CaRecord>,
}

fn take_snapshot() -> Result<Snapshot, WatchError> {
    let mut set = std::collections::BTreeSet::new();
    let mut meta = std::collections::BTreeMap::new();
    for (name, loc) in COMMON_STORES {
        let recs = read_store(name, *loc)?;
        for r in recs {
            let key = format!(
                "{}\\{}\\{}",
                r.store_location,
                r.store_name,
                ctls_core::normalize_fingerprint(&r.sha1_fingerprint)
            );
            set.insert(key.clone());
            meta.insert(key, r);
        }
    }
    Ok(Snapshot { set, meta })
}

/// Poll stores and report added/removed certificates.
/// `on_event` is called for each difference.
pub fn watch_loop<F>(
    interval: Duration,
    stop: Arc<AtomicBool>,
    mut on_event: F,
) -> Result<(), WatchError>
where
    F: FnMut(WatchEvent) + Send,
{
    let mut prev = take_snapshot()?;
    while !stop.load(Ordering::SeqCst) {
        std::thread::sleep(interval);
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let curr = match take_snapshot() {
            Ok(s) => s,
            Err(_) => continue,
        };

        for key in curr.set.difference(&prev.set) {
            if let Some(rec) = curr.meta.get(key) {
                on_event(WatchEvent {
                    kind: "added".into(),
                    store_name: rec.store_name.clone(),
                    store_location: rec.store_location.clone(),
                    sha1: rec.sha1_fingerprint.clone(),
                    subject: rec.subject.clone(),
                });
            }
        }
        for key in prev.set.difference(&curr.set) {
            if let Some(rec) = prev.meta.get(key) {
                on_event(WatchEvent {
                    kind: "removed".into(),
                    store_name: rec.store_name.clone(),
                    store_location: rec.store_location.clone(),
                    sha1: rec.sha1_fingerprint.clone(),
                    subject: rec.subject.clone(),
                });
            }
        }
        prev = curr;
    }
    Ok(())
}

/// One-shot diff used in tests / manual checks.
pub fn diff_once() -> Result<(Vec<WatchEvent>, Vec<WatchEvent>), WatchError> {
    let a = take_snapshot()?;
    std::thread::sleep(Duration::from_millis(50));
    let b = take_snapshot()?;
    let mut added = Vec::new();
    let mut removed = Vec::new();
    for key in b.set.difference(&a.set) {
        if let Some(rec) = b.meta.get(key) {
            added.push(WatchEvent {
                kind: "added".into(),
                store_name: rec.store_name.clone(),
                store_location: rec.store_location.clone(),
                sha1: rec.sha1_fingerprint.clone(),
                subject: rec.subject.clone(),
            });
        }
    }
    for key in a.set.difference(&b.set) {
        if let Some(rec) = a.meta.get(key) {
            removed.push(WatchEvent {
                kind: "removed".into(),
                store_name: rec.store_name.clone(),
                store_location: rec.store_location.clone(),
                sha1: rec.sha1_fingerprint.clone(),
                subject: rec.subject.clone(),
            });
        }
    }
    Ok((added, removed))
}
