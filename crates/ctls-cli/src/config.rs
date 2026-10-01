//! Server configuration (`config.json`) — the xray-style entry point.
//!
//! Resolution order for the config *file*:
//!   `-c/--config` > `$CTLS_CONFIG` > `/etc/ctls/config.json` > `<data>/config.json` > built-in defaults
//!
//! Resolution order for the *data dir*:
//!   `$CTLS_DATA_DIR` > `config.data_dir` > `~/.ctls` (`%USERPROFILE%\.ctls` on Windows)
//!
//! Safety: the mTLS admin endpoint must stay on a loopback address —
//! `validate()` rejects anything else, so a config typo can never expose
//! the admin listener to a network.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub const CONFIG_FILE_NAME: &str = "config.json";
/// Conventional system-wide config location (Linux server install layout).
pub const SYSTEM_CONFIG_PATH: &str = "/etc/ctls/config.json";

fn default_listen() -> String {
    "127.0.0.1:18080".into()
}

fn default_admin_listen() -> String {
    "127.0.0.1:18081".into()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Admin endpoint switch. When disabled the gateway exposes no status API.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Must be loopback — enforced by `ServerConfig::validate`.
    #[serde(default = "default_admin_listen")]
    pub listen: String,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_admin_listen(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// CONNECT verify-proxy listen address (`ip:port`). Use `0.0.0.0:18080`
    /// only when LAN clients should reach the proxy; keep `127.0.0.1` otherwise.
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub admin: AdminConfig,
    /// Data dir override (vault, lists, internal CA). Empty = env/default.
    #[serde(default)]
    pub data_dir: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            admin: AdminConfig::default(),
            data_dir: String::new(),
        }
    }
}

impl ServerConfig {
    pub fn validate(&self) -> Result<()> {
        let addr: SocketAddr = self.listen.parse().with_context(|| {
            format!(
                "listen: expected ip:port (e.g. 127.0.0.1:18080), got {:?}",
                self.listen
            )
        })?;
        if addr.port() == 0 {
            bail!("listen: port 0 is not a valid server port");
        }
        if self.admin.enabled {
            let admin: SocketAddr = self.admin.listen.parse().with_context(|| {
                format!(
                    "admin.listen: expected ip:port (e.g. 127.0.0.1:18081), got {:?}",
                    self.admin.listen
                )
            })?;
            if !admin.ip().is_loopback() {
                bail!(
                    "admin.listen {} is not a loopback address — the admin endpoint must \
                     stay on 127.0.0.1/::1 (mTLS + localhost only)",
                    self.admin.listen
                );
            }
            if admin.port() == 0 {
                bail!("admin.listen: port 0 is not a valid server port");
            }
            if admin.port() == addr.port() {
                bail!(
                    "listen and admin.listen must not share port {}",
                    addr.port()
                );
            }
        }
        if !self.data_dir.is_empty() {
            let p = Path::new(&self.data_dir);
            if p.is_relative() {
                bail!("data_dir must be an absolute path, got {:?}", self.data_dir);
            }
        }
        Ok(())
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let cfg: ServerConfig =
            serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Write the default config (`create_dir_all` on the parent).
    pub fn write_default(path: &Path, force: bool) -> Result<()> {
        if path.exists() && !force {
            bail!(
                "{} already exists — pass --force to overwrite",
                path.display()
            );
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
        }
        let text = serde_json::to_string_pretty(&ServerConfig::default())?;
        std::fs::write(path, format!("{text}\n"))
            .with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }
}

/// Fully resolved configuration for this invocation.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub config: ServerConfig,
    /// File the config came from; `None` = built-in defaults.
    pub path: Option<PathBuf>,
    /// Effective data dir (env > config > default).
    pub data_dir: PathBuf,
}

impl ResolvedConfig {
    pub fn source_label(&self) -> String {
        match &self.path {
            Some(p) => p.display().to_string(),
            None => "built-in defaults".to_string(),
        }
    }
}

/// Default data dir (no env, no config): `~/.ctls` / `%USERPROFILE%\.ctls`.
pub fn default_data_dir() -> PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".ctls")
}

/// Pure helper (unit-testable): `$CTLS_DATA_DIR` > `config.data_dir` > default.
fn effective_data_dir(
    env_data_dir: Option<PathBuf>,
    config_data_dir: &str,
    default: PathBuf,
) -> PathBuf {
    if let Some(env) = env_data_dir {
        if !env.as_os_str().is_empty() {
            return env;
        }
    }
    if config_data_dir.is_empty() {
        default
    } else {
        PathBuf::from(config_data_dir)
    }
}

/// Pure helper (unit-testable): which config file to read, if any.
fn discover_path(
    explicit: Option<&Path>,
    env_config: Option<PathBuf>,
    system_path: &Path,
    base_data_dir: &Path,
) -> Result<Option<PathBuf>> {
    if let Some(p) = explicit {
        if !p.exists() {
            bail!("config not found: {}", p.display());
        }
        return Ok(Some(p.to_path_buf()));
    }
    if let Some(p) = env_config {
        if !p.exists() {
            bail!("$CTLS_CONFIG points to a missing file: {}", p.display());
        }
        return Ok(Some(p));
    }
    if system_path.exists() {
        return Ok(Some(system_path.to_path_buf()));
    }
    let local = base_data_dir.join(CONFIG_FILE_NAME);
    if local.exists() {
        return Ok(Some(local));
    }
    Ok(None)
}

/// Resolve config file + data dir for this invocation.
/// Errors are hard failures (fail closed) for a present-but-broken config.
pub fn resolve(explicit: Option<&str>) -> Result<ResolvedConfig> {
    let env_config = std::env::var_os("CTLS_CONFIG").map(PathBuf::from);
    let env_data_dir = std::env::var_os("CTLS_DATA_DIR").map(PathBuf::from);

    // Base data dir used only to *find* a config (env > default).
    let base_data_dir = effective_data_dir(env_data_dir.clone(), "", default_data_dir());

    let path = discover_path(
        explicit.map(Path::new),
        env_config,
        Path::new(SYSTEM_CONFIG_PATH),
        &base_data_dir,
    )?;

    let config = match &path {
        Some(p) => ServerConfig::load_from(p)?,
        None => ServerConfig::default(),
    };

    let data_dir = effective_data_dir(env_data_dir, &config.data_dir, default_data_dir());

    Ok(ResolvedConfig {
        config,
        path,
        data_dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ctls_cfg_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn default_config_is_valid() {
        let cfg = ServerConfig::default();
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.listen, "127.0.0.1:18080");
        assert!(cfg.admin.enabled);
        assert_eq!(cfg.admin.listen, "127.0.0.1:18081");
        assert!(cfg.data_dir.is_empty());
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = serde_json::from_str::<ServerConfig>(r#"{"lissten":"0.0.0.0:1"}"#);
        assert!(err.is_err(), "typo'd field must be rejected");
    }

    #[test]
    fn rejects_non_loopback_admin() {
        let cfg = ServerConfig {
            admin: AdminConfig {
                listen: "0.0.0.0:18081".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("loopback"), "{err}");
    }

    #[test]
    fn rejects_bad_listen_and_port_collisions() {
        let cfg = ServerConfig {
            listen: "not-an-addr".into(),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());

        let cfg = ServerConfig {
            admin: AdminConfig {
                listen: "127.0.0.1:18080".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("share port"));

        let cfg = ServerConfig {
            listen: "127.0.0.1:0".into(),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_relative_data_dir() {
        let cfg = ServerConfig {
            data_dir: "var/lib/ctls".into(),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
        // absolute form is platform-specific (`/` alone is drive-relative on Windows)
        #[cfg(unix)]
        {
            let cfg = ServerConfig {
                data_dir: "/var/lib/ctls".into(),
                ..Default::default()
            };
            assert!(cfg.validate().is_ok());
        }
        #[cfg(windows)]
        {
            let cfg = ServerConfig {
                data_dir: "C:\\var\\lib\\ctls".into(),
                ..Default::default()
            };
            assert!(cfg.validate().is_ok());
        }
    }

    #[test]
    fn ipv6_loopback_admin_allowed() {
        let cfg = ServerConfig {
            admin: AdminConfig {
                listen: "[::1]:18081".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn roundtrip_write_and_load() {
        let dir = temp_dir("round");
        let path = dir.join(CONFIG_FILE_NAME);
        ServerConfig::write_default(&path, false).unwrap();
        let loaded = ServerConfig::load_from(&path).unwrap();
        assert_eq!(loaded, ServerConfig::default());
        // second write without --force fails
        assert!(ServerConfig::write_default(&path, false).is_err());
        ServerConfig::write_default(&path, true).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broken_config_file_fails_closed() {
        let dir = temp_dir("broken");
        let path = dir.join(CONFIG_FILE_NAME);
        std::fs::write(&path, "{ not json").unwrap();
        assert!(ServerConfig::load_from(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discover_prefers_explicit_then_env_then_system_then_local() {
        let dir = temp_dir("disc");
        let explicit = dir.join("explicit.json");
        std::fs::write(&explicit, "{}").unwrap();
        let env = dir.join("env.json");
        std::fs::write(&env, "{}").unwrap();
        let system = dir.join("system.json");
        std::fs::write(&system, "{}").unwrap();
        let base = dir.join("data");
        std::fs::create_dir_all(&base).unwrap();
        let local = base.join(CONFIG_FILE_NAME);
        std::fs::write(&local, "{}").unwrap();

        // explicit wins over everything
        let got = discover_path(Some(&explicit), Some(env.clone()), &system, &base).unwrap();
        assert_eq!(got, Some(explicit.clone()));

        // env wins over system + local
        let got = discover_path(None, Some(env.clone()), &system, &base).unwrap();
        assert_eq!(got, Some(env.clone()));

        // system wins over local
        let got = discover_path(None, None, &system, &base).unwrap();
        assert_eq!(got, Some(system.clone()));

        // local as fallback
        let missing_system = dir.join("no-such-system.json");
        let got = discover_path(None, None, &missing_system, &base).unwrap();
        assert_eq!(got, Some(local.clone()));

        // nothing → built-in defaults
        let empty = dir.join("empty-data");
        let got = discover_path(None, None, &missing_system, &empty).unwrap();
        assert_eq!(got, None);

        // explicit path that does not exist is a hard error
        assert!(
            discover_path(Some(&dir.join("ghost.json")), None, &missing_system, &empty).is_err()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn data_dir_precedence_env_config_default() {
        let default = PathBuf::from("/default/.ctls");
        // env beats config
        assert_eq!(
            effective_data_dir(Some("/env/dir".into()), "/cfg/dir", default.clone()),
            PathBuf::from("/env/dir")
        );
        // empty env falls through to config
        assert_eq!(
            effective_data_dir(Some("".into()), "/cfg/dir", default.clone()),
            PathBuf::from("/cfg/dir")
        );
        // no env, empty config field → default
        assert_eq!(
            effective_data_dir(None, "", default.clone()),
            default.clone()
        );
        // no env, config set → config
        assert_eq!(
            effective_data_dir(None, "/cfg/dir", default.clone()),
            PathBuf::from("/cfg/dir")
        );
    }

    #[test]
    fn default_config_json_is_stable_shape() {
        let text = serde_json::to_string_pretty(&ServerConfig::default()).unwrap();
        let parsed: ServerConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, ServerConfig::default());
        assert!(text.contains("\"127.0.0.1:18080\""));
        assert!(text.contains("\"enabled\": true"));
    }
}
