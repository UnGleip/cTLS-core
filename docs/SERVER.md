# Running cTLS as a server (Linux)

xray-style: one binary, one config file, one foreground command that a
service manager supervises.

```bash
ctls run -c /etc/ctls/config.json        # server (foreground)
ctls run --test                          # validate and initialize local state, then exit
ctls config init -c /etc/ctls/config.json --force
ctls config show                         # effective config + resolved paths
ctls version
```

> The standalone **installer (shell scripts) is planned as a separate
> project** — this document describes the manual layout the installer
> will automate.

## Install layout

| Path | Purpose |
|---|---|
| `/usr/local/bin/ctls` | binary (`cargo build --release`, or `cargo install --path crates/ctls-cli`) |
| `/etc/ctls/config.json` | server config (auto-discovered) |
| `/var/lib/ctls/` | data dir: `vault.db`, `official-ca.json`, `policy.json`, `drift-baseline.json`, `internal-ca/`, lists |

```bash
sudo useradd --system --home /var/lib/ctls --shell /usr/sbin/nologin ctls
sudo install -d -m 0750 /etc/ctls
sudo install -d -m 0700 -o ctls -g ctls /var/lib/ctls
sudo ctls config init -c /etc/ctls/config.json
# then set "data_dir": "/var/lib/ctls" in the file
```

## Config file

Discovery order (first hit wins):

1. `-c` / `--config <path>`
2. `$CTLS_CONFIG`
3. `/etc/ctls/config.json`
4. `<data-dir>/config.json`
5. built-in defaults (`127.0.0.1:18080`, admin on `127.0.0.1:18081`)

Data dir order: `$CTLS_DATA_DIR` > `config.data_dir` > `$HOME/.ctls`.

A present-but-broken config is a **hard failure for operational commands**
(fail closed). Unknown fields are rejected (`deny_unknown_fields`), so a
typo like `"lissten"` cannot silently fall back to defaults.
`help`, `version`, and `config init` bypass config discovery.

Example — LAN proxy, localhost-only admin:

```json
{
  "listen": "0.0.0.0:18080",
  "admin": {
    "enabled": true,
    "listen": "127.0.0.1:18081"
  },
  "data_dir": "/var/lib/ctls"
}
```

| Field | Default | Notes |
|---|---|---|
| `listen` | `127.0.0.1:18080` | CONNECT verify-proxy. `0.0.0.0:PORT` only if LAN clients must reach it |
| `admin.enabled` | `true` | mTLS status endpoint |
| `admin.listen` | `127.0.0.1:18081` | **must be loopback** — validated, non-loopback is rejected |
| `data_dir` | `""` | absolute path; empty = env/default |

`listen` and `admin.listen` may not share a port.

## Running

```bash
ctls run --test                 # pre-flight: config, policy.json, vault, mTLS CA
ctls run                        # foreground; Ctrl+C (or SIGTERM) to stop
ctls gateway status             # admin status over mTLS (SPKI-pinned)
```

`ctls gateway status` works from any directory: with `/etc/ctls/config.json`
present, every command resolves the same data dir automatically. For remote
inspection, SSH-tunnel the admin port (it is localhost-only by design):

`run --test` opens or creates the Vault and may create the internal mTLS CA
and pin files. It is a pre-flight check, not a read-only dry run.

```bash
ssh user@server -L 18081:127.0.0.1:18081
ctls gateway status 127.0.0.1:18081
```

Clients point their HTTPS proxy at `http://SERVER:18080` (browser or
`HTTPS_PROXY`). Preflight validates against `ALLOW` roots, but the actual
tunneled TLS handshake is separate and cannot be checked by this proxy.
Do not use this as a production trust enforcement boundary.

## systemd

`/etc/systemd/system/ctls.service`:

```ini
[Unit]
Description=cTLS experimental CONNECT proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ctls run -c /etc/ctls/config.json
Restart=on-failure
RestartSec=2
User=ctls
Group=ctls
StateDirectory=ctls
# hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ctls
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ctls
systemctl status ctls
journalctl -u ctls -f
```

Ports `18080`/`18081` are unprivileged (>1024); no capabilities are needed.
Open `18080` in the firewall only when non-local clients should use the
proxy — never `18081`.

## Environment variables

| Var | Effect |
|---|---|
| `CTLS_CONFIG` | config file path (below `-c`) |
| `CTLS_DATA_DIR` | data dir (beats `config.data_dir`) |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `config not found: …` | path given to `-c` / `$CTLS_CONFIG` does not exist |
| `unknown field …` | typo in config.json (fail-closed; fields are strict) |
| `admin.listen … is not a loopback address` | keep admin on `127.0.0.1` |
| `gateway startup (fail-closed): …` | vault/policy/internal CA problem — see `ctls vault verify-audit`, `ctls policy validate` |
| `ctls gateway status` refused | admin disabled in config, wrong addr, or client cert not from the internal CA |
| permission denied on `/var/lib/ctls` | fix ownership for the service user (`chown -R ctls:ctls /var/lib/ctls`) |
