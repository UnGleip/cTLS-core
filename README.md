# cTLS Core

[فارسی](docs/GUIDE.md) · [GPL-3.0-only](LICENSE) · [CI checks](.github/workflows/ci.yml)

**cTLS Core** is an experimental, cross-platform certificate inventory and
isolation toolkit by **UnGleip**. Its Rust workspace provides a CLI (`ctls`)
and separate libraries for certificate parsing, platform stores, scanning,
policy, an encrypted Vault, official-root synchronization, and a CONNECT
gateway. There is no graphical interface yet.

## What works

- Scan Windows and Linux trust stores; classify certificates using local
  rules and an optionally downloaded CCADB root list.
- Import PEM or DER certificates into a local encrypted SQLite Vault.
  New file/URL imports default to `QUARANTINE` unless an explicit policy
  allows them. Duplicate imports keep the existing decision.
- Audit status changes, manage policy and drift baselines, and optionally
  install certificates in an OS store. Backup, purge, and watchdog commands
  are Windows-only.
- Run a local CONNECT gateway or start it as a foreground service with
  `ctls run`. Its admin status endpoint uses loopback mTLS.

**Security limit:** The gateway validates a *separate preflight TLS
connection*. It cannot verify the certificate shown on the actual tunneled
connection, so it is **not a production trust-enforcement boundary**. The
scanner does not perform complete PKI validation or revocation checks.
PKCS#7 bundles are only partially supported; Android/iOS platform stores
are incomplete. See [architecture](docs/architecture.md) and
[security reporting](SECURITY.md).

## Build and try it

Install Rust, then run from this repository:

```sh
cargo build --locked --release
cargo test --locked --workspace
cargo run --locked -p ctls-cli -- help
```

The binary is `target/release/ctls` (`ctls.exe` on Windows).

```sh
ctls scan                 # inspect locally; no download
ctls sync                 # explicitly download/cache the CCADB list
ctls import-file my-ca.pem
ctls vault list           # imported entries start isolated
ctls vault verify-audit
ctls run --test           # validate configuration and open/create local state
```

`ctls sync`, `ctls import-url`, and `ctls repo` contact their configured
sources when invoked; `ctls scan --sync` also refreshes the root list.
The gateway connects to requested upstream hosts. No telemetry is configured.
The default data directory is `$HOME/.ctls` on Linux and
`%USERPROFILE%\.ctls` on Windows; set `CTLS_DATA_DIR` to override it.

## Documentation

- [Architecture and current limitations](docs/architecture.md)
- [Linux server setup](docs/SERVER.md)
- [Roadmap](docs/ROADMAP.md)
- [راهنمای کامل فارسی](docs/GUIDE.md)

## License

Copyright (C) 2026 **UnGleip**. Licensed under
[GNU General Public License version 3 only](LICENSE) (`GPL-3.0-only`).
When you distribute a covered modified version, the GPL's corresponding
source and licensing obligations apply. Private use alone does not require
publication of your project.

<details>
<summary><strong>فارسی — معرفی و شروع سریع</strong></summary>

cTLS Core ابزار آزمایشی **UnGleip** برای اسکن گواهی‌ها، نگهداری ایزوله در
Vault و مدیریت سیاست اعتماد است. فعلاً رابط گرافیکی ندارد. گواهی‌های واردشده
از فایل یا URL به‌صورت پیش‌فرض در وضعیت `QUARANTINE` قرار می‌گیرند؛ برای
جزئیات فرمان‌ها [راهنمای فارسی](docs/GUIDE.md) را ببینید.

```sh
cargo build --locked --release
cargo run --locked -p ctls-cli -- help
ctls scan
ctls import-file my-ca.pem
ctls vault list
```

**محدودیت مهم:** gateway فقط اتصال آزمایشی جداگانه را اعتبارسنجی می‌کند و
گواهی اتصال واقعیِ عبوری را نمی‌بیند؛ بنابراین ابزار اعمال اعتماد در محیط
عملیاتی نیست. مجوز پروژه `GPL-3.0-only` است. انتشار نسخهٔ مشتق‌شده مشمول
تعهدات انتشار کد متناظر GPL است؛ استفادهٔ خصوصی به‌تنهایی الزام انتشار ندارد.

</details>
