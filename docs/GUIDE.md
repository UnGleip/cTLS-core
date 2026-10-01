# راهنمای استفاده از cTLS Core (CLI)

cTLS Core نسخهٔ **فقط خط فرمان** پروژه است (بدون UI):
اسکن store ها → ورود به Vault رمزنگاری‌شده → تصمیم سیاستی (ALLOW/QUARANTINE/BLOCK)
→ Gateway یا Purger.

---

## ۱. نصب و اجرا

### build از سورس

```powershell
cargo build --workspace --release
# باینری:
.\target\release\ctls.exe help
```

### نصب به‌عنوان فرمان سراسری (اختیاری)

```powershell
cargo install --path crates/ctls-cli
ctls help
```

### داده‌ها

| مسیر | محتوا |
|---|---|
| `%USERPROFILE%\.ctls\vault.db` | Vault (SQLite + AES-256-GCM؛ کلید با TPM در ویندوز / DPAPI در شکست TPM / فایل 0600 در لینوکس + زنجیرهٔ هش audit) |
| `%USERPROFILE%\.ctls\official-ca.json` | کش لیست رoot های رسمی CCADB (خروجی `ctls sync`) |
| `%USERPROFILE%\.ctls\allowlist.json` | لیست اثرانگشت Safe (اختیاری) |
| `%USERPROFILE%\.ctls\blocklist.json` | لیست اثرانگشت Blocked (اختیاری) |
| `%USERPROFILE%\.ctls\policy.json` | سیاست به‌صورت کد (اختیاری) |
| `%USERPROFILE%\.ctls\drift-baseline.json` | نقطهٔ مرجع Drift (اختیاری) |
| `%USERPROFILE%\.ctls\internal-ca\` | CA داخلی mTLS: گواهی + کلید seal‌شده + پین SPKI |
| `%USERPROFILE%\.ctls\config.json` | config سرور (اختیاری؛ `ctls config init`) |
| `%USERPROFILE%\.ctls\backups\` | بکاپ store ها قبل از Purge (فقط ویندوز) |

برای تغییر مسیر داده‌ها: متغیر محیطی `CTLS_DATA_DIR`.
در لینوکس مسیر پیش‌فرض `$HOME/.ctls` است.

---

## ۲. فرمان‌ها

### به‌روزرسانی لیست رسمی CA (CCADB)

```powershell
ctls sync                        # دانلود + کش (اگر کش تازه باشد کاری نمی‌کند)
ctls sync --force                # اجبار به به‌روزرسانی
ctls sync --status               # وضعیت کش بدون دانلود
ctls scan --sync                 # اگر کش > ۷ روز باشد اول به‌روز می‌شود
```

- منبع: `AllIncludedRootCertsCSV` + `MozillaTLSServerAuthenticationCSV` (فقط https).
- خروجی در `official-ca.json` به‌صورت اتمیک نوشته می‌شود؛ اگر دانلود شکست بخورد
  کش قبلی حفظ می‌شود (stale-if-error).
- با وجود این لیست، گواهی‌های **رسمی** از **third-party** (مثل root های
  VPN/آنتی‌ویروس) تفکیک می‌شوند.

### اسکن

```powershell
ctls scan --sync                 # همهٔ store ها + به‌روزرسانی لیست رسمی
ctls scan                        # همهٔ store های رایج
ctls scan Root LocalMachine      # یک store خاص (ویندوز)
ctls scan --profile strict       # پروفایل قضاوت: strict|default|lenient
ctls count                       # تعداد per store
```

**پروفایل‌ها:** `strict` گواهی UNKNOWN را Suspicious می‌کند؛ `lenient`
گواهی Suspicious را Unknown می‌کند. پروفایل فقط قضاوت (Level) را عوض
می‌کند — بلاک‌لیست و منشأ (Origin) دست‌نخورده می‌مانند.

**Level ها (قضاوت):**
- `SAFE` — در فهرست رسمی یا allowlist، با تاریخ اعتبار قابل قبول
- `SUSPICIOUS` — self-signed، الگوریتم ضعیف، کلید کوتاه، تازه‌صادرشده و…
- `BLOCKED` — در blocklist یا نام CA مسدود (DigiNotar/Superfish)؛ ورود به Vault مجاز نیست
- `UNKNOWN` — اطلاعات کافی نیست

**Origin (منشأ — مستقل از قضاوت):**
- `OFFICIAL` — در لیست رسمی CCADB (`ctls sync`)
- `CURATED` — در allowlist اختصاصی cTLS
- `THIRD-PARTY` — self-signed؛ معمولاً نصب‌شده توسط نرم‌افزار دیگر (VPN/AV/سازمانی)
- `UNKNOWN` — صادرشده توسط CA دیگر، بدون اطلاعات منشأ

نمونهٔ خروجی:

```
[      SAFE] OFFICIAL    LocalMachine | cabd2a79a1076a31f21d253635cb039d4329a5e8 | CN=ISRG Root X1
[SUSPICIOUS] THIRD-PARTY CurrentUser  | 35d2eb2e... | CN=ctls-test.local
             reasons: recently issued self-signed root (not traceable to a public CA)
```

### Vault و سیاست

```powershell
ctls vault list                    # لیست با trust|status
ctls vault count
ctls vault set-status <sha1> ALLOW
ctls vault set-status <sha1> QUARANTINE
ctls vault set-status <sha1> BLOCK
ctls vault set-status <sha1> PENDING
ctls vault audit 20                # ۲۰ رکورد آخر Audit
ctls vault verify-audit            # راستی‌آزمایی زنجیرهٔ هش (خروجی ۲ اگر خراب)
ctls vault reeval [--profile …]    # بازارزیابی: تنزل خودکار، ارتقا فقط پیشنهاد
```

**فقط `ALLOW`** به Gateway اعتماد می‌شود و در keep-set ماندنی Purge قرار می‌گیرد.
بقیه (QUARANTINE/PENDING/BLOCK) **ایزوله** می‌مانند (fail-safe).
ورود از فایل، URL یا مخزن به‌طور پیش‌فرض `QUARANTINE` است، مگر policy
صریحاً اجازه دهد. `accept-sha1` تأیید آگاهانهٔ کاربر است. ورود دوبارهٔ همان
اثر انگشت، وضعیت و شناسهٔ قبلی را تغییر نمی‌دهد.

#### سیاست به‌صورت کد (`policy.json`)

اگر `%USERPROFILE%\.ctls\policy.json` وجود داشته باشد، هنگام import و
`reeval` اعمال می‌شود:

```powershell
ctls policy show                   # نمایش قوانین + اعتبارسنجی
ctls policy validate               # فقط اعتبارسنجی (خروجی ۱ اگر نامعتبر)
```

```json
{
  "version": 1,
  "rules": [
    { "name": "block-superfish", "match": { "name_contains": "superfish" }, "action": "BLOCK" },
    { "name": "quarantine-3p", "match": { "classification": "THIRD-PARTY" }, "action": "QUARANTINE" }
  ]
}
```

- اولین rule منطبق برنده است؛ اگر هیچ rule منطبق نباشد، نگاشت داخلی
  پیش‌فرض اعمال می‌شود.
- **بلاک‌لیست اسکنر همیشه مقدم است** — policy هرگز نمی‌تواند چیزی را که
  اسکنر BLOCKED کرده آزاد کند.
- `ALLOW` باید با `name_contains`/`issuer_contains` مشخص شود (فقط با
  classification/level مجاز نیست).
- فایل خراب → دستور متوقف می‌شود (fail closed).

#### Drift (تغییرات غیرمنتظرهٔ Vault)

```powershell
ctls drift init [--force]          # snapshot از وضعیت فعلی
ctls drift check                   # خروجی ۲ اگر اضافه/حذف/تغییر status دیده شود
```

مثلاً قبل از Purge یا بعد از یک دورهٔ عدم حضور، `drift check` نشان می‌دهد
vault از نقطهٔ مرجع چقدر فاصله گرفته است.

### ورود گواهی (دستی یا از سایت)

```powershell
# از فایل (PEM multi-cert / DER؛ پشتیبانی .p7b ناقص است)
ctls import-file .\my-ca.pem

# از URL — فقط https و host های allowlist (rca.gov.ir)
ctls import-url https://rca.gov.ir/... [sha1-expected]

# از store سیستم با اثرانگشت
ctls accept-sha1 <thumbprint>

# از مخزن rca.gov.ir
ctls repo list
ctls repo pull "<url>" [sha1]
```

بعد از import، گواهی **مستقیم داخل Vault** می‌رود (نه store سیستم).

### نصب در store سیستم (اختیاری)

```powershell
# CurrentUser — بدون Admin
ctls install-sha1 <sha1> Root CurrentUser

# LocalMachine — نیاز به PowerShell/Admin
ctls install-sha1 <sha1> Root LocalMachine

ctls export-sha1 <sha1> .\out.der
```

> برای استفادهٔ عادی از Gateway **نیازی به install نیست**؛ Gateway فقط Vault را می‌خواند.

### بکاپ / Purge / بازگردانی (فقط ویندوز)

```powershell
ctls backup                         # بکاپ دستی همهٔ store ها
ctls preview-purge                  # فقط شمارش (بدون حذف)
ctls purge                          # حذف LocalMachine\Root خارج از ALLOW — Admin + بکاپ اجباری
ctls restore <backup-dir>           # بازگردانی — Admin
```

در لینوکس/اندروید/iOS این فرمان‌ها پیام
`Windows-only in this build` می‌دهند (این پلتفرم‌ها چنین store قابل‌حذفی ندارند).

### Gateway و نظارت

```powershell
ctls gateway 18080                  # اجرای پروکسی؛ Ctrl+C برای توقف
ctls gateway 18080 --no-admin       # بدون endpoint مدیریتی
ctls gateway status                 # خواندن وضعیت از endpoint mTLS
ctls watch 5                        # (ویندوز) هر ۵ ثانیه تغییرات store ها را چاپ می‌کند
```

Gateway:
- اتصال آزمایشی را با ریشه‌های `status=ALLOW` در Vault اعتبارسنجی می‌کند
- اتصال واقعی CONNECT جداگانه است و گواهی آن دیده نمی‌شود؛ بنابراین
  **برای اعمال اعتماد در محیط عملیاتی قابل اتکا نیست**
- **هیچ گواهی‌ای را به سیستم اضافه نمی‌کند**
- endpoint مدیریتی `127.0.0.1:18081` فقط با **mTLS** کار می‌کند: گواهی
  client از CA داخلی صادر می‌شود (کلید CA با کلید Vault seal شده) و client
  پین SPKI برگ را چک می‌کند — بدون `ctls gateway status` خواندنی ممکن نیست
- با Ctrl+C کاملاً متوقف می‌شود (پروکسی سیستم فقط با API جدا فعال/غیرفعال می‌شود)

### حالت سرور (لینوکس — شبیه xray)

برای اجرا روی سرور (systemd و…) از config استفاده کن:

```powershell
ctls version                        # نسخه / پلتفرم / بیلد
ctls config init -c /etc/ctls/config.json   # ساخت config پیش‌فرض
ctls config show                    # config مؤثر + مسیرهای resolve‌شده
ctls run --test                     # پیش‌بررسی: config + policy.json + vault
ctls run                            # اجرای سرور در پیش‌زمینه (Ctrl+C = توقف)
```

- کشف config: `-c` > `$CTLS_CONFIG` > `/etc/ctls/config.json` >
  `<data>/config.json` > پیش‌فرض (`127.0.0.1:18080` + admin `127.0.0.1:18081`).
- مسیر داده: `$CTLS_DATA_DIR` > `config.data_dir` > `~/.ctls` — بعد از resolve
  برای کل فرمان ثابت می‌شود (پس `ctls gateway status` هم همان مسیر را می‌بیند).
- config خراب (JSON ناقص/فیلد ناشناخته/`admin.listen` غیر-loopback) = خطای
  فرمان‌های عملیاتی (fail-closed)؛ `help`، `version` و `config init` از
  کشف config عبور می‌کنند. `admin.listen` فقط loopback پذیرفته می‌شود.
- نمونهٔ واحد systemd + چیدمان نصب: [SERVER.md](SERVER.md)
  (نصب‌کنندهٔ خودکار shell، بعداً در پروژهٔ جدا).

---

## ۳. جریان کاری پیشنهادی

```
1. لیست رسمی را بگیر      ctls sync
2. اسکن کن                 ctls scan --sync
3. ورود گواهی‌ها             ctls import-file / import-url / repo pull
4. تأیید صریح در صورت نیاز   ctls vault set-status <sha1> ALLOW / accept-sha1
5. سیاست کدی (اختیاری)      ctls policy show / validate
6. نقطهٔ مرجع بگیر         ctls drift init
7. فعال‌سازی Gateway        ctls gateway 18080
   (سرور لینوکس:            ctls run --test && ctls run — docs/SERVER.md)
8. (اختیاری) نصب در OS      ctls install-sha1   ← فقط اگر بخواهی
9. قبل از Purge (ویندوز)    ctls preview-purge + ctls drift check
10. اجرای Purge فقط وقتی    keep مورد نظر است + Admin + بکاپ
11. راستی‌آزمایی            ctls vault verify-audit / ctls vault reeval
```

---

## ۴. پلتفرم‌ها

| قابلیت | ویندوز | لینوکس | اندروید | iOS |
|---|---|---|---|---|
| خواندن store سیستم | ✓ | ✓ | ✓ (فقط‌خواندنی) | خالی (sandbox) |
| نصب/حذف CA | ✓ (Admin برای LM) | ✓ (root + `update-ca-certificates`) | ✗ | ✗ |
| اسکن و قابلیت‌های شبکه | ✓ | ✓ | پشتیبانی ناقص | پشتیبانی ناقص |
| backup / purge / watch | ✓ | ✗ | ✗ | ✗ |
| حفاظت کلید Vault | TPM → DPAPI | فایل 0600 | Keystore (آینده) | Keychain (آینده) |

ساخت برای هدف‌های دیگر:

```powershell
rustup target add x86_64-unknown-linux-gnu aarch64-linux-android aarch64-apple-ios
cargo check --workspace --target x86_64-unknown-linux-gnu
```

بررسی کامل هدف لینوکس روی ویندوز به ابزار کامپایل C هدف مانند
`x86_64-linux-gnu-gcc` نیاز دارد؛ build بومی لینوکس در CI تعریف شده است.

---

## ۵. نکات ایمنی

1. **هرگز** store سیستم را بدون بکاپ کامل تغییر نده.
2. Purge فقط با **Admin + بکاپ اجباری**؛ `preview-purge` فقط شمارش می‌دهد.
3. تنها `status=ALLOW` در فهرست مجاز Vault است؛ محدودیت امنیتی Gateway
   دربارهٔ اتصال واقعی همچنان برقرار است.
4. `audit_log` فقط‌افزودنی است و به‌صورت **زنجیرهٔ هش + HMAC** بسته می‌شود؛
   با `ctls vault verify-audit` قابل راستی‌آزمایی است (خروجی ۲ = خرابی).
5. کلید Vault هنگام استفاده در حافظه باز می‌شود و با `Zeroizing` پاک‌سازی
   می‌شود. در یونیکس کلید در پایگاه داده بدون رمزگذاری جداگانه ذخیره می‌شود
   و حفاظت آن به مجوز فایل 0600/پوشه 0700 وابسته است؛ در ویندوز TPM با
   fallback به DPAPI به کار می‌رود و backend ثبت می‌شود.
6. دانلود URL به `https`، host های مجاز و سقف ۸ مگابایت محدود است؛ این
   کنترل‌ها جایگزین بازبینی DNS/میزبان‌های سفارشی نیستند. `ctls sync` نیز
   کش را اتمیک می‌نویسد و سقف پاسخ ۳۲ مگابایت دارد.
7. اپ‌هایی که pinning یا trust store خودشان دارند، از مسیر Gateway مستثنی‌اند.
8. endpoint مدیریتی Gateway فقط localhost است، گواهی client از CA داخلی می‌خواهد
   و client پین SPKI را چک می‌کند؛ شکست راه‌اندازی mTLS یعنی Gateway بالا نمی‌آید
   (fail closed).
9. policy می‌تواند هنگام ورود، اجازهٔ صریح تعریف کند؛ بلاک‌لیست بر آن
   مقدم است. در `reeval` تنزل خودکار است و ارتقا فقط پیشنهاد می‌شود.

---

## ۶. عیب‌یابی سریع

| مشکل | راه حل |
|---|---|
| `import-url` خطا می‌دهد | فقط host های allowlist؛ آدرس باید `https://` باشد |
| `install-sha1 … LocalMachine` شکست | PowerShell را Run as Administrator اجرا کن |
| `purge` می‌گوید no ALLOW | اول حداقل یک گواهی را `set-status … ALLOW` کن |
| Gateway اجرا می‌شود ولی سایت باز نمی‌شود | گواهی آن سایت در Vault با `status=ALLOW` نیست؛ یا پورت درگیر است |
| Origin همه `UNKNOWN` است | `ctls sync` را اجرا کن (لیست رسمی خالی است) |
| `sync` خطای شبکه می‌دهد | کش قبلی حفظ می‌شود؛ بعداً دوباره امتحان کن یا `--status` ببین |
| `vault verify-audit` خروجی ۲ می‌دهد | زنجیرهٔ audit دستکاری/خراب شده — فوراً `vault.db` را بکاپ بگیر و بررسی کن |
| `policy validate` خطا می‌دهد | پیام خطا را ببین (rule خالی/ALLOW بدون name/issuer)؛ فایل خراب، import هم را متوقف می‌کند |
| `drift check` خروجی ۲ می‌دهد | vault با baseline فرق دارد؛ گزارش [added]/[removed]/[status-changed] را ببین |
| `gateway status` پین خطا می‌دهد | gateway دیگری روی همان پورت است یا فایل پین مربوط به اجرای قبلی است؛ gateway را ری‌استارت کن |
| `ctls run` بالا نمی‌آید | `ctls run --test` بگیر؛ سپس `policy validate` و `vault verify-audit`؛ پورت درگیر را چک کن |
| `unknown field …` در config | غلط املایی در config.json؛ فیلدها strict هستند (fail-closed) |
| `admin.listen … not a loopback` | endpoint مدیریتی فقط loopback است — `127.0.0.1:18081` بگذار |
| `backup/purge/watch` پیام Windows-only می‌دهد | این فرمان‌ها فقط در ویندوز هستند |
| `ctls` پیدا نمی‌شود | `cargo install --path crates/ctls-cli` یا مسیر target\release را به PATH اضافه کن |

---

## ۷. ساخت مجدد

```powershell
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

معماری کامل: [architecture.md](architecture.md) — نقشهٔ راه و ایده‌های بعدی: [ROADMAP.md](ROADMAP.md).
