# شروع کار

[English](../getting-started.md) · **فارسی**

کاریز دو سرور را با یک تانل به هم وصل می‌کند:

- **ورودی** (`entry`) سرور عمومی است و کاربرها به آن وصل می‌شوند. قانون‌های `[[forward]]` مال ورودی‌اند: «هرچه روی این پورت رسید، به آن آدرس بفرست».
- **خروجی** (`exit`) سروری است که به مقصدهای واقعی دسترسی دارد. به آدرس‌هایی که ورودی بخواهد وصل می‌شود.

```mermaid
flowchart LR
    U[Users] -->|port 443| E[Entry server]
    E <==>|Kariz tunnel| X[Exit server]
    X --> T[Targets]
```

این‌که کدام سمت تانل را باز کند به **حالت** (`mode`) بستگی دارد:

| حالت | چه کسی وصل می‌شود | کی انتخابش کنید |
|---|---|---|
| `reverse` | خروجی به ورودی وصل می‌شود | ورودی می‌تواند از خروجی اتصال بپذیرد |
| `direct` | ورودی به خروجی وصل می‌شود | خروجی می‌تواند اتصال بپذیرد (یا پشت CDN است) |

سمتی که وصل می‌شود `tunnel.remote` را می‌نویسد و سمت دیگر `tunnel.listen` را.

## راه سریع: پنل وب

پنل را با اسکریپت مدیر روی یک سرور نصب کنید، سرورهای دیگر را به آن وصل کنید و تانل‌ها را در مرورگر بسازید. پنل همهٔ مرحله‌های پایین را روی هر دو سرور خودش انجام می‌دهد (کانفیگ‌ها، توکن، سرویس systemd و بررسی این‌که تانل وصل شده) و اگر مرحله‌ای خراب شود همه را به حالت قبل برمی‌گرداند:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MAHDI-byte64/tun2/main/scripts/kariz.sh)
```

در منو **۳** (نصب پنل وب) را انتخاب کنید و لینکی را که چاپ می‌شود باز کنید. بعد [کار با پنل](using-the-panel.md) را بخوانید؛ منو هم در [اسکریپت مدیر](manager.md) توضیح داده شده است.

بقیهٔ این صفحه همان کار است به‌صورت دستی: برای سروری که پنل ندارد، یا وقتی می‌خواهید ببینید پنل دقیقاً چه چیزی می‌نویسد.

## ۱. نصب

فایل اجرایی استاتیک لینوکس را برای CPU خودتان از [Releases](https://github.com/MAHDI-byte64/tun2/releases) بگیرید (`x86_64`، `aarch64` یا `armv7`؛ دستور `uname -m` نشانتان می‌دهد کدام)، یا با Rust نسخهٔ ۱٫۸۰ یا جدیدتر خودتان بسازید:

```bash
cargo build --release
sudo cp target/release/kariz /usr/local/bin/
```

این کار را روی هر دو سرور انجام دهید.

## ۲. ساخت توکن

```bash
kariz token
```

توکن تنها رازِ تانل است. هر دو سمت یک توکن دارند و هرکس آن را داشته باشد می‌تواند از تانل استفاده کند. توکن هیچ‌وقت روی شبکه فرستاده نمی‌شود.

## ۳. نوشتن دو کانفیگ

از یکی از جفت‌های پوشهٔ [`configs/`](../../configs) شروع کنید:

| جفت | کاربرد |
|---|---|
| `entry-reverse.toml`، `exit-reverse.toml` | حالت reverse روی `tcp` ساده |
| `entry-direct.toml`، `exit-direct.toml` | حالت direct روی `tcp` ساده |
| `entry-tcpmux-reverse.toml`، `exit-tcpmux-reverse.toml` | حالت reverse با mux |
| `entry-udp-reverse.toml`، `exit-udp-reverse.toml` | فوروارد UDP (وایرگارد، بازی) |
| `entry-wss-direct.toml`، `exit-wss-direct.toml` | `wss` به سرور خودتان، با گواهی خودامضا که pin شده |
| `entry-wss-cdn.toml`، `exit-wss-cdn.toml` | `wss` از پشت CDN ([راهنما](CDN.md)) |
| `entry-quic-direct.toml`، `exit-quic-direct.toml` | `quic`، با وایرگارد روی datagramهای QUIC (و `obfs` برای شبکه‌ای که QUIC را فیلتر می‌کند) |
| `entry-kcp-reverse.toml`، `exit-kcp-reverse.toml` | `kcp` برای مسیر پراتلاف |
| `entry-gaming.toml`، `exit-gaming.toml` | سرور بازی روی `kcp` با پروفایل gaming |

یک جفت حداقلی در حالت reverse:

```toml
# /etc/kariz/config.toml on the entry
role = "entry"
mode = "reverse"

[tunnel]
transport = "tcpmux"
listen = "0.0.0.0:3080"            # the exit connects here
token = "PASTE-THE-TOKEN"

[[forward]]
listen = "0.0.0.0:443"             # users connect here
target = "127.0.0.1:443"           # dialed by the exit
```

```toml
# /etc/kariz/config.toml on the exit
role = "exit"
mode = "reverse"

[tunnel]
transport = "tcpmux"
remote = "ENTRY_IP:3080"
token = "PASTE-THE-TOKEN"
```

`target` **روی خروجی** پیدا و وصل می‌شود؛ پس `127.0.0.1:443` یعنی پورت ۴۴۳ خودِ سرور خروجی.

## ۴. بررسی و اجرا

```bash
kariz check -c /etc/kariz/config.toml    # validates, prints a summary and warnings
kariz run -c /etc/kariz/config.toml
```

بهتر است اول سمتی را که گوش می‌دهد راه بیندازید، ولی ترتیب مهم نیست: سمتی که وصل می‌شود تا موفق شود دوباره تلاش می‌کند.

## ۵. اجرا به‌صورت سرویس

```bash
sudo cp systemd/kariz.service /etc/systemd/system/
sudo systemctl enable --now kariz
journalctl -u kariz -f
```

این unit فایل `/etc/kariz/config.toml` را می‌خواند، اگر کاریز از کار بیفتد دوباره راهش می‌اندازد و برای پورت‌های زیر ۱۰۲۴ دسترسی لازم را می‌دهد. بعد از تغییری که فقط در قاعده‌های `[[forward]]` باشد، `sudo systemctl reload kariz` آن را بدون قطع چیزی روی ورودیِ در حال اجرا اعمال می‌کند ([جزئیات](configuration.md#بارگذاری-دوبارهٔ-قاعده‌های-forward))؛ هر تغییر دیگری `sudo systemctl restart kariz` می‌خواهد.

## بعد از این

- برای مسیرتان ترنسپورت مناسب را انتخاب کنید: [ترنسپورت‌ها](transports.md).
- برای سرعت یا تأخیر کمتر تنظیم کنید: [پروفایل‌ها](profiles.md).
- همهٔ تنظیم‌ها: [مرجع پیکربندی](configuration.md).
- برای اداره‌کردن چند سرور از یک‌جا: [پنل وب](panel.md).
