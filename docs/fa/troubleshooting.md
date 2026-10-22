# عیب‌یابی

[English](../troubleshooting.md) · **فارسی**

روی هر دو سمت با `kariz check -c /etc/kariz/config.toml` شروع کنید: فایل را بررسی می‌کند، مقدارهای مؤثر را چاپ می‌کند و هشدارها را می‌گوید. روی تانلی که در حال اجراست، `kariz status -c ...` می‌گوید سمت دیگر وصل است یا نه، و اگر نیست، آخرین خطا چه بوده ([وضعیت](status.md)). بعد سراغ لاگ‌ها بروید:

```bash
journalctl -u kariz -f                      # with systemd
journalctl -u kariz -p warning              # warnings and errors only
RUST_LOG=kariz=debug kariz run -c ...       # more detail
```

اگر پنل وب دارید، صفحهٔ **لاگ** لاگ هر دو سمت یک تانل را به ترتیب زمان کنار هم نشان می‌دهد ([پنل](panel.md)).

## اصلاً بالا نمی‌آید

| پیام لاگ | علت | راه‌حل |
|---|---|---|
| `kariz@NAME.service: Main process exited, code=killed, status=4/ILL`، یا *Illegal instruction* وقتی دستی اجرا می‌کنید؛ تانل هر چند ثانیه ری‌استارت می‌شود | باینری به CPU جدیدتری از سرور نیاز دارد: بیلدهای x86_64 نسخه‌های 2.9.2 و 2.10.0 تا 2.10.2 دستورهای AVX2 دارند و این CPU ندارد (`grep -c avx2 /proc/cpuinfo` عدد `0` می‌دهد) | به 2.9.3 یا بالاتر به‌روز کنید (`kariz-manager update`)؛ تا آن موقع `kariz-manager update --version v2.9.1` |

## دو سمت وصل نمی‌شوند

| پیام لاگ | علت | راه‌حل |
|---|---|---|
| `could not connect to the entry side` / `could not connect to the exit side` | سمتی که گوش می‌دهد در دسترس نیست | `listen` و `remote`، فایروال و security group ابری را بررسی کنید (برای `quic` و `kcp` باید UDP باز باشد) |
| `tunnel handshake failed: invalid hello tag` (سمت گوش‌دهنده)، `rejected the tunnel connection` / `entry side rejected us or failed authentication` (سمت وصل‌شونده) | توکن‌ها فرق دارند | یک توکن را روی هر دو سمت بگذارید |
| `hello timestamp out of range` | ساعت دو سرور چند دقیقه اختلاف دارد | NTP را روشن کنید (`timedatectl set-ntp true`) |
| `peer has mux on but this side has it off` | تنظیم mux فرق دارد | `[tunnel.mux] enabled` را روی هر دو سمت یکسان کنید |
| `peer uses encryption ..., which tunnel.encryption on this side does not allow` | یک سمت `encryption = "none"` دارد | آن را روی هر دو سمت بگذارید یا روی هیچ‌کدام |
| `404` از گوش‌دهندهٔ `ws` / `wss` | `ws.path` یا `ws.host` درست نیست | `ws.path` را یکی کنید و `ws.host` را روی گوش‌دهنده ببینید |
| `bad_certificate` (`quic`) | توکن‌ها فرق دارند | یک توکن را روی هر دو سمت بگذارید |

## وصل می‌شود، ولی

**کاربرها وصل می‌شوند و بلافاصله قطع می‌شوند.** خروجی به مقصد نرسیده است. خروجی `could not connect to target` را لاگ می‌کند. `target` از روی خروجی وصل می‌شود، پس `127.0.0.1:443` یعنی پورت ۴۴۳ خود سرور خروجی.

**UDP کار نمی‌کند.** ببینید قانون `protocol = "udp"` یا `"tcp+udp"` دارد و mux روشن است (`kariz check` در غیر این صورت هشدار می‌دهد). خروجی نسخهٔ ۰٫۲ اصلاً UDP را پشتیبانی نمی‌کند، و قانونی که `duplicate` دارد خروجی نسخهٔ ۰٫۵ یا جدیدتر می‌خواهد.

**کند است.**

- **روی مسیر پراتلاف** ترنسپورت‌های مبتنی بر TCP از پا می‌افتند؛ `kcp` یا `quic` با `congestion = "bbr"` را امتحان کنید.
- **روی مسیر تمیز** هر stream در هر رفت‌وبرگشت به اندازهٔ یک پنجره داده می‌برد: `profile = "ultraspeed"` بگذارید یا `tunnel.mux.stream_window` را بالا ببرید.
- [کارایی](performance.md#تنظیم-برای-سرعت) را هم ببینید.

**بازی زیر بار لگ می‌کند.** روی هر دو سمت `profile = "gaming"` و `kcp` بگذارید. ترنسپورت‌های مبتنی بر TCP بستهٔ بازی را منتظر هر segment گم‌شده نگه می‌دارند. [UDP و بازی](udp-and-games.md) را ببینید.

**پشت CDN، اتصال‌ها بعد از حدود ۱۰۰ ثانیه بی‌کاری قطع می‌شوند.** `tunnel.mux.ping_interval_secs` (یا `tuning.keepalive_secs`) را ۹۰ یا کمتر نگه دارید.

**`quic` یا `kcp` هیچ‌وقت وصل نمی‌شود.** شاید UDP روی مسیر بسته یا کند شده باشد، به‌ویژه UDP روی پورت ۴۴۳. پورت دیگری امتحان کنید یا به `tcpmux` یا `wss` برگردید. اگر `kcp` وصل می‌شود ولی `quic` نه، احتمالاً مسیر QUIC را تشخیص می‌دهد: `obfs = true` را در `[tunnel.quic]` روی هر دو سمت بگذارید. اگر `obfs` فقط روی یک سمت باشد، اتصال timeout می‌خورد.

**سروری که با *QUIC* به پنل اضافه کرده‌اید ظاهر نمی‌شود.** این لینک روی UDP و روی پورتِ بعد از پورت agentهای پنل است؛ آن پورت UDP باید روی سرور پنل و در هر فایروال ابری باز باشد. اگر UDP روی کل مسیر بسته است، در *افزودن سرور* *خودکار* (یا *TCP* یا *WSS*) را انتخاب کنید. توضیح بیشتر در [پنل وب](panel.md#عیبیابی).

## هشدارهای `kariz check`

| هشدار | معنی |
|---|---|
| `tunnel.encryption = "none"` | ترافیک روی سیم خواناست |
| ping interval بالای ۹۰ ثانیه روی `ws` / `wss` | CDN اتصال‌های بی‌کار را می‌بُرد |
| UDP بدون mux فوروارد شده | هر جریان UDP یک اتصال کامل تانل را می‌گیرد |
| `forward.duplicate has no effect here` | کپی‌ها فقط روی `kcp` (با mux) و `quic` فرستاده می‌شوند |
| `quic.congestion = "bbr"` | در quinn آزمایشی است و صف‌ها را پر می‌کند |
| `tls.insecure = true` | گواهی سرور بررسی نمی‌شود |
| `tuning.dscp` روی QUIC یا ویندوز | علامت به سیم نمی‌رسد |
