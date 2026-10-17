<p align="center">
  <img src="assets/banner.png" alt="کاریز. آب، راهش را از زیر زمین پیدا می‌کند." width="100%">
</p>

<p align="center">
  <a href="https://github.com/MAHDI-byte64/tun2/actions/workflows/ci.yml"><img src="https://github.com/MAHDI-byte64/tun2/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/MAHDI-byte64/tun2/releases"><img src="https://img.shields.io/github/v/release/MAHDI-byte64/tun2?label=version&color=34d0c3" alt="آخرین نسخه"></a>
  <img src="https://img.shields.io/badge/rust-1.80%2B-e9c46a?logo=rust" alt="Rust 1.80+">
  <img src="https://img.shields.io/badge/platform-linux-12365e?logo=linux&logoColor=white" alt="Linux">
</p>

<p align="center">
  <a href="README.md">English</a> · <b>فارسی</b> ·
  <a href="https://mahdi-byte64.github.io/tun2/fa/">وب‌سایت</a> ·
  <a href="https://mahdi-byte64.github.io/tun2/fa/docs/">مستندات</a> ·
  <a href="https://mahdi-byte64.github.io/tun2/fa/try/">دموی زنده</a> ·
  <a href="docs/fa/CHANGELOG.md">تغییرات</a>
</p>

---

<div dir="rtl">

**کاریز** نامش را از کاریزهای ایران گرفته: کانال‌هایی که زیر کویر کنده‌اند و آب را از دل کوه، از میان ردیفی از چاه‌ها، بی‌آن‌که به سطح زمین بیاید به آبادی می‌رسانند. این برنامه همین کار را برای ترافیک می‌کند. دو سرور را با یک تانل سریع و رمزنگاری‌شده به هم وصل می‌کند؛ کاربرها به **ورودی** (entry) وصل می‌شوند و کاریز ترافیک TCP و UDP‌شان را به **خروجی** (exit) می‌رساند، همان سروری که به مقصدهای واقعی دسترسی دارد.

</div>

```mermaid
flowchart LR
    U([Users]) -->|TCP / UDP| E[Entry]
    E <==>|"Kariz tunnel<br/>tcp · tcpmux · ws · wss · quic · kcp"| X[Exit]
    X --> T([Targets])
```

<div dir="rtl">

خود برنامه یک فایل کوچک به زبان Rust است (حدود ۸ مگابایت حافظه برای هر سمت و بدون garbage collector) و برای اداره‌اش یک پنل وب دارد: سرورها، تانل‌ها، نمودارها و لاگ‌ها، همه در مرورگر.

</div>

<p align="center">
  <img src="assets/screens/map-night-fa.png" alt="نقشهٔ پنل: سرورها چاه‌اند و تانل‌ها کانال، با ترافیک زنده" width="92%">
</p>

<table align="center">
  <tr>
    <td align="center" width="62%"><img src="assets/screens/tunnels-dawn-fa.png" alt="صفحهٔ تانل‌ها در تم روشن" width="100%"></td>
    <td align="center" width="26%"><img src="assets/screens/servers-phone-fa.png" alt="صفحهٔ سرورها روی گوشی" width="100%"></td>
  </tr>
</table>

<div dir="rtl">

## نصب

روی سروری که پنل را نگه می‌دارد، با دسترسی root:

</div>

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MAHDI-byte64/tun2/main/scripts/kariz.sh)
```

<div dir="rtl">

اسکریپت CPU سرور را تشخیص می‌دهد (x86_64، aarch64 یا armv7)، آخرین نسخه را می‌گیرد، امضایش را می‌سنجد و یک منو باز می‌کند. **نصب پنل وب** را انتخاب کنید تا نشانی پنل و یک لینک ورود یک‌بارمصرف چاپ شود. از آن به بعد کار در مرورگر است: سرورهای دیگرتان را اضافه کنید (هر کدام یک دستور را با کدی که پنل می‌دهد اجرا می‌کند) و با ویزارد بین هر دو سرور تانل بسازید.

می‌خواهید اول ببینید؟ [دموی زنده](https://mahdi-byte64.github.io/tun2/fa/try/) پنل واقعی را با داده‌های نمونه اجرا می‌کند.

## چه چیزی دارد

- **شش ترنسپورت.** `tcp`، `tcpmux`، `ws` و `wss` (برای CDN و جایی که ترافیک باید شبیه HTTPS باشد) و `quic` و `kcp` روی UDP برای مسیرهای دور یا پراتلاف. `quic` را می‌شود بسته‌به‌بسته مهر و موم کرد تا برای شبکه‌ای که QUIC را فیلتر می‌کند شبیه QUIC نباشد.
- **هر دو جهت.** خروجی می‌تواند به ورودی وصل شود (`reverse`) یا برعکس (`direct`)، با اتصال دوبارهٔ خودکار.
- **TCP و UDP.** WireGuard، DNS و بازی از آن رد می‌شوند. روی `kcp` و `quic` بستهٔ گم‌شده چیز دیگری را معطل نمی‌کند و برای بازی FEC و تکثیر اختیاری بسته هم هست.
- **پنلی که اشتباهش را خودش جمع می‌کند.** ویزارد تانل اول هر دو سرور را می‌سنجد و اگر جایی خطا شود هر دو را به حالت قبل برمی‌گرداند. نقشهٔ زنده، نمودار، لاگ، تست سرعت، پشتیبان‌گیری، شبکهٔ خصوصی و به‌روزرسانی هم همان‌جاست.
- **اعلان در تلگرام.** رباتِ خودتان وقتی سروری آفلاین یا تانلی قطع شود (و وقتی برگردد) خبر می‌دهد و به `/status` با وضعیت همهٔ سرورها و تانل‌ها جواب می‌دهد. جایی که تلگرام بسته است از پروکسی یا از یک تانل رد می‌شود. [راه‌اندازی](https://mahdi-byte64.github.io/tun2/fa/docs/telegram/).
- **انتشار امضاشده.** اسکریپت نصب، پنل و agentها پیش از اجرای هر چیزی از یک نسخه، امضایش را بررسی می‌کنند.

## مستندات

بقیهٔ مطالب در وب‌سایت است، به فارسی و انگلیسی:

| | |
|---|---|
| [شروع کار](https://mahdi-byte64.github.io/tun2/fa/docs/getting-started/) | نصب، اولین تانل، systemd |
| [کار با پنل](https://mahdi-byte64.github.io/tun2/fa/docs/using-the-panel/) · [تور راهنما](https://mahdi-byte64.github.io/tun2/fa/docs/tour/) · [ویدیوی آموزشی](https://mahdi-byte64.github.io/tun2/fa/docs/video/) | پنل، صفحه به صفحه، و در دو دقیقه ویدیو |
| [اسکریپت مدیر](https://mahdi-byte64.github.io/tun2/fa/docs/manager/) | نصب، به‌روزرسانی، منو |
| [ترنسپورت‌ها](https://mahdi-byte64.github.io/tun2/fa/docs/transports/) · [کدام یکی؟](https://mahdi-byte64.github.io/tun2/fa/docs/how-it-works/) | انتخاب و تنظیم |
| [مرجع پیکربندی](https://mahdi-byte64.github.io/tun2/fa/docs/configuration/) | همهٔ تنظیم‌ها با مقدار پیش‌فرض و محدوده |
| [UDP و بازی](https://mahdi-byte64.github.io/tun2/fa/docs/udp-and-games/) · [CDN](https://mahdi-byte64.github.io/tun2/fa/docs/cdn/) | راه‌اندازی‌های خاص |
| [عیب‌یابی](https://mahdi-byte64.github.io/tun2/fa/docs/troubleshooting/) · [امنیت](https://mahdi-byte64.github.io/tun2/fa/docs/security/) | وقتی چیزی درست کار نمی‌کند |
| [تغییرات](https://mahdi-byte64.github.io/tun2/fa/docs/changelog/) | هر نسخه چه چیزی عوض شد |

همین صفحه‌ها فایل‌های Markdown پوشهٔ [`docs/fa/`](docs/fa/README.md) هستند (نسخهٔ انگلیسی: [`docs/`](docs/README.md)).

## ساخت از روی سورس

</div>

```bash
cargo build --release                         # target/release/kariz
cargo test                                    # اگر nginx نصب باشد تست‌های nginx هم اجرا می‌شوند
cargo build --release --no-default-features   # بدون quic و kcp
```

<div dir="rtl">

برنامهٔ وب پنل در `panel/web` است (`npm ci && npm run build`) و وب‌سایت در `site/`. طراحی و پروتکل در [docs/ROADMAP.md](docs/ROADMAP.md) شرح داده شده است.

## حمایت

کاریز را یک نفر می‌سازد و اجرایش روی سرورهای خودتان رایگان است. اگر به کارتان آمده و می‌خواهید ادامه پیدا کند، می‌توانید کمک مالی کنید؛ هیچ‌وقت لازم نیست. هر ارز را **فقط روی شبکه‌ای** بفرستید که کنارش نوشته شده: ارزی که روی شبکهٔ دیگری فرستاده شود برگردانده نمی‌شود. (همین مطلب در وب‌سایت هم هست: [فارسی](docs/fa/support.md) و [English](docs/support.md).)

</div>

| Coin | Network | Address |
|---|---|---|
| USDT | TRON (TRC20) | `TKM87mEXhUpEBzqvNxs1qjM4EddX6VMXmw` |
| Gram | TON | `UQDfjT-h4ENIrt_Sq5-zBy9TvhckniwSLCkS7zIVX4fVSaFw` |
| Bitcoin (BTC) | Bitcoin | `bc1qc4cgy5etuwj2375c5zqma7xmjtk59s5s49rfp5` |

<div dir="rtl">

ستاره دادن به مخزن، گزارش مشکل همراه با لاگ، و گفتن از کاریز به مدیران سرور دیگر هم به همان اندازه کمک می‌کند.

## مجوز

کاریز **کدباز نیست، «سورس‌در‌دسترس» است**. می‌توانید کد را بخوانید و نسخه‌های رسمی را روی سرورهای خودتان اجرا کنید؛ استفاده از هسته (یا هر بخشی از آن) در جای دیگر، کپی کردن یا پخش کردنش مجاز نیست. متن کامل شرایط در فایل [LICENSE](LICENSE) است (متن انگلیسی معتبر است).

<p align="center"><sub>© ErfanXRay</sub></p>

</div>
