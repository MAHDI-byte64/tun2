/* Kariz panel prototype, step 9.3: servers, tunnels, tunnel detail, logs, settings. */
(() => {
  "use strict";
  const K = window.K;
  const { $, $$, t, fmt, fmtRate, clamp, rgba, fitCanvas, uiFont, SERVERS, TUNNELS, state, byId, toast } = K;

  // ------------------------------------------------------------------ strings

  K.addStrings({
    fa: {
      "srv.sub": "{n} سرور · همه وصل‌اند",
      "srv.add": "افزودن سرور",
      "srv.count": "سرور",
      "srv.online": "آنلاین",
      "srv.tunnels": "تانل روی آن‌ها",
      "srv.panel": "پنل روی",
      "srv.search": "جستجوی نام یا IP",
      "srv.via": "از طریق {via}",
      "srv.seen": "{s} ثانیه پیش",
      "srv.cpu": "پردازنده",
      "srv.ram": "حافظه",
      "srv.net": "شبکه",
      "srv.tn": "{n} تانل",
      "srv.thisPanel": "پنل همین‌جاست",
      "srv.details": "جزئیات سرور",
      "srv.update": "به‌روزرسانی کاریز",
      "srv.restartAgent": "ری‌استارت agent",
      "srv.remove": "حذف سرور",
      "srv.removeNote": "تانل‌های این سرور اول باید حذف شوند.",
      "srv.arch": "معماری",
      "srv.version": "نسخه",
      "srv.uptime": "روشن از",
      "srv.link": "اتصال به پنل",
      "srv.upToDate": "به‌روز است",
      "add.title": "افزودن سرور",
      "add.name": "نام سرور (اختیاری)",
      "add.nameHelp": "اگر خالی بماند، hostname خود سرور گذاشته می‌شود.",
      "add.dir": "چه کسی وصل می‌شود؟",
      "add.dirAgent": "سرور به پنل وصل شود",
      "add.dirPanel": "پنل به سرور وصل شود",
      "add.dirAgentHelp": "پیشنهادی. روی سرور جدید پورتی باز نمی‌شود و پشت NAT هم کار می‌کند.",
      "add.dirPanelHelp": "وقتی پنل پشت NAT است. سرور روی یک پورت منتظر پنل می‌ماند.",
      "add.run": "این دستور را روی سرور جدید، با root، اجرا کنید:",
      "add.valid": "کد عضویت {m} دیگر اعتبار دارد و فقط یک بار کار می‌کند.",
      "add.waiting": "منتظر اتصال سرور…",
      "add.connected": "وصل شد: {name}",
      "add.new": "کد تازه",
      "done": "تمام",
      cancel: "انصراف",
      close: "بستن",
      copied: "کپی شد",
      "tn.sub": "{up} جاری · {down} قطع · {off} خاموش",
      "tn.all": "همه",
      "tn.search": "جستجوی نام، سرور یا پورت",
      "tn.new": "تانل جدید",
      "tn.mode": "حالت",
      "tn.ports": "پورت‌ها",
      "tn.empty": "تانلی با این فیلتر نیست.",
      "mode.reverse": "reverse",
      "mode.direct": "direct",
      "d.restart": "ری‌استارت",
      "d.stop": "خاموش",
      "d.start": "روشن",
      "d.edit": "ویرایش",
      "d.delete": "حذف",
      "d.speed": "اسپیدتست",
      "d.users": "کاربران به این‌جا وصل می‌شوند",
      "d.targets": "مقصدها از این‌جا dial می‌شوند",
      "d.lat": "تأخیر",
      "d.conns": "اتصال باز",
      "d.sessions": "session های mux",
      "d.hsErr": "خطای handshake در ساعت اخیر",
      "d.uptime": "روشن از",
      "d.traffic": "ترافیک",
      "d.down": "دانلود",
      "d.up": "آپلود",
      "d.fwd": "پورت‌های فوروارد",
      "d.listen": "روی entry",
      "d.target": "مقصد روی exit",
      "d.proto": "پروتکل",
      "d.config": "کانفیگ",
      "d.events": "رویدادها",
      "d.entrySide": "سمت entry",
      "d.exitSide": "سمت exit",
      "d.diagTitle": "handshake رد می‌شود",
      "d.diagText": "exit به entry می‌رسد، ولی entry اتصالش را رد می‌کند: توکن دو طرف یکی نیست. معمولاً وقتی پیش می‌آید که کانفیگ یک طرف دستی عوض شده باشد.",
      "d.diag1": "توکن را دوباره از پنل به هر دو طرف بفرستید (هر دو ری‌استارت می‌شوند).",
      "d.diag2": "اگر درست نشد، لاگ exit را ببینید: شاید دیوارآتش پورت 3080 را بسته باشد.",
      "d.fix": "یکسان‌سازی توکن",
      "d.fixing": "توکن تازه روی هر دو سرور نوشته شد؛ در حال ری‌استارت…",
      "d.fixed": "backup دوباره جاری است.",
      "d.speedIdle": "اسپیدتست از داخل همین تانل، با session های واقعی آن، اجرا می‌شود.",
      "d.speedRun": "اجرای اسپیدتست",
      "d.speedDown": "دانلود…",
      "d.speedUp": "آپلود…",
      "d.speedOff": "تانل باید جاری باشد.",
      "d.delTitle": "حذف تانل {name}",
      "d.delText": "کانفیگ و سرویس روی هر دو سرور پاک می‌شوند و کاربرانی که الان وصل‌اند قطع می‌شوند. برای تأیید، نام تانل را بنویسید:",
      "d.deleted": "تانل {name} حذف شد.",
      "d.restarted": "{name} ری‌استارت شد؛ ۲ session دوباره برقرار شد.",
      "range.5m": "۵ دقیقه",
      "range.1h": "۱ ساعت",
      "range.24h": "۲۴ ساعت",
      "ago.s": "{n} ثانیه پیش",
      "ago.m": "{n} دقیقه پیش",
      "ago.h": "{n} ساعت پیش",
      "ago.d": "{n} روز پیش",
      "dur.d": "{d} روز و {h} ساعت",
      "dur.h": "{h} ساعت و {m} دقیقه",
      "ev.start": "کاریز روی هر دو سرور شروع شد",
      "ev.session": "session mux برقرار شد (۲ از ۲)",
      "ev.speed": "اسپیدتست: ↓ ۸۴۲ ↑ ۱۹۶ Mbps",
      "ev.edit": "پورت 2053 اضافه شد",
      "ev.hsFail": "handshake رد شد: authentication failed",
      "ev.retry": "exit دوباره تلاش می‌کند (هر ۵ ثانیه)",
      "ev.stop": "با دست خاموش شد",
      "log.all": "همهٔ تانل‌ها",
      "log.search": "جستجو در لاگ",
      "log.pause": "توقف",
      "log.resume": "ادامه",
      "log.clear": "پاک کردن",
      "log.jump": "رفتن به آخرین خط ({n} تازه)",
      "log.none": "خطی با این فیلتر نیست.",
      "log.sub": "زنده، از journald هر دو سرور",
      "set.sub": "امنیت، دسترسی، ظاهر، به‌روزرسانی و پشتیبان",
      "set.sec": "امنیت",
      "set.access": "دسترسی به پنل",
      "set.look": "ظاهر",
      "set.upd": "به‌روزرسانی",
      "set.backup": "پشتیبان",
      "set.audit": "گزارش کارها",
      "set.pw": "رمز مدیر",
      "set.pwText": "تنظیم شده · ۱۲ روز پیش عوض شد",
      "set.pwChange": "تغییر رمز",
      "set.pwCur": "رمز فعلی",
      "set.pwNew": "رمز تازه",
      "set.pwAgain": "تکرار رمز تازه",
      "set.pwWeak": "ضعیف",
      "set.pwOk": "قابل قبول",
      "set.pwStrong": "قوی",
      "set.pwMismatch": "دو رمز یکی نیستند.",
      "set.pwSaved": "رمز عوض شد. بقیهٔ session ها بسته شدند.",
      "set.link": "لینک ورود یک‌بارمصرف",
      "set.linkText": "برای ورود از دستگاهی دیگر، بدون رمز. یک بار کار می‌کند و ۶۰ دقیقه اعتبار دارد.",
      "set.linkMake": "ساخت لینک",
      "set.linkValid": "اعتبار: {m}",
      "set.2fa": "تأیید دومرحله‌ای (TOTP)",
      "set.2faText": "بعد از رمز، یک کد ۶ رقمی از Google Authenticator یا هر برنامهٔ TOTP.",
      "set.2faScan": "این کد را در برنامهٔ احراز هویت اسکن کنید و کد ۶ رقمی را وارد کنید:",
      "set.2faCode": "کد ۶ رقمی",
      "set.2faOn": "تأیید دومرحله‌ای روشن شد.",
      "set.2faBad": "کد باید ۶ رقم باشد.",
      "set.verify": "تأیید",
      "set.sessions": "session های فعال",
      "set.sessionsText": "هر جا که وارد شده‌اید. هر کدام را که نمی‌شناسید باطل کنید.",
      "set.thisDevice": "همین دستگاه",
      "set.revoke": "باطل کردن",
      "set.revoked": "session باطل شد.",
      "set.lock": "محافظت از ورود",
      "set.lockText": "بعد از چند تلاش ناموفق، آن IP برای مدتی قفل می‌شود.",
      "set.lock5": "۵ تلاش، ۱۵ دقیقه قفل",
      "set.lock3": "۳ تلاش، ۱ ساعت قفل",
      "set.addr": "آدرس پنل",
      "set.addrText": "مسیر مخفی باعث می‌شود اسکنرها صفحهٔ ورود را پیدا نکنند.",
      "set.newPath": "مسیر تازه",
      "set.pathNew": "مسیر عوض شد. آدرس قدیمی دیگر کار نمی‌کند.",
      "set.tls": "گواهی TLS",
      "set.tlsText": "Self-signed بدون دامنه کار می‌کند؛ مرورگر اثر انگشتش را نشان می‌دهد.",
      "set.tlsSelf": "Self-signed",
      "set.tlsLe": "Let's Encrypt",
      "set.domain": "دامنه",
      "set.getCert": "گرفتن گواهی",
      "set.certOk": "گواهی گرفته شد؛ تا ۹۰ روز معتبر است و خودکار تمدید می‌شود.",
      "set.fp": "اثر انگشت SHA-256",
      "set.lang": "زبان",
      "set.theme": "تم",
      "set.digits": "ارقام",
      "set.digitsFa": "فارسی ۱۲۳",
      "set.digitsLatin": "لاتین 123",
      "set.motion": "حرکت",
      "set.motionFull": "کامل",
      "set.motionLow": "کم‌مصرف",
      "set.night": "شب",
      "set.dawn": "سحر",
      "set.updText": "آخرین نسخه: 0.6.1 · ۲ ساعت پیش بررسی شد",
      "set.check": "بررسی الان",
      "set.checked": "همه به‌روزند.",
      "set.auto": "بررسی خودکار روزانه",
      "set.bk": "پشتیبان رمزشده",
      "set.bkText": "همهٔ تانل‌ها، سرورها و تنظیمات، رمزشده با یک عبارت. توکن‌ها هم داخلش هستند.",
      "set.bkDown": "دانلود پشتیبان",
      "set.bkUp": "بازیابی از فایل",
      "set.bkPass": "عبارت رمز پشتیبان",
      "set.bkMade": "kariz-backup-2026-09-29.kbk آماده شد.",
      "set.when": "زمان",
      "set.what": "کار",
      "set.who": "از",
      "cmd.addServer": "افزودن سرور",
      "cmd.open": "باز کردن تانل",
      "cmd.link": "ساخت لینک ورود",
      "cmd.logs": "لاگ‌های زنده",
    },
    en: {
      "srv.sub": "{n} servers · all connected",
      "srv.add": "Add server",
      "srv.count": "servers",
      "srv.online": "online",
      "srv.tunnels": "tunnels on them",
      "srv.panel": "panel on",
      "srv.search": "Search a name or IP",
      "srv.via": "over {via}",
      "srv.seen": "{s} s ago",
      "srv.cpu": "CPU",
      "srv.ram": "Memory",
      "srv.net": "Network",
      "srv.tn": "{n} tunnels",
      "srv.thisPanel": "the panel runs here",
      "srv.details": "Server details",
      "srv.update": "Update Kariz",
      "srv.restartAgent": "Restart the agent",
      "srv.remove": "Remove server",
      "srv.removeNote": "Its tunnels have to be deleted first.",
      "srv.arch": "Architecture",
      "srv.version": "Version",
      "srv.uptime": "Up for",
      "srv.link": "Link to the panel",
      "srv.upToDate": "up to date",
      "add.title": "Add a server",
      "add.name": "Server name (optional)",
      "add.nameHelp": "Left empty, the server's own hostname is used.",
      "add.dir": "Who connects?",
      "add.dirAgent": "The server dials the panel",
      "add.dirPanel": "The panel dials the server",
      "add.dirAgentHelp": "Recommended. No port opens on the new server, and it works behind NAT.",
      "add.dirPanelHelp": "When the panel is behind NAT. The server waits for the panel on a port.",
      "add.run": "Run this on the new server, as root:",
      "add.valid": "The join code is valid for {m} more and works once.",
      "add.waiting": "Waiting for the server to connect…",
      "add.connected": "Connected: {name}",
      "add.new": "New code",
      done: "Done",
      cancel: "Cancel",
      close: "Close",
      copied: "Copied",
      "tn.sub": "{up} flowing · {down} broken · {off} stopped",
      "tn.all": "All",
      "tn.search": "Search a name, server or port",
      "tn.new": "New tunnel",
      "tn.mode": "Mode",
      "tn.ports": "Ports",
      "tn.empty": "No tunnel matches this filter.",
      "mode.reverse": "reverse",
      "mode.direct": "direct",
      "d.restart": "Restart",
      "d.stop": "Stop",
      "d.start": "Start",
      "d.edit": "Edit",
      "d.delete": "Delete",
      "d.speed": "Speed test",
      "d.users": "users connect here",
      "d.targets": "targets are dialed from here",
      "d.lat": "Latency",
      "d.conns": "Open connections",
      "d.sessions": "Mux sessions",
      "d.hsErr": "Handshake errors, last hour",
      "d.uptime": "Up for",
      "d.traffic": "Traffic",
      "d.down": "Down",
      "d.up": "Up",
      "d.fwd": "Forwarded ports",
      "d.listen": "On the entry",
      "d.target": "Target on the exit",
      "d.proto": "Protocol",
      "d.config": "Config",
      "d.events": "Events",
      "d.entrySide": "Entry side",
      "d.exitSide": "Exit side",
      "d.diagTitle": "The handshake is rejected",
      "d.diagText": "The exit reaches the entry, but the entry turns it away: the two sides' tokens differ. This usually happens when one side's config was edited by hand.",
      "d.diag1": "Send the token from the panel to both sides again (both restart).",
      "d.diag2": "If that does not fix it, read the exit's log: a firewall may be closing port 3080.",
      "d.fix": "Make the tokens match",
      "d.fixing": "A new token was written on both servers; restarting…",
      "d.fixed": "backup is flowing again.",
      "d.speedIdle": "The test runs inside this tunnel, through its real sessions.",
      "d.speedRun": "Run a speed test",
      "d.speedDown": "Download…",
      "d.speedUp": "Upload…",
      "d.speedOff": "The tunnel has to be flowing.",
      "d.delTitle": "Delete tunnel {name}",
      "d.delText": "Its config and service are removed from both servers, and users connected now are cut off. Type the tunnel's name to confirm:",
      "d.deleted": "Tunnel {name} deleted.",
      "d.restarted": "{name} restarted; 2 sessions are back.",
      "range.5m": "5 min",
      "range.1h": "1 hour",
      "range.24h": "24 hours",
      "ago.s": "{n} s ago",
      "ago.m": "{n} min ago",
      "ago.h": "{n} h ago",
      "ago.d": "{n} days ago",
      "dur.d": "{d} d {h} h",
      "dur.h": "{h} h {m} min",
      "ev.start": "Kariz started on both servers",
      "ev.session": "Mux sessions established (2 of 2)",
      "ev.speed": "Speed test: ↓ 842 ↑ 196 Mbps",
      "ev.edit": "Port 2053 added",
      "ev.hsFail": "Handshake rejected: authentication failed",
      "ev.retry": "The exit retries every 5 s",
      "ev.stop": "Stopped by hand",
      "log.all": "All tunnels",
      "log.search": "Search the log",
      "log.pause": "Pause",
      "log.resume": "Resume",
      "log.clear": "Clear",
      "log.jump": "Jump to the latest ({n} new)",
      "log.none": "No line matches this filter.",
      "log.sub": "live, from both servers' journald",
      "set.sub": "Security, access, appearance, updates and backups",
      "set.sec": "Security",
      "set.access": "Panel access",
      "set.look": "Appearance",
      "set.upd": "Updates",
      "set.backup": "Backup",
      "set.audit": "Audit log",
      "set.pw": "Admin password",
      "set.pwText": "Set · changed 12 days ago",
      "set.pwChange": "Change password",
      "set.pwCur": "Current password",
      "set.pwNew": "New password",
      "set.pwAgain": "New password again",
      "set.pwWeak": "weak",
      "set.pwOk": "fair",
      "set.pwStrong": "strong",
      "set.pwMismatch": "The two passwords differ.",
      "set.pwSaved": "Password changed. Other sessions were signed out.",
      "set.link": "One-time login link",
      "set.linkText": "Sign in from another device without the password. Works once, for 60 minutes.",
      "set.linkMake": "Make a link",
      "set.linkValid": "Valid for {m}",
      "set.2fa": "Two-step sign-in (TOTP)",
      "set.2faText": "After the password, a 6-digit code from Google Authenticator or any TOTP app.",
      "set.2faScan": "Scan this in your authenticator app and enter the 6-digit code:",
      "set.2faCode": "6-digit code",
      "set.2faOn": "Two-step sign-in is on.",
      "set.2faBad": "The code has 6 digits.",
      "set.verify": "Verify",
      "set.sessions": "Active sessions",
      "set.sessionsText": "Everywhere you are signed in. Revoke any you do not recognise.",
      "set.thisDevice": "this device",
      "set.revoke": "Revoke",
      "set.revoked": "Session revoked.",
      "set.lock": "Sign-in protection",
      "set.lockText": "After a few failed tries, that IP is locked out for a while.",
      "set.lock5": "5 tries, 15 min lockout",
      "set.lock3": "3 tries, 1 hour lockout",
      "set.addr": "Panel address",
      "set.addrText": "The secret path keeps scanners from finding the sign-in page.",
      "set.newPath": "New path",
      "set.pathNew": "Path changed. The old address no longer works.",
      "set.tls": "TLS certificate",
      "set.tlsText": "Self-signed works without a domain; the browser shows its fingerprint.",
      "set.tlsSelf": "Self-signed",
      "set.tlsLe": "Let's Encrypt",
      "set.domain": "Domain",
      "set.getCert": "Get the certificate",
      "set.certOk": "Certificate issued; valid for 90 days and renewed automatically.",
      "set.fp": "SHA-256 fingerprint",
      "set.lang": "Language",
      "set.theme": "Theme",
      "set.digits": "Digits",
      "set.digitsFa": "Persian ۱۲۳",
      "set.digitsLatin": "Latin 123",
      "set.motion": "Motion",
      "set.motionFull": "Full",
      "set.motionLow": "Low power",
      "set.night": "Night",
      "set.dawn": "Dawn",
      "set.updText": "Latest: 0.6.1 · checked 2 hours ago",
      "set.check": "Check now",
      "set.checked": "Everything is up to date.",
      "set.auto": "Check daily",
      "set.bk": "Encrypted backup",
      "set.bkText": "All tunnels, servers and settings, encrypted with a passphrase. Tokens included.",
      "set.bkDown": "Download backup",
      "set.bkUp": "Restore from a file",
      "set.bkPass": "Backup passphrase",
      "set.bkMade": "kariz-backup-2026-09-29.kbk is ready.",
      "set.when": "When",
      "set.what": "What",
      "set.who": "From",
      "cmd.addServer": "Add a server",
      "cmd.open": "Open tunnel",
      "cmd.link": "Make a login link",
      "cmd.logs": "Live logs",
    },
  });

  const tf = (key, vars) => t(key).replace(/\{(\w+)\}/g, (_, k) => vars[k]);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  const icon = (id, cls = "") => `<svg class="${cls}" width="18" height="18" aria-hidden="true"><use href="#i-${id}"/></svg>`;

  function ago(sec) {
    if (sec < 60) return tf("ago.s", { n: fmt(sec) });
    if (sec < 3600) return tf("ago.m", { n: fmt(Math.floor(sec / 60)) });
    if (sec < 86400) return tf("ago.h", { n: fmt(Math.floor(sec / 3600)) });
    return tf("ago.d", { n: fmt(Math.floor(sec / 86400)) });
  }
  function dur(sec) {
    const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
    return d ? tf("dur.d", { d: fmt(d), h: fmt(h) }) : tf("dur.h", { h: fmt(h), m: fmt(m) });
  }
  const mmss = (s) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;

  // ------------------------------------------------------------------ more sample data

  const EXTRA = {
    teh: { ver: "0.6.1", arch: "x86_64", up: 38 * 86400 + 4 * 3600, via: "local", net: 62, panel: true },
    tbz: { ver: "0.6.1", arch: "x86_64", up: 12 * 86400 + 7 * 3600, via: "tcpmux", net: 21 },
    fra: { ver: "0.6.1", arch: "x86_64", up: 51 * 86400, via: "tcpmux", net: 58 },
    hel: { ver: "0.6.1", arch: "aarch64", up: 9 * 86400 + 2 * 3600, via: "wss", net: 8 },
    ams: { ver: "0.6.1", arch: "aarch64", up: 3 * 86400 + 11 * 3600, via: "tcpmux", net: 2 },
  };
  for (const s of SERVERS) Object.assign(s, EXTRA[s.id], { seen: 1 + Math.floor(Math.random() * 3) });

  const FWD = {
    main: [["443", "127.0.0.1:443", "tcp"], ["8443", "127.0.0.1:8443", "tcp"], ["2053", "127.0.0.1:53", "tcp+udp"]],
    games: [["27015-27020", "10.0.0.5:27015-27020", "udp"], ["27015", "10.0.0.5:27015", "tcp"]],
    cdn: [["80", "127.0.0.1:80", "tcp"], ["443", "127.0.0.1:443", "tcp"]],
    backup: [["9443", "127.0.0.1:443", "tcp"]],
    office: [["3389", "10.1.0.20:3389", "tcp"], ["445", "10.1.0.20:445", "tcp"]],
  };
  for (const tn of TUNNELS) {
    tn.mode = tn.mode || (tn.id === "cdn" ? "direct" : "reverse");
    tn.fwd = tn.fwd || FWD[tn.id] || [];
    tn.ports = tn.ports ?? tn.fwd.reduce((n, f) => n + portCount(f[0]), 0);
    tn.uptime = tn.uptime ?? (tn.st === "up" ? 5 * 86400 + tn.level * 7200 : 0);
    tn.listenPort = tn.listenPort || 3080 + tn.level;
    tn.token = tn.token || "kz_" + Math.random().toString(36).slice(2, 14) + Math.random().toString(36).slice(2, 12);
    seedHistory(tn);
  }

  function portCount(spec) {
    const m = String(spec).match(/^(\d+)-(\d+)$/);
    return m ? Number(m[2]) - Number(m[1]) + 1 : 1;
  }

  function seedHistory(tn) {
    tn.h = { down: [], up: [] };
    let n = Math.random();
    for (let i = 0; i < 300; i++) {
      n = clamp(n + (Math.random() - 0.5) * 0.2, 0, 1);
      const d = tn.st === "up" ? tn.base * (0.7 + 0.6 * n) : 0;
      tn.h.down.push(d);
      tn.h.up.push(d * 0.18);
    }
  }
  K.seedHistory = seedHistory;
  K.portCount = portCount;

  K.ticks.push(() => {
    for (const tn of TUNNELS) {
      if (!tn.h) seedHistory(tn);
      tn.h.down.push(tn.down);
      tn.h.up.push(tn.up);
      tn.h.down.shift();
      tn.h.up.shift();
      if (tn.st === "up") tn.uptime += 1;
    }
    for (const s of SERVERS) {
      s.cpu = clamp(s.cpu + (Math.random() - 0.5) * 6, 2, 96);
      s.net = clamp((s.net || 5) + (Math.random() - 0.5) * 8, 1, 99);
      s.seen = s.via === "local" ? 0 : 1 + Math.floor(Math.random() * 3);
    }
  });

  // ------------------------------------------------------------------ shared UI parts

  function wellSvg(st, level = 0.6) {
    const col = st === "up" ? "var(--water)" : st === "warn" ? "var(--warn)" : "var(--danger)";
    const y = 40 - 14 * level;
    return `<svg class="srv-well" viewBox="0 0 44 44" aria-hidden="true">
      <path d="M4 16h36" stroke="var(--accent)" stroke-width="2" stroke-linecap="round"/>
      <path d="M12 16a10 7 0 0 1 20 0Z" fill="var(--accent)"/>
      <rect x="18" y="16" width="8" height="25" rx="2" fill="var(--stratum-3)"/>
      <rect x="18" y="${y}" width="8" height="${41 - y}" rx="2" fill="${col}"/>
    </svg>`;
  }

  function meter(label, pct, cls = "") {
    return `<div class="meter ${cls} ${pct > 85 ? "hot" : ""}"><div class="top"><span>${label}</span><b>${fmt(pct)}%</b></div><div class="bar"><i style="width:${pct}%"></i></div></div>`;
  }

  function stateBadge(st) {
    const cls = st === "up" ? "water" : st === "down" ? "danger" : "muted";
    return `<span class="badge ${cls}"><i class="dot ${st}"></i>${K.stateLabel(st)}</span>`;
  }

  // dialogs
  const dlg = $("#dialog");
  let dlgClose = null;
  function dialog(title, body, foot, onMount) {
    dlg.innerHTML = `<div class="dialog" role="document"><header><h2>${title}</h2><button class="x-btn" data-close aria-label="${t("close")}">${icon("x")}</button></header><div class="body">${body}</div>${foot ? `<footer>${foot}</footer>` : ""}</div>`;
    dlg.classList.add("is-on");
    const close = () => {
      dlg.classList.remove("is-on");
      dlgClose = null;
      clearInterval(dlg._timer);
      clearTimeout(dlg._wait);
    };
    dlgClose = close;
    for (const b of $$("[data-close]", dlg)) b.addEventListener("click", close);
    setTimeout(() => ($("input, button:not(.x-btn)", dlg) || $(".x-btn", dlg))?.focus(), 60);
    onMount?.(dlg, close);
    return close;
  }
  dlg.addEventListener("click", (e) => {
    if (e.target === dlg) dlgClose?.();
  });
  addEventListener("keydown", (e) => {
    if (e.key === "Escape" && dlgClose) dlgClose();
  });
  K.dialog = dialog;

  // copy buttons inside code blocks
  document.addEventListener("click", (e) => {
    const b = e.target.closest(".copy-btn");
    if (!b) return;
    const text = b.dataset.copy || b.closest(".code")?.dataset.text || "";
    navigator.clipboard?.writeText(text).catch(() => {});
    b.classList.add("done");
    b.innerHTML = icon("check");
    b.setAttribute("aria-label", t("copied"));
    setTimeout(() => {
      b.classList.remove("done");
      b.innerHTML = icon("copy");
    }, 1600);
  });
  const codeBlock = (html, text) => `<pre class="code" data-text="${esc(text)}">${html}<button class="copy-btn" type="button" aria-label="Copy">${icon("copy")}</button></pre>`;

  // TOML with a little colour
  function tomlHtml(src) {
    return src
      .split("\n")
      .map((line) => {
        const e = esc(line);
        if (/^\s*#/.test(line)) return `<span class="c">${e}</span>`;
        if (/^\s*\[/.test(line)) return `<span class="k">${e}</span>`;
        return e.replace(/^(\s*[\w.]+)( = )(.*)$/, (_, k, eq, v) => `${k}${eq}<span class="s">${v}</span>`);
      })
      .join("\n");
  }

  // the two configs of a tunnel, as the panel would write them
  function configs(tn) {
    const a = byId(tn.a), b = byId(tn.b);
    const entryListens = tn.mode === "reverse";
    const lsn = entryListens ? a : b;
    const host = lsn.ip.includes(":") ? `[${lsn.ip}]` : lsn.ip;
    const bind = tn.ipv4only ? "0.0.0.0" : "[::]";
    const common = (role) => `# Written by the Kariz panel. Edit it from the panel, not by hand.\nrole = "${role}"\nmode = "${tn.mode}"\nprofile = "${tn.prof}"\n\n[tunnel]\ntransport = "${tn.tr}"\n`;
    const side = (listens) => (listens ? `listen = "${bind}:${tn.listenPort}"\n` : `remote = "${host}:${tn.listenPort}"\n`);
    const extra = (dialer) =>
      tn.tr === "ws" || tn.tr === "wss"
        ? `\n[tunnel.ws]\npath = "${tn.wsPath || "/ws"}"\n` + (tn.tr === "wss" ? (dialer ? `\n[tunnel.tls]\npin_sha256 = "9f2c41e07b5d3a18c6e4f0a9d2b7c85e1f3a6d0c4b8e2f7a9c1d5e3b6a0f4c82"\n` : `\n[tunnel.tls]\ncert = "/etc/kariz/${tn.id}.crt"\nkey = "/etc/kariz/${tn.id}.key"\n`) : "")
        : "";
    const tok = `token = "${tn.token}"\n`;
    const entry =
      common("entry") + side(entryListens) + tok + extra(!entryListens) +
      tn.fwd.map((f) => `\n[[forward]]\nlisten = "${bind}:${f[0]}"\ntarget = "${f[1]}"\n` + (f[2] !== "tcp" ? `protocol = "${f[2]}"\n` : "")).join("") +
      `\n[log]\nlevel = "info"`;
    const exit = common("exit") + side(!entryListens) + tok + extra(entryListens) + `\n[log]\nlevel = "info"`;
    return { entry, exit };
  }
  K.configs = configs;
  K.tomlHtml = tomlHtml;
  K.codeBlock = codeBlock;
  K.icon = icon;
  K.esc = esc;
  K.tf = tf;
  K.wellSvg = wellSvg;
  K.mmss = mmss;

  // ------------------------------------------------------------------ servers

  const srvView = { q: "" };

  K.pages.servers = {
    render(box) {
      K.setTitle(t("page.servers"), tf("srv.sub", { n: fmt(SERVERS.length) }));
      box.innerHTML = `
        <div class="page-band">
          <div class="summary">
            <div><b>${fmt(SERVERS.length)}</b><span>${t("srv.count")}</span></div>
            <div><b>${fmt(SERVERS.length)}</b><span>${t("srv.online")}</span></div>
            <div><b>${fmt(TUNNELS.length)}</b><span>${t("srv.tunnels")}</span></div>
            <div><b class="small" style="font-size:var(--fs-md);padding-top:6px">tehran-1</b><span>${t("srv.panel")}</span></div>
          </div>
          <div class="grow"></div>
          <label class="search">${icon("search")}<input type="search" id="srv-q" placeholder="${t("srv.search")}" value="${esc(srvView.q)}"></label>
          <button class="btn btn-primary btn-sm" id="srv-add"><span class="shine"></span>${icon("plus")}${t("srv.add")}</button>
        </div>
        <ul class="srv-list" id="srv-list"></ul>`;
      $("#srv-add", box).addEventListener("click", addServer);
      $("#srv-q", box).addEventListener("input", (e) => {
        srvView.q = e.target.value;
        this.list(box);
      });
      this.list(box);
    },
    list(box) {
      const q = srvView.q.trim().toLowerCase();
      const rows = SERVERS.filter((s) => !q || s.name.includes(q) || s.ip.includes(q) || s.loc[state.lang].toLowerCase().includes(q));
      $("#srv-list", box).innerHTML = rows
        .map((s) => {
          const n = TUNNELS.filter((x) => x.a === s.id || x.b === s.id).length;
          return `<li class="srv ${s.isNew ? "is-new" : ""}" data-s="${s.id}">
            ${wellSvg(s.st, s.cpu / 100 + 0.3)}
            <div><button class="srv-name link" data-open="${s.id}">${s.name}</button><div class="srv-sub">${s.loc[state.lang]} · ${t("role." + s.role)} · ${s.arch} · Kariz ${s.ver}</div></div>
            <div class="c-link"><div class="srv-ip">${s.ip}</div><div class="srv-link"><i class="dot ${s.st === "warn" ? "warn" : "up"}"></i><span class="js-seen">${s.panel ? t("srv.thisPanel") : `${tf("srv.via", { via: s.via })} · ${tf("srv.seen", { s: fmt(s.seen) })}`}</span></div></div>
            <div class="m-cpu">${meter(t("srv.cpu"), Math.round(s.cpu))}</div>
            <div class="m-ram">${meter(t("srv.ram"), Math.round(s.ram))}</div>
            <div class="m-net">${meter(t("srv.net"), Math.round(s.net))}</div>
            <span class="badge ${n ? "" : "muted"}">${tf("srv.tn", { n: fmt(n) })}</span>
          </li>`;
        })
        .join("");
      for (const b of $$("[data-open]", box)) b.addEventListener("click", () => serverDetails(byId(b.dataset.open)));
      for (const s of SERVERS) delete s.isNew;
    },
    tick() {
      const box = $('.page[data-page="servers"]');
      if (state.page !== "servers" || !box) return;
      for (const li of $$(".srv", box)) {
        const s = byId(li.dataset.s);
        const set = (sel, v) => {
          const m = $(sel, li);
          if (!m) return;
          $(".bar i", m).style.width = `${v}%`;
          $(".top b", m).textContent = `${fmt(Math.round(v))}%`;
          m.classList.toggle("hot", v > 85);
        };
        set(".m-cpu .meter", s.cpu);
        set(".m-ram .meter", s.ram);
        set(".m-net .meter", s.net);
        if (!s.panel) $(".js-seen", li).textContent = `${tf("srv.via", { via: s.via })} · ${tf("srv.seen", { s: fmt(s.seen) })}`;
      }
    },
  };
  K.ticks.push(() => K.pages.servers.tick());

  function serverDetails(s) {
    const n = TUNNELS.filter((x) => x.a === s.id || x.b === s.id);
    dialog(
      `${s.name}`,
      `<dl class="kv">
        <dt>IP</dt><dd class="mono" dir="ltr">${s.ip}</dd>
        <dt>${t("tip.role")}</dt><dd>${t("role." + s.role)} · ${s.loc[state.lang]}</dd>
        <dt>${t("srv.version")}</dt><dd>Kariz ${s.ver} <span class="badge water">${t("srv.upToDate")}</span></dd>
        <dt>${t("srv.arch")}</dt><dd>${s.arch}</dd>
        <dt>${t("srv.uptime")}</dt><dd>${dur(s.up)}</dd>
        <dt>${t("srv.link")}</dt><dd>${s.panel ? t("srv.thisPanel") : tf("srv.via", { via: s.via })}</dd>
        <dt>${t("nav.tunnels")}</dt><dd>${n.map((x) => `<span class="tag">${x.id}</span>`).join(" ") || "—"}</dd>
      </dl>
      <div class="grid-3">${meter(t("srv.cpu"), Math.round(s.cpu))}${meter(t("srv.ram"), Math.round(s.ram))}${meter(t("srv.net"), Math.round(s.net))}</div>`,
      `<button class="btn btn-danger btn-sm" ${n.length || s.panel ? "disabled" : ""} title="${n.length ? t("srv.removeNote") : ""}">${icon("trash")}${t("srv.remove")}</button>
       <div style="flex:1"></div>
       <button class="btn btn-ghost btn-sm" data-act2="agent">${icon("restart")}${t("srv.restartAgent")}</button>
       <button class="btn btn-ghost btn-sm" data-close>${t("close")}</button>`,
      (d, close) => {
        $('[data-act2="agent"]', d).addEventListener("click", () => {
          close();
          toast(`${s.name}: ${t("srv.restartAgent")} ✓`);
        });
      }
    );
  }

  // the join flow: a one-line command with a join code, then the server shows up
  function addServer() {
    let dir = "agent";
    let left = 600;
    const code = () => "kz1_" + Array.from({ length: 5 }, () => Math.random().toString(36).slice(2, 6)).join("");
    let join = code();
    const cmd = () =>
      dir === "agent"
        ? `bash <(curl -fsSL https://raw.githubusercontent.com/MAHDI-byte64/tun2/main/scripts/kariz.sh) \\\n    --agent ${join}`
        : `bash <(curl -fsSL https://raw.githubusercontent.com/MAHDI-byte64/tun2/main/scripts/kariz.sh) \\\n    --agent ${join} --agent-listen 3999`;
    dialog(
      t("add.title"),
      `<div class="field"><label for="add-name">${t("add.name")}</label><input class="text mono" id="add-name" placeholder="istanbul-1" dir="ltr"><span class="help">${t("add.nameHelp")}</span></div>
       <div class="field"><span class="label">${t("add.dir")}</span>
         <div class="seg" role="group"><button aria-pressed="true" data-dir="agent">${t("add.dirAgent")}</button><button aria-pressed="false" data-dir="panel">${t("add.dirPanel")}</button></div>
         <span class="help" id="add-dir-help">${t("add.dirAgentHelp")}</span></div>
       <div class="field"><span class="label">${t("add.run")}</span><div id="add-cmd"></div><span class="countdown" id="add-left"></span></div>
       <div class="waiting" id="add-wait"><svg class="qloader" viewBox="0 0 180 90" aria-hidden="true">${K.LOADER}</svg><span>${t("add.waiting")}</span></div>`,
      `<button class="btn btn-ghost btn-sm" id="add-new">${t("add.new")}</button><div style="flex:1"></div><button class="btn btn-ghost btn-sm" data-close>${t("cancel")}</button><button class="btn btn-primary btn-sm" id="add-done" disabled>${t("done")}</button>`,
      (d, close) => {
        const paint = () => {
          $("#add-cmd", d).innerHTML = codeBlock(esc(cmd()), cmd().replace("\\\n    ", ""));
          $("#add-left", d).textContent = tf("add.valid", { m: K.localDigits(mmss(left)) });
        };
        paint();
        for (const b of $$("[data-dir]", d))
          b.addEventListener("click", () => {
            dir = b.dataset.dir;
            for (const x of $$("[data-dir]", d)) x.setAttribute("aria-pressed", String(x === b));
            $("#add-dir-help", d).textContent = t(dir === "agent" ? "add.dirAgentHelp" : "add.dirPanelHelp");
            paint();
          });
        $("#add-new", d).addEventListener("click", () => {
          join = code();
          left = 600;
          paint();
        });
        d._timer = setInterval(() => {
          left = Math.max(0, left - 1);
          $("#add-left", d).textContent = tf("add.valid", { m: K.localDigits(mmss(left)) });
        }, 1000);
        // in the prototype the server "connects" after a few seconds
        d._wait = setTimeout(() => {
          const name = ($("#add-name", d).value.trim() || "istanbul-1").replace(/[^\w-]/g, "");
          const w = $("#add-wait", d);
          w.classList.add("done");
          w.innerHTML = `${wellSvg("up", 0.9)}<span><b>${tf("add.connected", { name })}</b><br><span class="mono xs muted" dir="ltr">198.51.100.90 · aarch64 · Kariz 0.6.1</span></span>`;
          const done = $("#add-done", d);
          done.disabled = false;
          done.onclick = () => {
            if (!SERVERS.some((s) => s.id === name)) {
              SERVERS.push({ id: name, name, loc: { fa: "استانبول", en: "Istanbul" }, ip: "198.51.100.90", role: "exit", st: "up", cpu: 3, ram: 14, ver: "0.6.1", arch: "aarch64", up: 60, via: dir === "agent" ? "tcpmux" : "direct", net: 1, seen: 1, isNew: true });
            }
            close();
            K.setPage("servers", true);
            toast(tf("add.connected", { name }));
          };
        }, 5200);
      }
    );
  }
  K.addServer = addServer;

  // ------------------------------------------------------------------ tunnels

  const tnView = { f: "all", q: "" };

  K.pages.tunnels = {
    render(box) {
      const c = (st) => TUNNELS.filter((x) => x.st === st).length;
      K.setTitle(t("page.tunnels"), tf("tn.sub", { up: fmt(c("up")), down: fmt(c("down")), off: fmt(c("off")) }));
      box.innerHTML = `
        <div class="page-band">
          <div class="seg" role="group" id="tn-f">${["all", "up", "down", "off"].map((f) => `<button data-f="${f}" aria-pressed="${tnView.f === f}">${f === "all" ? t("tn.all") : K.stateLabel(f)} <span class="muted">${fmt(f === "all" ? TUNNELS.length : c(f))}</span></button>`).join("")}</div>
          <label class="search">${icon("search")}<input type="search" id="tn-q" placeholder="${t("tn.search")}" value="${esc(tnView.q)}"></label>
          <div class="grow"></div>
          <button class="btn btn-primary btn-sm" id="tn-new"><span class="shine"></span>${icon("plus")}${t("tn.new")}</button>
        </div>
        <div class="stratum s1" style="padding-top:var(--sp-3)">
          <table class="tunnels"><thead><tr>
            <th>${t("t.name")}</th><th>${t("t.route")}</th><th>${t("t.transport")}</th><th>${t("tn.mode")}</th><th>${t("tn.ports")}</th><th>${t("t.state")}</th><th>${t("t.rate")}</th><th><span class="sr-only">${t("t.onoff")}</span></th>
          </tr></thead><tbody id="tn-body"></tbody></table>
        </div>`;
      for (const b of $$("[data-f]", box))
        b.addEventListener("click", () => {
          tnView.f = b.dataset.f;
          this.render(box);
        });
      $("#tn-q", box).addEventListener("input", (e) => {
        tnView.q = e.target.value;
        this.body(box);
      });
      $("#tn-new", box).addEventListener("click", () => K.wizard.open());
      this.body(box);
    },
    body(box) {
      const q = tnView.q.trim().toLowerCase();
      const rows = TUNNELS.filter((tn) => (tnView.f === "all" || tn.st === tnView.f) && (!q || [tn.id, byId(tn.a).name, byId(tn.b).name, tn.tr, ...tn.fwd.map((f) => f[0])].join(" ").toLowerCase().includes(q)));
      const body = $("#tn-body", box);
      if (!rows.length) {
        body.innerHTML = `<tr><td colspan="8" class="muted" style="text-align:center;padding:var(--sp-7)">${t("tn.empty")}</td></tr>`;
        return;
      }
      body.innerHTML = rows
        .map(
          (tn) => `<tr data-t="${tn.id}">
            <td><button class="t-name link" data-go="${tn.id}">${tn.id}</button></td>
            <td><span class="t-route"><span>${byId(tn.a).name}</span>${icon("arrow")}<span>${byId(tn.b).name}</span></span></td>
            <td class="c-transport"><span class="tag">${tn.tr}</span> <span class="tag">${tn.prof}</span></td>
            <td class="c-transport">${t("mode." + tn.mode)}</td>
            <td class="c-transport num">${fmt(tn.ports)}</td>
            <td><span class="state ${tn.st}"><i class="dot ${tn.st}"></i>${K.stateLabel(tn.st)}</span></td>
            <td class="rate num"></td>
            <td><button class="switch" role="switch" aria-checked="${tn.st !== "off"}" aria-label="${tn.id}"></button></td>
          </tr>`
        )
        .join("");
      for (const b of $$("[data-go]", body)) b.addEventListener("click", () => K.setPage("tunnel", false, b.dataset.go));
      for (const sw of $$(".switch", body))
        sw.addEventListener("click", () => {
          const tn = TUNNELS.find((x) => x.id === sw.getAttribute("aria-label"));
          setRunning(tn, tn.st === "off");
          this.render(box);
        });
      this.rates(box);
    },
    rates(box) {
      for (const row of $$("#tn-body tr[data-t]", box)) {
        const tn = TUNNELS.find((x) => x.id === row.dataset.t);
        if (!tn) continue;
        const r = fmtRate(tn.down + tn.up);
        $(".rate", row).textContent = tn.st === "up" ? `${r.v} ${r.u}` : "—";
      }
    },
  };
  K.ticks.push(() => {
    const box = $('.page[data-page="tunnels"]');
    if (state.page === "tunnels" && box) K.pages.tunnels.rates(box);
  });

  function setRunning(tn, on) {
    if (on) tn.st = tn.broken ? "down" : "up";
    else {
      tn.broken = tn.st === "down";
      tn.st = "off";
    }
    (tn.events ||= []).unshift({ at: Date.now(), k: on ? "ev.start" : "ev.stop", cls: on ? "" : "info" });
    K.tick();
    K.renderRows();
  }
  K.setRunning = setRunning;
  // backup starts out broken
  const backup = TUNNELS.find((x) => x.id === "backup");
  if (backup) backup.broken = true;

  // ------------------------------------------------------------------ tunnel detail

  const detail = { id: null, range: "5m", tab: "entry", raf: 0, speed: null };

  function events(tn) {
    if (tn.events) return tn.events;
    const now = Date.now();
    const m = 60000;
    tn.events =
      tn.st === "down"
        ? [
            { at: now - 0.2 * m, k: "ev.retry", cls: "bad" },
            { at: now - 3 * m, k: "ev.hsFail", cls: "bad" },
            { at: now - 3.1 * m, k: "ev.start", cls: "" },
          ]
        : tn.st === "off"
        ? [{ at: now - 2 * 86400000, k: "ev.stop", cls: "info" }, { at: now - 9 * 86400000, k: "ev.start", cls: "" }]
        : [
            { at: now - 42 * m, k: "ev.speed", cls: "info" },
            { at: now - 26 * 3600000, k: "ev.edit", cls: "info" },
            { at: now - tn.uptime * 1000 + 2000, k: "ev.session", cls: "" },
            { at: now - tn.uptime * 1000, k: "ev.start", cls: "" },
          ];
    return tn.events;
  }

  K.pages.tunnel = {
    render(box, id) {
      const tn = TUNNELS.find((x) => x.id === id);
      if (!tn) return K.setPage("tunnels", true);
      detail.id = id;
      const a = byId(tn.a), b = byId(tn.b);
      K.setTitle(tn.id, `${a.name} → ${b.name}`, () => K.setPage("tunnels"));
      const cf = configs(tn);
      box.innerHTML = `
        <div class="hero-route">
          <div class="head">
            ${stateBadge(tn.st)}<span class="tag">${tn.tr}</span><span class="tag">${tn.prof}</span><span class="tag">${tn.mode}</span>
            <div class="grow"></div>
            <div class="row-actions">
              <button class="btn btn-ghost btn-sm" data-do="speed" ${tn.st === "up" ? "" : "disabled"}>${icon("bolt")}${t("d.speed")}</button>
              <button class="btn btn-ghost btn-sm" data-do="restart" ${tn.st === "off" ? "disabled" : ""}>${icon("restart")}${t("d.restart")}</button>
              <button class="btn btn-ghost btn-sm" data-do="toggle">${icon(tn.st === "off" ? "play" : "pause")}${t(tn.st === "off" ? "d.start" : "d.stop")}</button>
              <button class="btn btn-ghost btn-sm" data-do="edit">${icon("edit")}${t("d.edit")}</button>
              <button class="btn btn-danger btn-sm" data-do="delete">${icon("trash")}${t("d.delete")}</button>
            </div>
          </div>
          <canvas id="d-route" aria-hidden="true"></canvas>
        </div>
        ${
          tn.st === "down"
            ? `<div class="diagnosis" role="alert"><div class="diag-icon">!</div><div><h3>${t("d.diagTitle")}</h3><p>${t("d.diagText")}</p><ol><li>${t("d.diag1")}</li><li>${t("d.diag2")}</li></ol></div><button class="btn btn-primary btn-sm" data-do="fix"><span class="shine"></span>${icon("key")}${t("d.fix")}</button></div>`
            : ""
        }
        <div class="stratum s1"><div class="facts" id="d-facts"></div></div>
        <div class="stratum s2">
          <div class="stratum-head"><h2>${t("d.traffic")}</h2><div class="legend"><span><i style="background:var(--water)"></i>${t("d.down")}</span><span><i style="background:var(--accent)"></i>${t("d.up")}</span></div><div style="flex:1"></div>
            <div class="seg" role="group">${["5m", "1h", "24h"].map((r) => `<button data-range="${r}" aria-pressed="${detail.range === r}">${t("range." + r)}</button>`).join("")}</div></div>
          <div class="chart-wrap"><canvas class="chart" id="d-chart"></canvas><div class="chart-tip" id="d-tip"></div></div>
        </div>
        <div class="stratum s1"><div class="grid-2">
          <div><div class="stratum-head"><h2>${t("d.fwd")}</h2></div>
            <table class="plain-table"><thead><tr><th>${t("d.listen")}</th><th>${t("d.target")}</th><th>${t("d.proto")}</th></tr></thead>
            <tbody>${tn.fwd.map((f) => `<tr><td class="mono">:${f[0]}</td><td class="mono">${f[1]}</td><td><span class="tag">${f[2]}</span></td></tr>`).join("")}</tbody></table></div>
          <div><div class="stratum-head"><h2>${t("d.speed")}</h2></div><div id="d-speed"></div></div>
        </div></div>
        <div class="stratum s2"><div class="grid-2">
          <div><div class="stratum-head"><h2>${t("d.config")}</h2></div>
            <div class="tabs" role="tablist">${["entry", "exit"].map((s) => `<button role="tab" data-tab="${s}" aria-selected="${detail.tab === s}">${t(s === "entry" ? "d.entrySide" : "d.exitSide")} · ${s === "entry" ? a.name : b.name}</button>`).join("")}</div>
            <div id="d-conf">${codeBlock(tomlHtml(cf[detail.tab]), cf[detail.tab])}</div></div>
          <div><div class="stratum-head"><h2>${t("d.events")}</h2></div><ul class="timeline">${events(tn).map((e) => `<li class="${e.cls}"><span>${t(e.k)}</span><time>${ago(Math.max(1, Math.round((Date.now() - e.at) / 1000)))}</time></li>`).join("")}</ul></div>
        </div></div>`;

      for (const btn of $$("[data-range]", box))
        btn.addEventListener("click", () => {
          detail.range = btn.dataset.range;
          for (const x of $$("[data-range]", box)) x.setAttribute("aria-pressed", String(x === btn));
          drawChart();
        });
      for (const btn of $$("[data-tab]", box))
        btn.addEventListener("click", () => {
          detail.tab = btn.dataset.tab;
          for (const x of $$("[data-tab]", box)) x.setAttribute("aria-selected", String(x === btn));
          $("#d-conf", box).innerHTML = codeBlock(tomlHtml(cf[detail.tab]), cf[detail.tab]);
        });
      for (const btn of $$("[data-do]", box)) btn.addEventListener("click", () => act(tn, btn.dataset.do));
      const chart = $("#d-chart", box);
      chart.addEventListener("pointermove", (e) => {
        const r = chart.getBoundingClientRect();
        detail.hx = e.clientX - r.left;
        drawChart();
      });
      chart.addEventListener("pointerleave", () => {
        detail.hx = null;
        drawChart();
      });
      facts();
      speedPanel();
      drawChart();
      cancelAnimationFrame(detail.raf);
      detail.parts = [];
      const loop = (now) => {
        if (state.page !== "tunnel" || detail.id !== id || !box.isConnected) return;
        drawRoute(tn, now);
        detail.raf = requestAnimationFrame(loop);
      };
      detail.raf = requestAnimationFrame(loop);
    },
  };

  K.ticks.push(() => {
    if (state.page !== "tunnel") return;
    facts();
    drawChart();
  });

  function facts() {
    const tn = TUNNELS.find((x) => x.id === detail.id);
    const el = $("#d-facts");
    if (!tn || !el) return;
    const up = tn.st === "up";
    const f = (label, value, unit = "") => `<div class="fact"><div class="label">${label}</div><div class="value">${value}${unit ? `<small>${unit}</small>` : ""}</div></div>`;
    el.innerHTML =
      f(t("d.lat"), up ? fmt(tn.lat + Math.round(Math.random() * 4)) : "—", up ? "ms" : "") +
      f(t("d.conns"), up ? fmt(tn.open) : "—") +
      f(t("d.sessions"), up ? `${fmt(2)}` : fmt(0), up ? `${t("m.of")} ${fmt(2)}` : "") +
      f(t("d.hsErr"), tn.st === "down" ? `<span style="color:var(--danger)">${fmt(37)}</span>` : fmt(0)) +
      f(t("d.uptime"), up ? `<span style="font-size:var(--fs-lg)">${dur(tn.uptime)}</span>` : "—");
  }

  // traffic chart: two lines, grid, hover read-out
  function drawChart() {
    const tn = TUNNELS.find((x) => x.id === detail.id);
    const cv = $("#d-chart");
    if (!tn || !cv || !cv.getBoundingClientRect().width) return;
    const P = K.P;
    const { ctx, W, H } = fitCanvas(cv);
    const rtl = document.documentElement.dir === "rtl";
    ctx.clearRect(0, 0, W, H);
    let down = tn.h.down, up = tn.h.up;
    if (detail.range !== "5m") {
      // longer ranges are made up in the prototype: a smooth daily shape
      const n = 300, k = detail.range === "1h" ? 1 : 24;
      const f = (i) => tn.base * (0.55 + 0.35 * Math.sin((i / n) * Math.PI * 2 * (k === 24 ? 1 : 0.2) + tn.level) + 0.1 * Math.sin(i * 1.7 + tn.level));
      down = Array.from({ length: n }, (_, i) => (tn.st === "up" ? Math.max(0, f(i)) : i < n * 0.6 && tn.st === "off" ? Math.max(0, f(i)) : 0));
      up = down.map((v) => v * 0.18);
    }
    const padL = 52, padR = 12, padT = 12, padB = 26;
    const max = Math.max(10, ...down) * 1.15;
    const X = (i) => {
      const x = padL + (i / (down.length - 1)) * (W - padL - padR);
      return rtl ? W - x : x;
    };
    const Y = (v) => padT + (1 - v / max) * (H - padT - padB);
    // grid
    ctx.font = uiFont(400, 11);
    ctx.fillStyle = P.text3;
    ctx.strokeStyle = rgba(P.gold, 0.1);
    ctx.lineWidth = 1;
    ctx.textBaseline = "middle";
    for (let i = 0; i <= 4; i++) {
      const v = (max / 4) * i;
      const y = Y(v);
      ctx.beginPath();
      ctx.moveTo(rtl ? 0 : padL, y);
      ctx.lineTo(rtl ? W - padL : W - padR, y);
      ctx.stroke();
      const r = fmtRate(v);
      ctx.textAlign = rtl ? "left" : "right";
      ctx.fillText(`${r.v}`, rtl ? W - padL + 8 : padL - 8, y);
    }
    ctx.textAlign = "center";
    const fa = state.lang === "fa";
    const back = detail.range === "5m" ? [5, 4, 3, 2, 1] : detail.range === "1h" ? [60, 45, 30, 15] : [24, 18, 12, 6];
    const unit = detail.range === "24h" ? (fa ? " ساعت" : "h") : fa ? " دقیقه" : "m";
    const labels = [...back.map((n) => (fa ? `${fmt(n)}${unit}` : `-${n}${unit}`)), t("t.rate")];
    labels.forEach((l, i) => ctx.fillText(l, X((i / (labels.length - 1)) * (down.length - 1)), H - 10));
    // series
    const line = (arr, col, fill) => {
      ctx.beginPath();
      arr.forEach((v, i) => (i ? ctx.lineTo(X(i), Y(v)) : ctx.moveTo(X(i), Y(v))));
      if (fill) {
        ctx.lineTo(X(arr.length - 1), Y(0));
        ctx.lineTo(X(0), Y(0));
        const g = ctx.createLinearGradient(0, padT, 0, H - padB);
        g.addColorStop(0, rgba(col, 0.28));
        g.addColorStop(1, rgba(col, 0));
        ctx.fillStyle = g;
        ctx.fill();
        ctx.beginPath();
        arr.forEach((v, i) => (i ? ctx.lineTo(X(i), Y(v)) : ctx.moveTo(X(i), Y(v))));
      }
      ctx.strokeStyle = col;
      ctx.lineWidth = 1.8;
      ctx.stroke();
    };
    line(down, P.water, true);
    line(up, P.accent, false);
    // hover
    const tip = $("#d-tip");
    if (detail.hx != null) {
      const frac = clamp(((rtl ? W - detail.hx : detail.hx) - padL) / (W - padL - padR), 0, 1);
      const i = Math.round(frac * (down.length - 1));
      const x = X(i);
      ctx.strokeStyle = rgba(P.text3, 0.6);
      ctx.setLineDash([3, 4]);
      ctx.beginPath();
      ctx.moveTo(x, padT);
      ctx.lineTo(x, H - padB);
      ctx.stroke();
      ctx.setLineDash([]);
      for (const [arr, col] of [[down, P.water], [up, P.accent]]) {
        ctx.fillStyle = col;
        ctx.beginPath();
        ctx.arc(x, Y(arr[i]), 4, 0, 6.28);
        ctx.fill();
      }
      const d = fmtRate(down[i]), u = fmtRate(up[i]);
      tip.innerHTML = `↓ <b>${d.v}</b> ${d.u} &nbsp; ↑ <b>${u.v}</b> ${u.u}`;
      tip.style.left = `${clamp(x + 12, 0, W - tip.offsetWidth)}px`;
      tip.classList.add("is-on");
    } else tip?.classList.remove("is-on");
  }

  // the tunnel as one channel between two wells
  function drawRoute(tn, now) {
    const cv = $("#d-route");
    if (!cv) return;
    const P = K.P;
    const { ctx, W, H } = fitCanvas(cv);
    const rtl = document.documentElement.dir === "rtl";
    const time = now / 1000;
    const a = byId(tn.a), b = byId(tn.b);
    const yH = 58, x0 = rtl ? W - 90 : 90, x1 = rtl ? 90 : W - 90;
    const y0 = 118, y1 = 124;
    ctx.clearRect(0, 0, W, H);
    // earth
    const g = ctx.createLinearGradient(0, yH, 0, H);
    g.addColorStop(0, P.earth);
    g.addColorStop(1, P.bg);
    ctx.fillStyle = g;
    ctx.fillRect(0, yH, W, H - yH);
    // shafts
    ctx.strokeStyle = rgba(P.gold, 0.5);
    ctx.lineWidth = 4;
    ctx.lineCap = "round";
    for (const [x, y] of [[x0, y0], [x1, y1]]) {
      ctx.beginPath();
      ctx.moveTo(x, yH);
      ctx.lineTo(x, y);
      ctx.stroke();
    }
    // channel
    const pt = (k) => ({ x: x0 + (x1 - x0) * k, y: y0 + (y1 - y0) * k + Math.sin(k * Math.PI) * 10 });
    const stroke = (from, to, w, col) => {
      ctx.strokeStyle = col;
      ctx.lineWidth = w;
      ctx.beginPath();
      for (let i = 0; i <= 50; i++) {
        const k = from + ((to - from) * i) / 50;
        const p = pt(k);
        i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y);
      }
      ctx.stroke();
    };
    stroke(0, 1, 18, P.night ? "#06121f" : "#cdb489");
    const reach = tn.st === "down" ? 0.55 : tn.st === "off" ? 0 : 1;
    if (reach > 0) {
      const wg = ctx.createLinearGradient(x0, 0, x1, 0);
      wg.addColorStop(0, P.waterDeep);
      wg.addColorStop(1, P.waterBright);
      stroke(0, reach, 10, wg);
    }
    if (tn.st !== "up") {
      ctx.save();
      ctx.setLineDash([4, 6]);
      stroke(reach, 1, 1.2, tn.st === "down" ? rgba(P.danger, 0.6) : rgba(P.text3, 0.6));
      ctx.restore();
    }
    if (tn.st === "down") {
      const p = pt(reach);
      const k = K.state.low ? 0.5 : (time * 0.8) % 1;
      ctx.strokeStyle = rgba(P.danger, 1 - k);
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(p.x, p.y, 6 + k * 18, 0, 6.28);
      ctx.stroke();
      ctx.fillStyle = P.danger;
      ctx.beginPath();
      ctx.arc(p.x, p.y, 5, 0, 6.28);
      ctx.fill();
    }
    // particles: downloads flow back to the entry
    if (tn.st === "up" && !K.state.low) {
      const rate = tn.down + tn.up;
      const want = Math.round(clamp(10 + rate / 6, 10, 90));
      while (detail.parts.length < want) detail.parts.push({ k: Math.random(), dir: Math.random() < 0.8 ? -1 : 1, s: 0.5 + Math.random() * 0.7, j: Math.random() * 6 });
      detail.parts.length = want;
      const v = clamp(0.12 + rate / 2500, 0.12, 0.5);
      ctx.globalCompositeOperation = P.night ? "lighter" : "source-over";
      for (const q of detail.parts) {
        q.k = (q.k + q.dir * v * 0.016 + 1) % 1;
        const p = pt(q.k);
        const r = (q.dir < 0 ? 8 : 6) * q.s;
        ctx.globalAlpha = q.dir < 0 ? 1 : 0.55;
        ctx.fillStyle = P.waterBright;
        ctx.beginPath();
        ctx.arc(p.x, p.y + Math.sin(time * 3 + q.j) * 2, r / 3, 0, 6.28);
        ctx.fill();
      }
      ctx.globalAlpha = 1;
      ctx.globalCompositeOperation = "source-over";
    }
    // horizon and mounds
    ctx.strokeStyle = P.gold;
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(0, yH);
    ctx.lineTo(W, yH);
    ctx.stroke();
    ctx.fillStyle = P.gold;
    for (const x of [x0, x1]) {
      ctx.beginPath();
      ctx.ellipse(x, yH, 18, 12, 0, Math.PI, 0);
      ctx.fill();
    }
    // labels
    ctx.textAlign = "center";
    ctx.direction = document.documentElement.dir;
    const lbl = (x, s, role, note) => {
      ctx.font = uiFont(600, 14);
      ctx.fillStyle = P.text;
      ctx.fillText(s.name, x, yH - 30);
      ctx.font = uiFont(400, 11);
      ctx.fillStyle = P.text3;
      ctx.fillText(`${t("role." + role)} · ⁦${s.ip}⁩`, x, yH - 14); // the IP stays left-to-right
      ctx.fillText(note, x, y1 + 26);
    };
    lbl(x0, a, "entry", t("d.users"));
    lbl(x1, b, "exit", t("d.targets"));
    if (tn.st === "up") {
      const r = fmtRate(tn.down + tn.up);
      const p = pt(0.5);
      ctx.font = uiFont(600, 13);
      ctx.fillStyle = P.text;
      ctx.fillText(`${r.v} ${r.u}`, p.x, p.y - 20);
    }
  }

  function speedPanel() {
    const el = $("#d-speed");
    const tn = TUNNELS.find((x) => x.id === detail.id);
    if (!el || !tn) return;
    const sp = detail.speed && detail.speed.id === tn.id ? detail.speed : null;
    const level = sp ? sp.level : 0;
    const y = 104 - 88 * level;
    el.innerHTML = `<div class="gauge">
      <svg viewBox="0 0 120 120" aria-hidden="true">
        <rect x="34" y="16" width="52" height="92" rx="6" fill="var(--stratum-3)"/>
        <rect class="well-water" x="34" y="${y}" width="52" height="${108 - y}" rx="6"/>
        <rect class="well-surface" x="34" y="${y}" width="52" height="3"/>
        <rect class="well-wall" x="34" y="16" width="52" height="92" rx="6"/>
        <path d="M22 16h76" stroke="var(--accent)" stroke-width="3" stroke-linecap="round"/>
      </svg>
      <div class="gauge-read">
        ${
          sp
            ? `<div class="muted small">${sp.phase === "done" ? t("d.speed") : t(sp.phase === "down" ? "d.speedDown" : "d.speedUp")}</div>
               <div class="big">↓ ${fmt(sp.down)} <span class="small muted">Mbps</span></div>
               <div class="big" style="font-size:var(--fs-xl)">↑ ${fmt(sp.up)} <span class="small muted">Mbps</span></div>
               ${sp.phase === "done" ? `<div class="small muted">${t("d.lat")}: ${fmt(39)} ms · UDP ${fmt(0)}% loss</div>` : ""}`
            : `<p class="small muted" style="margin:0">${tn.st === "up" ? t("d.speedIdle") : t("d.speedOff")}</p>`
        }
        <div><button class="btn btn-primary btn-sm" id="d-speed-run" ${tn.st !== "up" || (sp && sp.phase !== "done") ? "disabled" : ""}><span class="shine"></span>${icon("bolt")}${t("d.speedRun")}</button></div>
      </div></div>`;
    $("#d-speed-run", el).addEventListener("click", () => runSpeed(tn));
  }

  function runSpeed(tn) {
    const sp = (detail.speed = { id: tn.id, phase: "down", down: 0, up: 0, level: 0 });
    const base = tn.base;
    tn.base = 900; // the channel runs full while the test is on
    let i = 0;
    const iv = setInterval(() => {
      i++;
      if (i <= 20) {
        sp.down = Math.round(842 * (1 - Math.exp(-i / 5)) + Math.random() * 20);
        sp.level = clamp(sp.down / 1000, 0, 1);
      } else if (i <= 36) {
        sp.phase = "up";
        sp.up = Math.round(196 * (1 - Math.exp(-(i - 20) / 4)) + Math.random() * 8);
        sp.level = clamp(sp.down / 1000, 0, 1);
      } else {
        sp.phase = "done";
        sp.down = 842;
        sp.up = 196;
        clearInterval(iv);
        tn.base = base;
        (tn.events ||= []).unshift({ at: Date.now(), k: "ev.speed", cls: "info" });
      }
      if (state.page === "tunnel" && detail.id === tn.id) speedPanel();
    }, 200);
    speedPanel();
  }

  function act(tn, what) {
    if (what === "speed") {
      $("#d-speed")?.scrollIntoView({ behavior: "smooth", block: "center" });
      runSpeed(tn);
    } else if (what === "restart") {
      const line = $("#loader-line");
      line.classList.add("is-on");
      tn.fill = 0;
      setTimeout(() => {
        line.classList.remove("is-on");
        toast(tf("d.restarted", { name: tn.id }));
      }, 1600);
    } else if (what === "toggle") {
      setRunning(tn, tn.st === "off");
      K.setPage("tunnel", true, tn.id);
    } else if (what === "edit") {
      K.wizard.open({ edit: tn });
    } else if (what === "delete") {
      dialog(
        tf("d.delTitle", { name: tn.id }),
        `<p style="margin:0" class="small">${t("d.delText")}</p><input class="text mono" id="del-name" dir="ltr" autocomplete="off" placeholder="${tn.id}">`,
        `<button class="btn btn-ghost btn-sm" data-close>${t("cancel")}</button><button class="btn btn-danger solid btn-sm" id="del-go" disabled>${icon("trash")}${t("d.delete")}</button>`,
        (d, close) => {
          const inp = $("#del-name", d), go = $("#del-go", d);
          inp.addEventListener("input", () => (go.disabled = inp.value.trim() !== tn.id));
          go.addEventListener("click", () => {
            TUNNELS.splice(TUNNELS.indexOf(tn), 1);
            TUNNELS.forEach((x, i) => (x.level = i));
            close();
            K.renderRows();
            K.setPage("tunnels");
            toast(tf("d.deleted", { name: tn.id }));
          });
        }
      );
    } else if (what === "fix") {
      toast(t("d.fixing"));
      const line = $("#loader-line");
      line.classList.add("is-on");
      setTimeout(() => {
        line.classList.remove("is-on");
        tn.st = "up";
        tn.broken = false;
        tn.base = 64;
        tn.conns = 90;
        tn.lat = 71;
        tn.uptime = 1;
        (tn.events ||= []).unshift({ at: Date.now(), k: "ev.session", cls: "" });
        K.tick();
        K.renderRows();
        K.setPage("tunnel", true, tn.id);
        toast(t("d.fixed"));
      }, 2600);
    }
  }

  // ------------------------------------------------------------------ logs

  const LOG = { lines: [], paused: false, tunnel: "all", level: "all", q: "", unseen: 0, seq: 0 };
  const MSG = {
    INFO: [
      (tn) => `mux session from the exit side established peer=${byId(tn.b).ip}:${40000 + Math.floor(Math.random() * 20000)}`,
      (tn) => `stream opened listen=[::]:${tn.fwd[0]?.[0] ?? 443} client=5.${Math.floor(Math.random() * 200)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}:${50000 + Math.floor(Math.random() * 15000)}`,
      (tn) => `mux ping rtt=${tn.lat + Math.floor(Math.random() * 6)}ms`,
      () => `udp flow opened client=${Math.floor(Math.random() * 200)}.18.4.${Math.floor(Math.random() * 250)}:${27000 + Math.floor(Math.random() * 100)}`,
      () => `stream closed bytes_up=${Math.floor(Math.random() * 90000)} bytes_down=${Math.floor(Math.random() * 9000000)}`,
    ],
    WARN: [
      (tn) => `could not connect to target target=${tn.fwd[0]?.[1] ?? "127.0.0.1:443"} error=connection refused`,
      () => `tunnel handshake failed peer=198.51.100.23:61722 error=authentication failed`,
    ],
    ERROR: [() => `entry side rejected us or failed authentication error=handshake rejected`],
  };
  function logLine(tn, lv, msg) {
    const d = new Date();
    return { id: ++LOG.seq, time: d.toTimeString().slice(0, 8) + "." + String(d.getMilliseconds()).padStart(3, "0"), lv, who: tn.id, side: lv === "ERROR" ? byId(tn.b).name : byId(tn.a).name, msg };
  }
  function genLog() {
    const live = TUNNELS.filter((x) => x.st !== "off");
    if (!live.length) return null;
    const tn = live[Math.floor(Math.random() * live.length)];
    if (tn.st === "down") return logLine(tn, Math.random() < 0.5 ? "ERROR" : "WARN", Math.random() < 0.5 ? MSG.ERROR[0](tn) : "could not connect to the entry side error=handshake rejected, retrying in 5s");
    const r = Math.random();
    const lv = r < 0.9 ? "INFO" : "WARN";
    const pool = MSG[lv];
    return logLine(tn, lv, pool[Math.floor(Math.random() * pool.length)](tn));
  }
  for (let i = 0; i < 70; i++) {
    const l = genLog();
    if (l) LOG.lines.push(l);
  }

  function matches(l) {
    return (LOG.tunnel === "all" || l.who === LOG.tunnel) && (LOG.level === "all" || l.lv === LOG.level) && (!LOG.q || `${l.msg} ${l.who}`.toLowerCase().includes(LOG.q.toLowerCase()));
  }
  function lineHtml(l, fresh) {
    let msg = esc(l.msg);
    if (LOG.q) msg = msg.replace(new RegExp(LOG.q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), (m) => `<mark>${m}</mark>`);
    return `<div class="log-line ${fresh ? "is-new" : ""}"><time>${l.time}</time><span class="lv ${l.lv}">${l.lv}</span><span class="who">${l.who}@${l.side}</span><span>${msg}</span></div>`;
  }

  K.pages.logs = {
    render(box) {
      K.setTitle(t("page.logs"), t("log.sub"));
      box.innerHTML = `
        <div class="page-band log-bar">
          <select class="select" id="log-t" style="width:auto;min-width:170px"><option value="all">${t("log.all")}</option>${TUNNELS.map((x) => `<option value="${x.id}" ${LOG.tunnel === x.id ? "selected" : ""}>${x.id}</option>`).join("")}</select>
          <div class="seg" role="group">${["all", "INFO", "WARN", "ERROR"].map((l) => `<button data-lv="${l}" aria-pressed="${LOG.level === l}">${l === "all" ? t("tn.all") : l}</button>`).join("")}</div>
          <label class="search">${icon("search")}<input type="search" id="log-q" placeholder="${t("log.search")}" value="${esc(LOG.q)}" dir="ltr"></label>
          <div class="grow"></div>
          <button class="btn btn-ghost btn-sm" id="log-pause">${icon(LOG.paused ? "play" : "pause")}${t(LOG.paused ? "log.resume" : "log.pause")}</button>
          <button class="btn btn-ghost btn-sm" id="log-clear">${t("log.clear")}</button>
        </div>
        <div style="position:relative"><div class="log-view" id="log-view" role="log" aria-live="off"></div>
        <button class="btn btn-primary btn-sm jump" id="log-jump" hidden></button></div>`;
      $("#log-t", box).value = LOG.tunnel;
      $("#log-t", box).addEventListener("change", (e) => {
        LOG.tunnel = e.target.value;
        this.fill(box);
      });
      for (const b of $$("[data-lv]", box))
        b.addEventListener("click", () => {
          LOG.level = b.dataset.lv;
          for (const x of $$("[data-lv]", box)) x.setAttribute("aria-pressed", String(x === b));
          this.fill(box);
        });
      $("#log-q", box).addEventListener("input", (e) => {
        LOG.q = e.target.value;
        this.fill(box);
      });
      $("#log-pause", box).addEventListener("click", () => {
        LOG.paused = !LOG.paused;
        this.render(box);
      });
      $("#log-clear", box).addEventListener("click", () => {
        LOG.lines = [];
        this.fill(box);
      });
      const view = $("#log-view", box);
      view.addEventListener("scroll", () => {
        if (atBottom(view)) {
          LOG.unseen = 0;
          $("#log-jump", box).hidden = true;
        }
      });
      $("#log-jump", box).addEventListener("click", () => {
        view.scrollTop = view.scrollHeight;
      });
      this.fill(box);
    },
    fill(box) {
      const view = $("#log-view", box);
      const rows = LOG.lines.filter(matches);
      view.innerHTML = rows.length ? rows.map((l) => lineHtml(l)).join("") : `<div class="log-empty">${t("log.none")}</div>`;
      view.scrollTop = view.scrollHeight;
      LOG.unseen = 0;
      $("#log-jump", box).hidden = true;
    },
    push(l) {
      const box = $('.page[data-page="logs"]');
      if (state.page !== "logs" || !box || !matches(l)) return;
      const view = $("#log-view", box);
      const stick = atBottom(view);
      $(".log-empty", view)?.remove();
      view.insertAdjacentHTML("beforeend", lineHtml(l, true));
      while (view.children.length > 400) view.firstElementChild.remove();
      if (stick) view.scrollTop = view.scrollHeight;
      else {
        LOG.unseen++;
        const j = $("#log-jump", box);
        j.hidden = false;
        j.textContent = tf("log.jump", { n: fmt(LOG.unseen) });
      }
    },
  };
  const atBottom = (v) => v.scrollHeight - v.scrollTop - v.clientHeight < 24;

  K.ticks.push(() => {
    if (LOG.paused) return;
    const n = Math.random() < 0.35 ? 2 : Math.random() < 0.7 ? 1 : 0;
    for (let i = 0; i < n; i++) {
      const l = genLog();
      if (!l) continue;
      LOG.lines.push(l);
      if (LOG.lines.length > 2000) LOG.lines.shift();
      K.pages.logs.push(l);
    }
  });

  // ------------------------------------------------------------------ settings

  const SET = {
    twofa: false,
    tls: "self",
    path: "k-7f3a9c",
    port: 28443,
    lock: "5",
    sessions: [
      { id: 1, who: "Chrome · Windows", ip: "5.119.38.201", seen: 0, me: true },
      { id: 2, who: "Safari · iPhone", ip: "5.119.40.17", seen: 3 * 3600 },
      { id: 3, who: "Firefox · Linux", ip: "89.36.12.4", seen: 4 * 86400 },
    ],
    audit: [
      [120, "tunnel main: speed test", "5.119.38.201"],
      [26 * 3600, "tunnel main: port 2053 added", "5.119.38.201"],
      [2 * 86400, "tunnel office: stopped", "5.119.40.17"],
      [3 * 86400, "server amsterdam joined", "5.119.38.201"],
      [12 * 86400, "admin password changed", "5.119.38.201"],
    ],
    section: "sec",
  };

  K.pages.settings = {
    render(box) {
      K.setTitle(t("page.settings"), t("set.sub"));
      const secs = ["sec", "access", "look", "upd", "backup", "audit"];
      const row = (title, text, ctl) => `<div class="set-row"><div><h3>${title}</h3>${text ? `<p>${text}</p>` : ""}</div><div class="ctl">${ctl}</div></div>`;
      const seg = (name, cur, opts) => `<div class="seg" role="group" data-seg="${name}">${opts.map(([v, l]) => `<button data-v="${v}" aria-pressed="${cur === v}">${l}</button>`).join("")}</div>`;
      const url = `https://203.0.113.5:${SET.port}/${SET.path}/`;
      box.innerHTML = `<div class="settings">
        <nav class="settings-nav" aria-label="${t("page.settings")}">${secs.map((s) => `<button data-sec="${s}" aria-current="${SET.section === s}">${t("set." + s)}</button>`).join("")}</nav>
        <div>
          <section class="stratum s1 set-section" id="set-sec"><div class="stratum-head"><h2>${t("set.sec")}</h2></div>
            ${row(t("set.pw"), t("set.pwText"), `<button class="btn btn-ghost btn-sm" id="pw-change">${icon("key")}${t("set.pwChange")}</button>`)}
            ${row(t("set.link"), t("set.linkText"), `<button class="btn btn-ghost btn-sm" id="link-make">${t("set.linkMake")}</button><div id="link-out" style="width:100%"></div>`)}
            ${row(t("set.2fa"), t("set.2faText"), `<button class="switch" role="switch" id="twofa" aria-checked="${SET.twofa}" aria-label="${t("set.2fa")}"></button>`)}
            ${row(t("set.sessions"), t("set.sessionsText"), `<div style="width:100%" id="sessions">${sessionsHtml()}</div>`)}
            ${row(t("set.lock"), t("set.lockText"), seg("lock", SET.lock, [["5", t("set.lock5")], ["3", t("set.lock3")]]))}
          </section>
          <section class="stratum s2 set-section" id="set-access"><div class="stratum-head"><h2>${t("set.access")}</h2></div>
            ${row(t("set.addr"), t("set.addrText"), `${codeBlock(esc(url), url)}<button class="btn btn-ghost btn-sm" id="path-new">${icon("restart")}${t("set.newPath")}</button>`)}
            ${row(t("set.tls"), t("set.tlsText"), `${seg("tls", SET.tls, [["self", t("set.tlsSelf")], ["le", t("set.tlsLe")]])}<div id="tls-more" style="width:100%"></div>`)}
          </section>
          <section class="stratum s1 set-section" id="set-look"><div class="stratum-head"><h2>${t("set.look")}</h2></div>
            ${row(t("set.lang"), "", seg("lang", state.lang, [["fa", "فارسی"], ["en", "English"]]))}
            ${row(t("set.theme"), "", seg("theme", state.theme, [["night", t("set.night")], ["dawn", t("set.dawn")]]))}
            ${state.lang === "fa" ? row(t("set.digits"), "", seg("digits", state.digits || "fa", [["fa", t("set.digitsFa")], ["latin", t("set.digitsLatin")]])) : ""}
            ${row(t("set.motion"), "", seg("motion", state.low ? "low" : "full", [["full", t("set.motionFull")], ["low", t("set.motionLow")]]))}
          </section>
          <section class="stratum s2 set-section" id="set-upd"><div class="stratum-head"><h2>${t("set.upd")}</h2></div>
            ${row(t("set.upd"), t("set.updText"), `<table class="plain-table" style="width:100%"><tbody>${SERVERS.map((s) => `<tr><td>${s.name}</td><td class="mono">${s.ver}</td><td><span class="badge water">${t("srv.upToDate")}</span></td></tr>`).join("")}</tbody></table><button class="btn btn-ghost btn-sm" id="upd-check">${icon("restart")}${t("set.check")}</button>`)}
            ${row(t("set.auto"), "", `<button class="switch" role="switch" aria-checked="true" id="upd-auto" aria-label="${t("set.auto")}"></button>`)}
          </section>
          <section class="stratum s1 set-section" id="set-backup"><div class="stratum-head"><h2>${t("set.backup")}</h2></div>
            ${row(t("set.bk"), t("set.bkText"), `<div class="row-actions"><button class="btn btn-primary btn-sm" id="bk-down"><span class="shine"></span>${t("set.bkDown")}</button><button class="btn btn-ghost btn-sm" id="bk-up">${t("set.bkUp")}</button></div>`)}
          </section>
          <section class="stratum s2 set-section" id="set-audit"><div class="stratum-head"><h2>${t("set.audit")}</h2></div>
            <table class="plain-table"><thead><tr><th>${t("set.when")}</th><th>${t("set.what")}</th><th class="hide-sm">${t("set.who")}</th></tr></thead>
            <tbody>${SET.audit.map(([s, w, ip]) => `<tr><td class="muted">${ago(s)}</td><td>${esc(w)}</td><td class="mono hide-sm">${ip}</td></tr>`).join("")}</tbody></table>
          </section>
        </div></div>`;
      this.tls(box);
      this.bind(box);
    },
    tls(box) {
      $("#tls-more", box).innerHTML =
        SET.tls === "self"
          ? `<div class="field"><span class="label">${t("set.fp")}</span>${codeBlock("9F:2C:41:E0:7B:5D:3A:18:C6:E4:F0:A9:D2:B7:C8:5E:\n1F:3A:6D:0C:4B:8E:2F:7A:9C:1D:5E:3B:6A:0F:4C:82", "9F2C41E07B5D3A18C6E4F0A9D2B7C85E1F3A6D0C4B8E2F7A9C1D5E3B6A0F4C82")}</div>`
          : `<div class="field"><label for="le-domain">${t("set.domain")}</label><input class="text mono" id="le-domain" dir="ltr" placeholder="panel.example.com"><span class="help" id="le-help"></span></div><button class="btn btn-primary btn-sm" id="le-get"><span class="shine"></span>${t("set.getCert")}</button>`;
      $("#le-get", box)?.addEventListener("click", () => {
        const d = $("#le-domain", box).value.trim();
        const help = $("#le-help", box);
        if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(d)) {
          help.className = "err";
          help.textContent = state.lang === "fa" ? "یک دامنه مثل panel.example.com بنویسید که به همین سرور اشاره کند." : "Enter a domain such as panel.example.com that points at this server.";
          return;
        }
        help.className = "ok";
        help.textContent = t("set.certOk");
      });
    },
    bind(box) {
      const scroller = $("#main");
      for (const b of $$("[data-sec]", box))
        b.addEventListener("click", () => {
          SET.section = b.dataset.sec;
          for (const x of $$("[data-sec]", box)) x.setAttribute("aria-current", String(x === b));
          $(`#set-${b.dataset.sec}`, box).scrollIntoView({ behavior: "smooth", block: "start" });
        });
      scroller.onscroll = () => {
        if (state.page !== "settings") return;
        let cur = "sec";
        for (const s of $$(".set-section", box)) if (s.getBoundingClientRect().top < 160) cur = s.id.slice(4);
        if (cur !== SET.section) {
          SET.section = cur;
          for (const x of $$("[data-sec]", box)) x.setAttribute("aria-current", String(x.dataset.sec === cur));
        }
      };
      for (const g of $$("[data-seg]", box))
        for (const b of $$("button", g))
          b.addEventListener("click", () => {
            const v = b.dataset.v, name = g.dataset.seg;
            for (const x of $$("button", g)) x.setAttribute("aria-pressed", String(x === b));
            if (name === "lang" && v !== state.lang) K.toggleLang();
            if (name === "theme" && v !== state.theme) K.toggleTheme();
            if (name === "digits") {
              state.digits = v;
              K.setPage("settings", true);
              K.renderRows();
            }
            if (name === "motion") K.setLow(v === "low", true);
            if (name === "tls") {
              SET.tls = v;
              this.tls(box);
            }
            if (name === "lock") SET.lock = v;
          });
      $("#pw-change", box).addEventListener("click", changePassword);
      $("#link-make", box).addEventListener("click", () => makeLink(box));
      $("#twofa", box).addEventListener("click", (e) => (SET.twofa ? ((SET.twofa = false), e.target.setAttribute("aria-checked", "false")) : setupTotp(box)));
      bindSessions(box);
      $("#path-new", box).addEventListener("click", () => {
        SET.path = "k-" + Math.random().toString(16).slice(2, 8);
        this.render(box);
        toast(t("set.pathNew"));
      });
      $("#upd-check", box).addEventListener("click", (e) => {
        const b = e.currentTarget;
        b.disabled = true;
        $("#loader-line").classList.add("is-on");
        setTimeout(() => {
          b.disabled = false;
          $("#loader-line").classList.remove("is-on");
          toast(t("set.checked"));
        }, 1400);
      });
      $("#upd-auto", box).addEventListener("click", (e) => e.target.setAttribute("aria-checked", String(e.target.getAttribute("aria-checked") !== "true")));
      $("#bk-down", box).addEventListener("click", () =>
        dialog(t("set.bk"), `<div class="field"><label for="bk-pass">${t("set.bkPass")}</label><input class="text" id="bk-pass" type="password" autocomplete="new-password"><span class="help">${t("set.bkText")}</span></div>`, `<button class="btn btn-ghost btn-sm" data-close>${t("cancel")}</button><button class="btn btn-primary btn-sm" id="bk-go">${t("set.bkDown")}</button>`, (d, close) =>
          $("#bk-go", d).addEventListener("click", () => {
            close();
            toast(t("set.bkMade"));
          })
        )
      );
      $("#bk-up", box).addEventListener("click", () => toast(state.lang === "fa" ? "بازیابی در فاز ۱۲ ساخته می‌شود." : "Restore is built in phase 12."));
    },
  };

  function sessionsHtml() {
    return SET.sessions
      .map((s) => `<div class="session" data-sid="${s.id}"><span class="who">${s.who}${s.me ? ` <span class="badge water">${t("set.thisDevice")}</span>` : ""}</span>${s.me ? "<span></span>" : `<button class="btn btn-ghost btn-sm" data-revoke="${s.id}">${t("set.revoke")}</button>`}<span class="meta"><span class="mono" dir="ltr">${s.ip}</span> · ${s.me ? K.stateLabel("up") : ago(s.seen)}</span></div>`)
      .join("");
  }
  function bindSessions(box) {
    for (const b of $$("[data-revoke]", box))
      b.addEventListener("click", () => {
        const row = b.closest(".session");
        row.animate([{ opacity: 1, transform: "none" }, { opacity: 0, transform: "translateX(24px)" }], { duration: 250, easing: "ease-in" }).onfinish = () => {
          SET.sessions = SET.sessions.filter((s) => String(s.id) !== b.dataset.revoke);
          $("#sessions", box).innerHTML = sessionsHtml();
          bindSessions(box);
          toast(t("set.revoked"));
        };
      });
  }

  function makeLink(box) {
    const tok = Array.from(crypto.getRandomValues(new Uint8Array(18)), (b) => b.toString(16).padStart(2, "0")).join("");
    const url = `https://203.0.113.5:${SET.port}/${SET.path}/#t=${tok}`;
    let left = 3600;
    const out = $("#link-out", box);
    out.innerHTML = `${codeBlock(esc(url), url)}<span class="countdown" id="link-left"></span>`;
    const tick = () => {
      const el = $("#link-left", box);
      if (!el) return clearInterval(iv);
      el.textContent = tf("set.linkValid", { m: K.localDigits(mmss(left)) });
      left--;
    };
    const iv = setInterval(tick, 1000);
    tick();
  }

  function strength(pw) {
    let s = 0;
    if (pw.length >= 10) s++;
    if (pw.length >= 14) s++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
    if (/\d/.test(pw) && /[^\w]/.test(pw)) s++;
    return s;
  }

  function changePassword() {
    dialog(
      t("set.pwChange"),
      `<div class="field"><label for="pw0">${t("set.pwCur")}</label><input class="text" id="pw0" type="password" autocomplete="current-password"></div>
       <div class="field"><label for="pw1">${t("set.pwNew")}</label><input class="text" id="pw1" type="password" autocomplete="new-password">
         <div class="meter" id="pw-meter"><div class="top"><span></span><b></b></div><div class="bar"><i style="width:0"></i></div></div></div>
       <div class="field"><label for="pw2">${t("set.pwAgain")}</label><input class="text" id="pw2" type="password" autocomplete="new-password"><span class="err" id="pw-err2"></span></div>`,
      `<button class="btn btn-ghost btn-sm" data-close>${t("cancel")}</button><button class="btn btn-primary btn-sm" id="pw-save" disabled>${t("set.pwChange")}</button>`,
      (d, close) => {
        const upd = () => {
          const p1 = $("#pw1", d).value, p2 = $("#pw2", d).value;
          const s = strength(p1);
          const m = $("#pw-meter", d);
          $(".bar i", m).style.width = `${(s / 4) * 100}%`;
          $(".bar i", m).style.background = s < 2 ? "var(--danger)" : s < 3 ? "var(--warn)" : "";
          $(".top b", m).textContent = p1 ? t(s < 2 ? "set.pwWeak" : s < 3 ? "set.pwOk" : "set.pwStrong") : "";
          $("#pw-err2", d).textContent = p2 && p1 !== p2 ? t("set.pwMismatch") : "";
          $("#pw-save", d).disabled = !($("#pw0", d).value && s >= 2 && p1 === p2);
        };
        for (const i of $$("input", d)) i.addEventListener("input", upd);
        $("#pw-save", d).addEventListener("click", () => {
          close();
          toast(t("set.pwSaved"));
        });
      }
    );
  }

  function setupTotp(box) {
    // a stand-in QR: a seeded grid, not a real code
    const r = K.rng(42);
    let cells = "";
    for (let y = 0; y < 25; y++)
      for (let x = 0; x < 25; x++) {
        const finder = (x < 7 && y < 7) || (x > 17 && y < 7) || (x < 7 && y > 17);
        const on = finder ? x % 6 === 0 || y % 6 === 0 || (x % 6 > 1 && x % 6 < 5 && y % 6 > 1 && y % 6 < 5) || x === 18 || x === 24 || y === 18 || y === 24 : r() < 0.45;
        if (on) cells += `<rect x="${x}" y="${y}" width="1" height="1"/>`;
      }
    dialog(
      t("set.2fa"),
      `<p class="small" style="margin:0">${t("set.2faScan")}</p>
       <div style="display:flex;gap:var(--sp-5);align-items:center;flex-wrap:wrap"><svg class="qr" viewBox="0 0 25 25" shape-rendering="crispEdges" fill="#0b1f34">${cells}</svg>
       <div class="field" style="flex:1;min-width:180px"><span class="label">secret</span><span class="mono small" dir="ltr">JBSW Y3DP EHPK 3PXP</span></div></div>
       <div class="field"><label for="totp">${t("set.2faCode")}</label><input class="text mono" id="totp" inputmode="numeric" maxlength="6" dir="ltr" autocomplete="one-time-code" style="letter-spacing:.4em;font-size:var(--fs-lg)"><span class="err" id="totp-err"></span></div>`,
      `<button class="btn btn-ghost btn-sm" data-close>${t("cancel")}</button><button class="btn btn-primary btn-sm" id="totp-go">${t("set.verify")}</button>`,
      (d, close) =>
        $("#totp-go", d).addEventListener("click", () => {
          if (!/^\d{6}$/.test($("#totp", d).value)) {
            $("#totp-err", d).textContent = t("set.2faBad");
            $("#totp", d).setAttribute("aria-invalid", "true");
            return;
          }
          SET.twofa = true;
          $("#twofa", box).setAttribute("aria-checked", "true");
          close();
          toast(t("set.2faOn"));
        })
    );
  }
  K.makeLoginLink = () => {
    K.setPage("settings");
    setTimeout(() => {
      const box = $('.page[data-page="settings"]');
      if (box) makeLink(box);
    }, 520);
  };

  // ------------------------------------------------------------------ palette commands

  K.commands = () => [
    { label: t("tn.new"), hint: "N", run: () => K.wizard.open() },
    { label: t("cmd.addServer"), hint: "", run: () => (K.setPage("servers"), setTimeout(addServer, 500)) },
    ...TUNNELS.map((tn) => ({ label: `${t("cmd.open")} ${tn.id}`, hint: K.stateLabel(tn.st), run: () => K.setPage("tunnel", false, tn.id) })),
    { label: t("cmd.link"), hint: "", run: K.makeLoginLink },
  ];

  addEventListener("keydown", (e) => {
    const tag = (e.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select" || e.ctrlKey || e.metaKey || e.altKey) return;
    if (!$("#app").classList.contains("is-on") || $("#wizard").classList.contains("is-on") || dlgClose) return;
    if (e.key === "n" || e.key === "N") K.wizard.open();
  });

  addEventListener("resize", () => drawChart());
})();
