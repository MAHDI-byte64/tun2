// Languages, the strings of the site's own screens, and the map of the documentation.
// The pages of the documentation themselves come from `docs/` and are never copied here.
export type Lang = "en" | "fa";
export const LANGS: Lang[] = ["en", "fa"];
export const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
export const REPO = "https://github.com/MAHDI-byte64/tun2";
declare const __KARIZ_VERSION__: string;
export const VERSION: string = __KARIZ_VERSION__;

/** A path on the site, in a language: href("fa", "/docs/panel/") */
export const href = (lang: Lang, path = "/") => `${BASE}${lang === "fa" ? "/fa" : ""}${path}`;

/** The same page in the other language (the switch keeps the page). */
export const otherLang = (lang: Lang): Lang => (lang === "en" ? "fa" : "en");

export const dirOf = (lang: Lang) => (lang === "fa" ? "rtl" : "ltr");

const digits = "۰۱۲۳۴۵۶۷۸۹";
/** Persian digits for numbers in Persian text (the docs keep the digits they were written with). */
export const num = (lang: Lang, n: number | string) =>
  lang === "fa" ? String(n).replace(/\d/g, (d) => digits[+d]) : String(n);

export const ui = {
  en: {
    tagline: "A fast, light tunnel core in Rust",
    skip: "Skip to content",
    docs: "Documentation",
    tryPanel: "Try the panel",
    github: "GitHub",
    support: "Support",
    search: "Search the docs",
    searchPlaceholder: "Search the documentation",
    searchNone: "Nothing found for",
    searchHint: "Type to search. Runs in your browser; nothing is sent anywhere.",
    searchOff: "Search is built with the published site. Build the site to try it.",
    theme: "Switch between Night and Dawn",
    lowPower: "Low power: stop animation",
    langSwitch: "فارسی",
    langSwitchLabel: "Read this page in Persian",
    onThisPage: "On this page",
    menu: "Menu",
    notTranslated: "This page is not translated yet. You are reading the English version.",
    translatedNote: "This page is also in English.",
    editOnGithub: "Edit this page on GitHub",
    copy: "Copy",
    copied: "Copied",
    next: "Next",
    previous: "Previous",
    version: "Version",
    footer: "Kariz is source-available software. The site is built from the repository's docs.",
    notFound: "This page is not here.",
    notFoundText: "The channel ends before this well. Try the documentation index or the search.",
    backHome: "Back to the front page",
    docsIntro: "Start with Getting started. Come back to the reference when you need a specific setting.",
    demoTitle: "Try the panel",
    demoLead: "The real panel's screens, fed with sample data. Everything runs in this page; nothing is sent anywhere.",
    demoOpen: "Open it full screen",
    demoNote: "Sample data. The password is kariz.",
    breadcrumb: "Breadcrumb",
  },
  fa: {
    tagline: "هستهٔ تانل سریع و سبک، با Rust",
    skip: "پرش به محتوا",
    docs: "مستندات",
    tryPanel: "پنل را امتحان کنید",
    github: "گیت‌هاب",
    support: "حمایت",
    search: "جستجو در مستندات",
    searchPlaceholder: "جستجو در مستندات",
    searchNone: "چیزی پیدا نشد برای",
    searchHint: "بنویسید تا جستجو شود. در مرورگر شما اجرا می‌شود و چیزی جایی فرستاده نمی‌شود.",
    searchOff: "جستجو همراه سایتِ منتشرشده ساخته می‌شود. برای امتحان، سایت را بسازید.",
    theme: "جابه‌جایی بین شب و سپیده‌دم",
    lowPower: "کم‌مصرف: توقف انیمیشن",
    langSwitch: "English",
    langSwitchLabel: "خواندن این صفحه به انگلیسی",
    onThisPage: "در این صفحه",
    menu: "منو",
    notTranslated: "این صفحه هنوز ترجمه نشده است. نسخهٔ انگلیسی را می‌خوانید.",
    translatedNote: "این صفحه به انگلیسی هم هست.",
    editOnGithub: "ویرایش این صفحه در گیت‌هاب",
    copy: "کپی",
    copied: "کپی شد",
    next: "بعدی",
    previous: "قبلی",
    version: "نسخه",
    footer: "کاریز سورس‌در‌دسترس است. این سایت از مستندات همین مخزن ساخته می‌شود.",
    notFound: "این صفحه اینجا نیست.",
    notFoundText: "مجرا پیش از این چاه تمام می‌شود. فهرست مستندات یا جستجو را امتحان کنید.",
    backHome: "بازگشت به صفحهٔ اول",
    docsIntro: "از «شروع کار» آغاز کنید. برای یک تنظیم مشخص به صفحه‌های مرجع برگردید.",
    demoTitle: "پنل را امتحان کنید",
    demoLead: "صفحه‌های پنل واقعی، با داده‌های نمونه. همه‌چیز در همین صفحه اجرا می‌شود و چیزی جایی فرستاده نمی‌شود.",
    demoOpen: "باز کردن تمام‌صفحه",
    demoNote: "داده‌های نمونه. رمز: kariz",
    breadcrumb: "مسیر",
  },
} as const;

export interface Section {
  id: string;
  title: Record<Lang, string>;
  pages: string[];
}

/** The map of the docs. A slug is the file name of a page in `docs/`, lower case. */
export const SECTIONS: Section[] = [
  { id: "start", title: { en: "Get started", fa: "شروع کار" }, pages: ["getting-started", "using-the-panel", "video", "tour", "manager", "panel"] },
  { id: "concepts", title: { en: "Concepts", fa: "مفاهیم" }, pages: ["how-it-works", "transports", "profiles", "udp-and-games", "cdn"] },
  { id: "guides", title: { en: "Guides", fa: "راهنماها" }, pages: ["networks", "troubleshooting", "speedtest", "telegram", "performance"] },
  { id: "reference", title: { en: "Reference", fa: "مرجع" }, pages: ["configuration", "status", "accessibility"] },
  { id: "security", title: { en: "Security", fa: "امنیت" }, pages: ["security", "security-review"] },
  { id: "project", title: { en: "Project", fa: "پروژه" }, pages: ["changelog", "roadmap", "support"] },
];

/** Short names for the sidebar; a page not listed uses its own heading. */
export const LABELS: Record<string, Record<Lang, string>> = {
  "getting-started": { en: "Getting started", fa: "شروع کار" },
  manager: { en: "The manager script", fa: "اسکریپت مدیر" },
  panel: { en: "The web panel", fa: "پنل وب" },
  "using-the-panel": { en: "Using the panel", fa: "کار با پنل" },
  tour: { en: "Guided tour", fa: "تور راهنما" },
  video: { en: "Video tutorial", fa: "ویدیوی آموزشی" },
  "how-it-works": { en: "How it works", fa: "چطور کار می‌کند" },
  transports: { en: "Transports", fa: "ترنسپورت‌ها" },
  profiles: { en: "Profiles", fa: "پروفایل‌ها" },
  "udp-and-games": { en: "UDP and games", fa: "UDP و بازی" },
  cdn: { en: "Behind a CDN", fa: "پشت CDN" },
  networks: { en: "Private networks (GRE, VXLAN)", fa: "شبکه‌های خصوصی (GRE، VXLAN)" },
  troubleshooting: { en: "Troubleshooting", fa: "عیب‌یابی" },
  speedtest: { en: "Speed test", fa: "تست سرعت" },
  telegram: { en: "Telegram alerts", fa: "اعلان تلگرام" },
  performance: { en: "Performance", fa: "کارایی" },
  configuration: { en: "Configuration", fa: "پیکربندی" },
  status: { en: "Status", fa: "وضعیت" },
  accessibility: { en: "Accessibility", fa: "دسترس‌پذیری" },
  security: { en: "Security", fa: "امنیت" },
  "security-review": { en: "Security review", fa: "بازبینی امنیتی" },
  changelog: { en: "Changelog", fa: "تغییرات" },
  roadmap: { en: "Design and protocol", fa: "طراحی و پروتکل" },
  support: { en: "Support Kariz", fa: "حمایت از کاریز" },
};

/** Pages made by the site itself (not a file of docs/): they exist in both languages. */
export const OWN_PAGES = new Set(["how-it-works", "tour", "video"]);

export const sectionOf = (slug: string) => SECTIONS.find((s) => s.pages.includes(slug));

/** The flat reading order, for Previous / Next. */
export const ORDER = SECTIONS.flatMap((s) => s.pages);
