# The Kariz site

The documentation website, at <https://mahdi-byte64.github.io/tun2/>. It is built with
[Astro](https://astro.build) from the files of this repository; nothing of the text lives here.

| What | Where it comes from |
|---|---|
| Documentation pages | `docs/*.md` (English) and `docs/fa/*.md` (Persian), plus `CHANGELOG.md` |
| Tokens and fonts | `panel/web/src/tokens.css`, `panel/web/src/fonts/` (the panel's own) |
| The hero's drawing helpers | `panel/web/src/draw.ts` |
| The live demo | `design/prototype/` (the interactive prototype, with sample data) |
| The front page, how-it-works, the diagrams | `site/src/` (written in both languages) |

`scripts/prepare.mjs` copies the shared files into places Astro serves; the copies are not
committed.

## Work on it

```bash
cd site
npm ci
npm run dev        # http://localhost:4321/tun2/ (search needs a build)
npm run build      # the site, then the Pagefind search index, into dist/
npm run check      # translations and links (needs the build)
npm test           # Playwright: axe in both themes and languages, search, the diagrams
```

`PW_CHANNEL=msedge npm test` uses the Edge that is installed instead of downloading Chromium.

## Rules that keep it honest

- **One source.** A page of the docs is a markdown file in `docs/`; links between files
  (`transports.md`, `../README.md`) work in GitHub and on the site (`src/plugins/remark-doc-links.mjs`).
  A new file must be added to `SECTIONS` in `src/lib/site.ts`, or the build fails.
- **Persian is not an afterthought.** An English page with no Persian version is listed in
  `untranslated.txt`, and `scripts/check-translations.mjs` fails when the list is not true.
- **Links must land.** `scripts/check-links.mjs` follows every internal link and `#anchor` of the built site.
- **Nothing moves when the reader asks it not to.** `prefers-reduced-motion` and the low-power
  switch stop every animation; the hero holds still and is one screen tall.
- **The demo is the prototype.** The site never edits `design/prototype/`; the language and
  theme are passed in the address (`?lang=en&theme=dawn`) by a small patch in `prepare.mjs`.

## Publishing

`.github/workflows/site.yml` builds and checks the site on every pull request that touches it,
and publishes to GitHub Pages on a release tag and on pushes to `main` that touch `docs/`,
`site/` or the files above. In the repository's settings, Pages must use **GitHub Actions** as
its source.
