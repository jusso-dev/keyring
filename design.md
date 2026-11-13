# Design: Keyring

A locked design system for Keyring's web UI. `static/style.css` is built from
this file. Change this file first when the system needs to grow, then the
stylesheet. Don't restyle a single page on its own.

Direction, chosen by the owner: **operational console + audit ledger**. A calm,
cool console for the shell and most pages; crisp ledger tables wherever rows of
names, dates and counts are read. Function carries every page. There is no
decoration: no illustrations, gradients, background art, charts or scores.

## Genre and structure

- Genre: modern-minimal (an app, not marketing).
- Macrostructure: Workbench, as an app shell. A thin top bar, a section nav on
  the left, and one work area. Every page uses the same shell.
- Page types:
  - **List pages** (vaults, secrets, certificates, keys, deleted): heading,
    one action row, a summary line, filters, then a framed table.
  - **Detail pages** (secret, certificate, key, deleted item): back link, mono
    heading, status badges, action row, then fact lists and tables.
  - **Form pages** (create, edit, upload, renewal, rotation policy,
    generator): a single column of fields, 40rem wide at most.
  - **Decision pages** (confirm, disable, rotate, rollback, upload preview,
    sign-in, signed out, errors): one narrow panel that ends in its action.
  - **Ledger pages** (audit, expiry): the table is the page. Fully ledger-style.

## Colour

Light only. Dark mode is left out on purpose: every pair below would need a
second check, and the owner marked it optional.

All tokens are OKLCH, inside sRGB, and are the only colours the stylesheet
uses. Hex is what they render as.

| Token | OKLCH | Hex | Use |
| --- | --- | --- | --- |
| `--color-paper` | `oklch(97.6% 0.004 250)` | `#f5f7fa` | Page background, cool light grey |
| `--color-paper-2` | `oklch(95% 0.006 250)` | `#ebeff2` | Value well, tags, hover rows, hints |
| `--color-surface` | `oklch(100% 0 0)` | `#ffffff` | Panels, framed tables, inputs |
| `--color-rule` | `oklch(90% 0.008 250)` | `#dadee3` | Hairlines (decorative, no contrast need) |
| `--color-rule-strong` | `oklch(58% 0.016 250)` | `#737b84` | Input and control borders |
| `--color-ink` | `oklch(25% 0.018 255)` | `#1c222a` | Text |
| `--color-ink-2` | `oklch(46% 0.02 255)` | `#515963` | Secondary text, column headers |
| `--color-accent` | `oklch(47% 0.075 215)` | `#186575` | The one accent: slate teal. Links, primary buttons, current nav |
| `--color-accent-strong` | `oklch(40% 0.07 215)` | `#02515f` | Hover on accent; the focus ring |
| `--color-accent-tint` | `oklch(95.5% 0.018 215)` | `#e3f4f8` | Current nav item, Current badge |
| `--color-accent-rule` | `oklch(80% 0.05 215)` | `#9ac7d2` | Border of accent-tinted things |
| `--color-accent-ink` | `oklch(100% 0 0)` | `#ffffff` | Text on accent and danger fills |
| `--color-focus` | `oklch(40% 0.07 215)` | `#02515f` | Focus ring on light surfaces |
| `--color-chrome` | `oklch(26% 0.02 250)` | `#1d252d` | Top bar |
| `--color-chrome-ink` | `oklch(97% 0.004 250)` | `#f3f5f8` | Top bar text |
| `--color-chrome-muted` | `oklch(78% 0.015 250)` | `#b0b8c1` | Top bar labels |
| `--color-chrome-link` | `oklch(84% 0.06 210)` | `#9dd6e0` | Top bar links |
| `--color-chrome-focus` | `oklch(86% 0.1 210)` | `#7be3f5` | Focus ring in the top bar |
| `--color-ok` / `-tint` / `-rule` | `oklch(45% 0.1 155)` / `oklch(96% 0.03 155)` / `oklch(80% 0.07 155)` | `#17653c` / `#e3f8e9` / `#9accaa` | Active, Allowed, saved |
| `--color-warn` / `-tint` / `-rule` | `oklch(47% 0.1 65)` / `oklch(96.5% 0.03 85)` / `oklch(80% 0.08 75)` | `#804d0c` / `#fdf2dd` / `#dcb783` | Expiring within 90 days, cautions |
| `--color-danger` / `-tint` / `-rule` | `oklch(50% 0.17 25)` / `oklch(96.5% 0.012 25)` / `oklch(80% 0.07 25)` | `#b02a2d` / `#fcf1ef` / `#e8ada7` | Expired, under 30 days, refused, errors |
| `--color-danger-strong` | `oklch(43% 0.15 25)` | `#901e21` | Hover on danger fills |
| `--color-shadow` | `oklch(25% 0.018 255 / 0.12)` | ink at 12% | The idle notice's shadow, the only shadow |

Accent footprint: the primary button, links, the current nav item and the
focus ring. Nothing is flooded with it.

### Contrast (WCAG 2 ratio, computed from the OKLCH values)

Text needs 4.5:1. Control borders, glyphs and focus rings need 3:1.

| Foreground | Background | Ratio | Where |
| --- | --- | --- | --- |
| ink | paper | 14.92 | Body text |
| ink | surface | 15.99 | Panels, tables |
| ink | paper-2 | 13.83 | Value well, tags |
| ink | accent-tint | 14.10 | Current nav item |
| ink | warn-tint | 14.44 | Text in a caution notice |
| ink-2 | paper | 6.64 | Muted text on the page |
| ink-2 | surface | 7.12 | Muted text, column headers |
| ink-2 | paper-2 | 6.15 | Muted text in the well, hints |
| ink-2 | ok / warn / danger tint | 6.40 / 6.43 / 6.40 | Muted text in notices |
| accent | paper | 6.19 | Links |
| accent | surface | 6.63 | Links in tables and panels |
| accent | paper-2 | 5.73 | Links on hover rows |
| accent | accent-tint | 5.85 | Current badge |
| accent | warn / danger tint | 5.99 / 5.97 | Links in notices |
| accent-strong | surface | 8.97 | Link hover |
| accent-ink | accent | 6.63 | Primary button |
| accent-ink | accent-strong | 8.97 | Primary button hover |
| accent-ink | danger | 6.55 | Danger button |
| accent-ink | danger-strong | 8.76 | Danger button hover |
| ok | ok-tint | 6.37 | Active badge, saved notice |
| ok | surface | 7.08 | Allowed |
| warn | warn-tint | 6.33 | Expiring badge, caution notice |
| danger | danger-tint | 5.90 | Expired badge, error notice |
| danger | surface | 6.55 | Field errors, outlined Delete, tile figures |
| danger | paper | 6.12 | Field errors on the page |
| chrome-ink | chrome | 14.23 | Top bar text |
| chrome-muted | chrome | 7.76 | Top bar labels |
| chrome-link | chrome | 9.69 | Top bar links |
| rule-strong | surface | 4.28 | Input and secondary button borders (3:1) |
| rule-strong | paper | 3.99 | Same, on the page (3:1) |
| rule-strong | paper-2 | 3.70 | Value well border (3:1) |
| focus | paper | 8.38 | Focus ring (3:1) |
| focus | surface | 8.97 | Focus ring (3:1) |
| focus | paper-2 | 7.76 | Focus ring (3:1) |
| chrome-focus | chrome | 10.47 | Focus ring in the top bar (3:1) |
| surface | accent / danger | 6.63 / 6.55 | The ring's offset gap against a filled button (3:1) |

Badge glyphs are drawn in the badge's text colour, so they share its ratio.
`--color-rule` is only used for hairlines that separate rows; the text and
the controls carry the meaning, so it has no contrast need.

## Typography

System fonts only. No font files are bundled or fetched.

- `--font-body`: `system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif`.
  Used for everything, headings included. (Hallmark's "no system display
  face" gate is overridden by the owner's decision.)
- `--font-mono`: `ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace`.
  Only for values, names and identifiers: vault, secret, certificate and key
  names, version IDs, thumbprints, tags, operations, IP addresses and the
  revealed value.
- Numbers line up: `font-variant-numeric: tabular-nums` on tables, fact lists,
  badges, tiles, the pager and the countdown.
- Scale: `--text-xs` 0.75rem (column headers, badges), `--text-sm` 0.875rem
  (help, tags, small cells), `--text-base` 1rem (body), `--text-md` 1.125rem
  (h2), `--text-lg` 1.5rem (h1), `--text-xl` 1.75rem (tile figures).
- Headings are roman, weight 650 (h1) and 600 (h2), tracking -0.01em, line
  height 1.25. Never italic. Long names wrap anywhere.
- Column headers: `--text-xs`, uppercase, 0.06em tracking, weight 600, ink-2.

## Space, size and shape

- Spacing: `--space-3xs` 0.25rem, `--space-2xs` 0.5rem, `--space-xs` 0.75rem,
  `--space-sm` 1rem, `--space-md` 1.5rem, `--space-lg` 2rem, `--space-xl`
  3rem. Multiples of 4 px only.
- Control height `--control-h` 2.5rem (40 px) for inputs, selects and buttons
  side by side. Small buttons `--control-h-sm` 2rem.
- Radius: `--radius` 6px (controls, panels, tables), `--radius-sm` 4px
  (badges, tags).
- Top bar `--bar-height` 3rem. Section nav 12rem. Work area 72rem at most.
- Measure: running text 70ch at most. Forms 40rem.

## Shell

- **Top bar**: dark chrome, one line on desktop. Wordmark (an inline SVG key
  ring, hidden from assistive tech, and "Keyring"), the current vault as a
  small "Vault" label with the name in mono and a "Change vault" link, and the
  signed-in person with "Sign out" at the right. It wraps on small screens.
- **Section nav**: 12rem on the paper colour with a hairline on its right. The
  current section has the accent tint, a 3px accent bar and weight 600. Below
  48rem it becomes a wrapping row with an underline for the current section.
- **Work area**: paper background. Panels and tables sit on white.

## Badges

One size, one shape, one vocabulary.

- Size: `--text-xs`, weight 600, height 1.375rem, padding 0 0.5rem, radius 4px,
  1px border in the tone's rule colour, tabular figures.
- Every badge has a text label **and** a CSS-drawn glyph before it, so colour
  is never the only signal. The glyph is a `::before` box with no text, so
  screen readers read only the label.

| Status | Class | Tone | Glyph |
| --- | --- | --- | --- |
| Active, Enabled | `badge badge-ok` | ok | filled circle |
| Current | `badge` | accent | filled circle |
| Expired, Expires within 30 days, Refused | `badge badge-error` | danger | diamond |
| Expires within 90 days, soft delete Off | `badge badge-warn` | warn | triangle |
| Disabled, Not active yet, Managed by a certificate | `badge badge-muted` | neutral | ring |
| No expiry | `badge badge-none` | neutral | dash |

"None" in an empty cell stays plain muted text, so an empty cell doesn't look
like a status.

## Tables

All tables follow the ledger rules: hairline row rules, small uppercase
column headers, tabular figures, rows at least 3rem tall, and names in mono.

- **Framed** (default): white table with a 1px rule border and 6px radius.
  Header row ruled off with `--color-rule-strong`. Rows tint paper-2 on hover.
- **Ledger** (`table.ledger`, audit and expiry): no frame, sits on the page.
  A 2px ink rule above the header, a 1px ink rule under it, hairline rules
  between rows and hairline column rules. Times and dates don't wrap.
- Tables scroll sideways inside `.table-wrap` at narrow widths. Nothing else
  on a page scrolls sideways.

## Facts

`dl.props` is a two-column fact list with a hairline above each row, labels in
ink-2 at `--text-sm`, and values in ink. It stacks below 30rem.

## Buttons and links

- Primary (`button`, `.button`): accent fill, white text, 6px radius, 40px
  tall, weight 600. Hover: accent-strong.
- Secondary (`.button-secondary`): white, ink text, rule-strong border. Hover:
  paper-2.
- Danger link (`a.button-danger`, the Delete that opens a confirm page):
  outlined, danger text and border on white.
- Danger action (`button.button-danger`, the final confirm): danger fill.
- Text links: accent, underlined, 1px from the baseline.
- Disabled controls: native `disabled`, 0.55 opacity and a not-allowed cursor.
- Button labels never wrap.

## Notices and empty states

- Notice: tone tint, 1px tone rule, 6px radius, a glyph in the left padding
  (ok: circle, warn: triangle, error: diamond). Never a thick side stripe.
- Hint ("What to ask for"): paper-2 inset block with a 6px radius.
- Empty state: white panel, hairline border, ink text.

## Patterns

### Reveal (secret value and generator)

- The value sits in a bordered mono well: paper-2, 1px rule-strong border,
  6px radius, mono at 0.9375rem.
- Copy, Show for longer and Hide sit in one row under it.
- The copy status shows as a neutral chip once it has words, so "Copied" is a
  clear label beside the buttons.
- The countdown is text with a clock glyph and tabular figures: "Hiding in 30
  seconds." The words are unchanged.
- A quiet note says the read is recorded: Keyring logs it, and the vault's
  audit log shows it if the vault sends its logs to Log Analytics. It links to
  "Who used it". Generator values aren't read from a vault, so the generator
  has no such note.
- Values are hidden in print.

### Expiry dashboard

- Count tiles first: one per group (Expired, Next 7 days, 8 to 30 days, 31 to
  90 days, More than 90 days, No expiry set). Each tile shows its count as a
  figure with the group's glyph and tone, then its label. Tiles with items
  link to their section; empty tiles are plain.
- The tile figure is the one place the badge element is drawn larger: it is a
  count, not a status, and keeps the badge's glyph so the tone isn't colour
  alone.
- Then a ledger table per group, most urgent first. No charts, no score.

### Audit

- One ledger table. When, Who, What, Item, Result, From. Times are tabular and
  don't wrap. Allowed is ok-coloured text with a check glyph; Refused is an
  error badge; Unknown stays muted.

### Rollback, rotate

Read as "make a new version". The primary button is the accent, never danger.

## Motion

Only colour changes on hover, 120ms ease-out. No transforms, no reveals.
Focus rings appear at once. `prefers-reduced-motion: reduce` turns all
transitions off.

## Accessibility rules the stylesheet must keep

- `[hidden] { display: none !important; }`.
- A visible focus ring on everything focusable: 2px `--color-focus` with a
  2px offset; `--color-chrome-focus` in the top bar.
- Reflow at 320 CSS px. Grid tracks use `minmax(0, ...)`. `overflow-x: clip`
  on `html` and `body` as a backstop; tables scroll inside their wrapper.
- `forced-colors: active`: badges, tags and buttons get a `CanvasText` border,
  glyphs are drawn in `CanvasText`, and the current nav item keeps
  `Highlight` and an underline.
- `@media print` hides `[data-secret-value]`.
- No inline styles, no `<style>` blocks, no fonts, images or data: URIs. Icons
  are inline `<svg>` with `aria-hidden="true"` or CSS glyphs.

## What pages must share

The top bar, nav, tokens, type scale, badge vocabulary, table rules, button
voice and notice style. Pages differ only in which of the page types above
they are.

## Exports

### tokens.css

```css
:root {
  --color-paper: oklch(97.6% 0.004 250);
  --color-paper-2: oklch(95% 0.006 250);
  --color-surface: oklch(100% 0 0);
  --color-rule: oklch(90% 0.008 250);
  --color-rule-strong: oklch(58% 0.016 250);
  --color-ink: oklch(25% 0.018 255);
  --color-ink-2: oklch(46% 0.02 255);
  --color-accent: oklch(47% 0.075 215);
  --color-accent-strong: oklch(40% 0.07 215);
  --color-accent-tint: oklch(95.5% 0.018 215);
  --color-accent-rule: oklch(80% 0.05 215);
  --color-accent-ink: oklch(100% 0 0);
  --color-focus: oklch(40% 0.07 215);
  --font-body: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --space-3xs: 0.25rem; --space-2xs: 0.5rem; --space-xs: 0.75rem;
  --space-sm: 1rem; --space-md: 1.5rem; --space-lg: 2rem; --space-xl: 3rem;
  --radius: 6px; --radius-sm: 4px;
}
```
