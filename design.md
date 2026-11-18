# Design: Keyring

A locked design system for Keyring's web UI. `static/style.css` is built from
this file. Change this file first when the system needs to grow, then the
stylesheet. Don't restyle a single page on its own.

Direction, chosen by the owner: **operational console + audit ledger**. A calm,
cool console for the shell and most pages; crisp ledger tables wherever rows of
names, dates and counts are read. Function carries every page. There is no
decoration: no illustrations, gradients, background art, charts or scores.

## Genre and structure

- Genre: enterprise console (an app, not marketing). It follows Fluent 2 and
  the Azure portal, so Keyring sits comfortably beside the portal and the
  Entra admin centre. The owner asked for this on 18 November 2026, after
  comparing Keyring with backup and secrets-management consoles.
- Macrostructure: Workbench, as an app shell. A 48px top bar, a grouped
  section nav with icons on the left, and one work area up to 80rem wide.
  Every page uses the same shell.
- Every page opens with the same **page header**: a breadcrumb, a title row
  (h1 and status badges), one short description line, then a command bar.
  Longer explanations sit in a closed "About this page" `<details>` under
  the description, or in field help. Safety and consequence messages stay
  visible where they are.
- Page types:
  - **List pages** (vaults, secrets, certificates, keys, deleted): page
    header with the create action in the command bar, then a compact
    toolbar (one row of filter pills, a count, actions on the right), then
    the table across the work area. No separate filter panel.
  - **Detail pages** (secret, certificate, key, deleted item): page header,
    then a tab strip (Overview, Versions, Who used it, Access and sharing)
    of links to existing routes or anchors on the page, the open one with
    `aria-current="page"`. Overview shows the value panel and the
    properties side by side on wide screens, as compact fact lists.
  - **Form pages** (create, edit, upload, renewal, rotation policy,
    generator): fields grouped under small section headings (Basics,
    Value, Expiry, Ownership and notes, Tags, Advanced), 40rem wide at
    most. One rhythm: `--space-sm` (16px) above each field's label,
    `--space-lg` (32px) above each section heading. A field label that
    isn't a `<label>` (such as "Type of secret") is `p.field-label`.
  - **Decision pages** (confirm, disable, rotate, rollback, upload preview,
    sign-in, signed out, errors): one narrow panel that ends in its action.
  - **Ledger pages** (audit, expiry, vault health, access): the table is the page.
    Fully ledger-style.

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
| `--color-chrome-2` | `oklch(32% 0.02 250)` | `#2b343d` | The vault switcher chip in the top bar |
| `--color-chrome-ink` | `oklch(97% 0.004 250)` | `#f3f5f8` | Top bar text |
| `--color-chrome-muted` | `oklch(78% 0.015 250)` | `#b0b8c1` | Top bar labels |
| `--color-chrome-link` | `oklch(84% 0.06 210)` | `#9dd6e0` | Top bar links |
| `--color-chrome-focus` | `oklch(86% 0.1 210)` | `#7be3f5` | Focus ring in the top bar |
| `--color-ok` / `-tint` / `-rule` | `oklch(45% 0.1 155)` / `oklch(96% 0.03 155)` / `oklch(80% 0.07 155)` | `#17653c` / `#e3f8e9` / `#9accaa` | Active, Allowed, saved |
| `--color-warn` / `-tint` / `-rule` | `oklch(47% 0.1 65)` / `oklch(96.5% 0.03 85)` / `oklch(80% 0.08 75)` | `#804d0c` / `#fdf2dd` / `#dcb783` | Expiring within 90 days, cautions |
| `--color-danger` / `-tint` / `-rule` | `oklch(50% 0.17 25)` / `oklch(96.5% 0.012 25)` / `oklch(80% 0.07 25)` | `#b02a2d` / `#fcf1ef` / `#e8ada7` | Expired, under 30 days, refused, errors |
| `--color-danger-strong` | `oklch(43% 0.15 25)` | `#901e21` | Hover on danger fills |
| `--color-shadow` | `oklch(25% 0.018 255 / 0.12)` | ink at 12% | The idle notice's and the More menu's shadow, the only shadows |

Accent footprint: the primary button, links, the current nav item, the open
tab's underline, toolbar icons and the focus ring. Nothing is flooded with it.

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
| chrome-ink / chrome-muted / chrome-link | chrome-2 | 11.61 / 6.34 / 7.91 | Vault switcher name, label and link |
| rule-strong | chrome | 3.63 | Vault switcher border (3:1) |
| chrome-muted | chrome-2 | 6.34 | Search icon and account icon (3:1) |
| accent | paper / paper-2 | 6.19 / 5.73 | Pin star (3:1) |
| ink-2 | paper | 6.64 | Column headers on the paper header row, nav group labels |
| ink | paper-2 | 13.83 | Info notice, toolbar button hover, More menu hover |
| danger | surface | 6.55 | Delete in the More menu |
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

One ramp, from Fluent 2's web type ramp. The owner asked for it on 18
November 2026: the earlier scale mixed 13, 14, 16 and 24px text on six line
heights and three weights.

- `--font-body`: `"Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, sans-serif`.
  System fonts only: Segoe UI on Windows, the platform face elsewhere. The
  UI loads no font files.
- `--font-mono`: `ui-monospace, "Cascadia Mono", Consolas, SFMono-Regular, Menlo, monospace`.
  Only for technical data: version IDs, thumbprints, tags, operations, IP
  addresses and secret values. Resource names use the UI font.
- Nothing in Keyring is set in italic.

| Token | Size / line | Use |
| --- | --- | --- |
| `--text-caption` / `--lh-caption` | 12px / 16px | Column headers, badges, field help, breadcrumb, nav group labels, filter labels |
| `--text-body` / `--lh-body` | 14px / 20px | Body text, controls, table cells, labels, fact lists |
| `--text-mono` / `--lh-mono` | 13px / 20px | Technical values (fixed, never relative to its parent) |
| `--text-subtitle` / `--lh-subtitle` | 16px / 22px | h2, section titles; editable text on small screens |
| `--text-title` / `--lh-title` | 20px / 28px | h1 on every page |
| `--text-large` / `--lh-large` | 24px / 32px | The expiry and age count figures only |

- Weights: 400 and 600 only. `strong`, `b`, `th` and labels are 600.
- No em-relative font sizes. Every text element uses one of the tokens.
- Headings are weight 600, no negative tracking. h3 uses the body size.
- Column headers: `--text-caption`, weight 600, ink-2, sentence case (no
  uppercase, no extra tracking).
- Numbers line up: `font-variant-numeric: tabular-nums` on tables, fact lists,
  badges, tiles, the pager and the countdown.
- Small screens (below 48rem): inputs, selects and textareas use
  `--text-subtitle`, so mobile browsers don't zoom on focus.

## Space, size and shape

- Spacing on a 4px grid: `--space-3xs` 4px, `--space-2xs` 8px, `--space-xs`
  12px, `--space-sm` 16px, `--space-md` 24px, `--space-lg` 32px, `--space-xl` 48px.
- Controls `--control-h` 32px (inputs, selects, buttons). Small controls
  `--control-h-sm` 24px (row actions, the Pin button, toolbar extras). Every
  target is at least 24 by 24px.
- Table rows about 40px: cell padding 8px by 12px, `tbody tr` 40px high.
- Panels: 16px padding (20px on decision panels).
- Radius: `--radius` 4px (controls, panels, tables), `--radius-sm` 2px
  (badges, tags).
- Top bar `--bar-height` 48px. Section nav 12rem. Work area 80rem at most.
- Measure: running text 70ch at most. Forms 40rem.

## Shell

- **Top bar** (48px, dark chrome): the mark and "Keyring", then the vault
  switcher (a "Vault" label, the vault name and "Change vault", or "Choose
  a vault"), the global search, and the signed-in person with "Sign out"
  at the right. Below 48rem it wraps and search takes its own row.
- **Search** is a plain GET form to `/search` with a visually hidden
  label, styled like the Azure portal's: a 20rem field on chrome-2 with a
  rule-strong border, chrome-ink text and a leading 16px search icon in
  chrome-muted (inline SVG, `aria-hidden`). The Search button is quiet:
  no fill or border, chrome-link text, chrome-2 on hover. Enter also
  searches.
- **Account** is a compact chip: 24px high, caption size, a person icon,
  chrome-2 fill, a rule-strong border and fully rounded ends. "Sign out"
  stays a text link beside it.
- **Section nav** (12rem, paper, hairline right): items in groups, each
  group with a caption label.
  - Vault: Secrets, Certificates, Keys
  - Across vaults: Vaults, Expiry, Vault health, Search
  - Governance: Audit, Access, My access
  - Tools: Generator
  Each item has a hand-drawn 16px inline SVG icon (`aria-hidden`, drawn in
  `currentColor`), placed beside the link inside the item so the link's
  text is just its label. The current item has the accent tint, a 3px accent
  bar on the left and weight 600. Below 48rem the groups become wrapping
  rows, labels hidden, with an underline for the current item.
- **Work area**: paper background. Panels and tables sit on white.

## Page header

- **Breadcrumb**: `nav.breadcrumb` with `aria-label="Breadcrumb"`, an `ol` of
  links at `--text-caption` (each at least 24px wide) separated by a CSS chevron, the last item a
  `span` with `aria-current="page"`. Item pages: Vaults > vault > Secrets >
  name. It replaces every "Back to" link.
- **Title row**: the h1 (`--text-title`), then status badges, then the Pin
  button when the script adds it, styled as a command bar button.
- **Description**: one line, `p.page-desc`, ink-2. An item's own
  description (`.item-note`) takes its place on detail pages.
- **About this page**: `details.about`, closed, a summary with an info
  glyph, holding the rest of the page's explanation.
- **Command bar** (`div.commandbar`): the primary action as a filled
  button, other common actions as subtle toolbar buttons (`a.cmd`,
  `button.cmd`: no border, a 16px icon and a label, paper-2 on hover), and
  the rarely used or destructive ones (Delete, Disable, Copy to another
  vault, deleted items and similar) in a **More** menu: `details.menu` with
  a `summary` button and a list under it, aligned to the summary's right
  edge so it opens towards the page. It sits under the idle sign-out
  notice. No script: Enter or Space opens
  it, Tab moves through it. Destructive items are danger-coloured text.
- **Tabs** (`nav.tabs`, `aria-label` names the item): links in a row on a
  hairline, the open one ink, weight 600, with a 2px accent underline and
  `aria-current="page"`. Tabs that point at a section on the same page
  are anchors. The open tab is a link, except "Who used it", which is a
  `span` with `aria-current="page"`, so it can't drop the filters applied
  on that page.

## Badges

One size, one shape, one vocabulary.

- Size: 20px high, `--text-caption` (12/16), weight 600, padding 0 6px,
  radius 2px, 1px border in the tone's rule colour, tabular figures.
- Every badge has a text label **and** a CSS-drawn glyph before it, so colour
  is never the only signal. The glyph is a `::before` box with no text, so
  screen readers read only the label.

| Status | Class | Tone | Glyph |
| --- | --- | --- | --- |
| Active, Enabled | `badge badge-ok` | ok | filled circle |
| Current | `badge` | accent | filled circle |
| Expired, Expires within 30 days, Refused | `badge badge-error` | danger | diamond |
| Expires within 90 days, soft delete Off, Not changed in over a year | `badge badge-warn` | warn | triangle |
| Disabled, Not active yet, Managed by a certificate | `badge badge-muted` | neutral | ring |
| No expiry | `badge badge-none` | neutral | dash |
| Health check: Pass / Warn / Unknown | `badge-ok` / `badge-warn` / `badge-muted` | ok / warn / neutral | circle / triangle / ring |
| Rotation: OK / Failed / Unknown | `badge-ok` / `badge-error` / `badge-muted` | ok / danger / neutral | circle / diamond / ring |

"None" in an empty cell stays plain muted text, so an empty cell doesn't look
like a status.

## Tables

All tables follow the ledger rules: hairline row rules, sentence-case
column headers at `--text-caption` weight 600 in ink-2, tabular figures,
rows about 40px tall (8px by 12px cell padding), and names in the UI font.
Links in cells aren't underlined until hover or focus: the column says
they are names to open.

- **Framed** (default): white table with a 1px rule border and 4px radius.
  Header row on paper with a rule-strong line under it. Rows tint paper on
  hover. The table fills the work area.
- **Ledger** (`table.ledger`, audit and expiry): no frame, sits on the page.
  A 2px ink rule above the header, a 1px ink rule under it, hairline rules
  between rows and hairline column rules. Times and dates don't wrap.
- **Every data table is one line per row**, about 40px, whatever the data.
  Real tenants have long sign-in names (`kr-e2e-colleague-1118@yumait.au`),
  long item names and long descriptions, so the rule is enforced by
  classes, not by short demo data:
  - Dates and times: `nowrap`. Log times are compact in the cell ("18 Nov
    2026, 05:22") inside `<time datetime="2026-11-18T05:22:09Z">`, so the
    full ISO time stays in the markup. The column header says the zone:
    "When (UTC)", "Last (UTC)".
  - Names, sign-in names, owners, descriptions, content types, reasons and
    other free text sit in a `span.clip`: one line, cut with an ellipsis.
    The width is per column: `clip-sm` 8rem (content type, IP-like
    values), `clip-md` 12rem (descriptions, owners, items, reasons),
    `clip-lg` 16rem (sign-in names, item names in a list). CSS cuts only
    what is drawn: the whole text stays in the page, so a screen reader
    reads all of it, and the item's own page shows it in full. Where a
    page is the only place a value is shown (versions, import preview), it
    wraps in full (`td.mono-wrap`).
  - No `title` tooltips: they can't be reached by touch or keyboard.
  - `tests/one_line_rows.rs` checks the main lists and both audit views
    carry these classes on those columns.
- **Columns fit at 1440px with no sideways scroll.** The secrets list shows
  Name, Status, Description, Owner, Content type, Value changed and
  Expires; certificates show Name, Status, Description, Owner, Expires and
  Thumbprint; keys show Name, Status, Description, Owner, Created and
  Expires. Tags are on each item's page and found with the Tag filter.
  The stale badge sits in the Status cell. Below 1100px (`68.75rem`) the
  lower-priority columns hide with CSS: content type first (`col-p3`),
  then description (`col-p2`). No column picker and no script.
- Tables scroll sideways inside `.table-wrap` only on small screens.
  Nothing else on a page scrolls sideways.

## Toolbar (lists)

- `form.filters` sits straight above the table: one row of 32px filter
  pills on a white bar with a hairline border, as in the Azure portal.
- A **filter pill** (`.fpill`) is one bordered 32px box: the `<label>` as
  a caption-size ink-2 prefix ("Status"), a colon, then the borderless
  select or input inside it ("Status: All secrets"). The whole pill takes
  the focus ring (`:focus-within`). The label is a real `<label for>`, so
  the control keeps its accessible name. Placeholders are never used.
- Help that only explains goes into the page's "About this page". Two
  hints stay visible because they change what you type or what happens:
  the tag syntax, as a short caption suffix in the Tag pill ("name or
  name=value", `.fpill-hint`, tied with `aria-describedby`), and the bulk
  change's "Key Vault can't remove an expiry date" beside the date.
  A unit ("days") is a suffix the same way.
- "Owned by me" is a checkbox pill.
- The last item is a compact secondary **Apply** button (Search, Check or
  Run report where the page says so). Enter in any text box applies the
  filters too, as a plain GET form. Clear is a text link after it.
- A row's checkbox has its visually hidden label stretched over the cell,
  so the target is the cell, not the 16px box.
- A count ("9 items") and the page's status links sit in `.toolbar-meta`
  under the toolbar, at caption size.
- "With selected" (bulk changes) is a second toolbar, closed by default in
  a `details.bulk`, so the table stays near the top of the page.

## Facts

`dl.props` is a compact two-column fact list: labels in ink-2 at body size,
a 12rem label column, values in ink, a hairline between rows and 6px of
padding above and below each row. It stacks below 30rem.

## Buttons and links

- Primary (`button`, `.button`): accent fill, white text, 4px radius, 32px
  tall, 0 12px padding, `--text-body` weight 600. Hover: accent-strong.
- Secondary (`.button-secondary`): white, ink text, rule-strong border. Hover:
  paper-2.
- Small (`.button-small`): 24px tall, 0 8px padding, body size.
- Toolbar (`.cmd`): no border or fill, ink text, a 16px accent icon, paper-2
  on hover. Used in command bars only.
- Danger link (`a.button-danger`, the Delete that opens a confirm page):
  outlined, danger text and border on white.
- Danger action (`button.button-danger`, the final confirm): danger fill.
- Text links: accent, underlined, 2px from the baseline, in running text.
- Disabled controls: native `disabled`, 0.55 opacity and a not-allowed cursor.
- Button labels never wrap.

## Notices and empty states

- Notice: a Fluent message bar. Tone tint, 1px tone rule, 4px radius, a
  16px glyph in the left padding (info: ring, ok: circle, warn: triangle,
  error: diamond), body text, 8px by 12px padding. One line where the
  words allow. Never a thick side stripe.
- Hint ("What to ask for"): paper-2 inset block with a 4px radius.
- Empty state: white panel, hairline border, ink text.

## Patterns

### Reveal (secret value and generator)

- The value sits in a bordered mono well: paper-2, 1px rule-strong border,
  4px radius, mono at `--text-mono`.
- Copy, Show for longer and Hide sit in one row under it.
- The copy status shows as a neutral chip once it has words, so "Copied" is a
  clear label beside the buttons.
- The countdown is text with a clock glyph and tabular figures: "Hiding in 30
  seconds." The words are unchanged.
- A quiet note says the read is recorded: Keyring logs it, and the vault's
  audit log shows it if the vault sends its logs to Log Analytics. It names
  "Who used it" on the secret's page rather than adding another link to the
  panel. Every way off the page waits for the clipboard clear after a copy
  (static/app.js), so Hide stays the panel's one exit. Generator values aren't
  read from a vault, so the generator has no such note.
- A typed secret (Login, Database, API key, SSH private key) shows one
  labelled well per field, each with its own secondary "Copy <field>"
  button under it; Show for longer and Hide stay in the one row below.
  A line above says every field is part of the value. Database connection
  strings sit in a closed `<details>` after the fields. A typed value
  that doesn't match its type shows as the plain well with a warn notice.
- The create form picks the type from a row of plain links ("Type of
  secret"), the current one bold with `aria-current`. Password and key
  fields are masked inputs; every field follows the usual label, help and
  error pattern.
- With `KEYRING_PASSWORD_POLICY` set, the Password value box and a Login's
  password field get a second field help line, after the usual help, that
  says what the policy asks for and that the Azure CLI and portal don't
  apply it. On the plain Value box it adds that every plain value is
  checked as a password, and to choose the type that fits for a key, PEM
  block or connection string. A policy error is an ordinary field error on
  that field.
- The import preview says once, above the table, what the policy asks
  for. A row that misses it is "Can't import" with fixed words that name
  no rule.
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
- Before the groups, a "Rotation failed" ledger table (Name with the Failed
  badge, Vault, Rotated by, Last attempt, Open), only when a secret's
  `rotation-status` tag is `failed`, with a muted line saying it is what the
  tags say. On a secret's page the same tags show as one "Rotation" row in
  the fact list, after Tags, with the status badge and a muted note.
- Two views share the Expiry section: "By expiry date" (`/expiry`) and "By
  time since the value changed" (`/expiry/age`). A `p.view-switch` under the
  heading links the two, inside a `nav` labelled "Expiry views". The open
  view is ink text at weight 600 with `aria-current="page"` and no
  underline; the other is a normal link. Not tabs: each is its own page and
  works without JavaScript.

### Age view

- The same layout as the expiry dashboard: the view switch, filters (vault,
  type, tag, Download CSV), notes on vaults not read, count tiles, then a
  ledger table per band.
- Bands, oldest first: Over a year, 180 to 365 days, 90 to 180 days, Under
  90 days. A fifth, "Date not given", shows only when it has items. The
  Over a year tile is warn; the rest are neutral. Age is a prompt to
  rotate, never an error.
- Columns: Name, Type, Vault, Value changed (date, "N days ago" muted, and
  the stale badge), Tags, Open.
- The stale badge, "Not changed in over a year" (or "over N days" when
  `KEYRING_STALE_AFTER_DAYS` isn't 365), is `badge-warn`. It shows in the
  Value changed cell on the age view and the secrets list, and beside the
  status badges on a secret's page. Never on an item managed by a
  certificate.

### Search

- A list page across vaults: heading, the search form (text, vault, type,
  status), then the notes on vaults not read, then one framed table per vault
  under an `h2` with the vault name in the UI font and its count.
- Rows use the same columns and status badges as each vault's own list.
- Before a search, and when nothing matches, an empty state says what to do.

### Audit

- One ledger table. When (UTC), Who, What, Item, Result, From. Times are
  compact, tabular and don't wrap. Every cell is one line: What shows
  Azure's operation in plain words (the raw operation is in the CSV). Allowed and Accepted (202, queued by Key Vault) are ok-coloured
  text with a check glyph, Accepted with the status muted after it; Refused
  (401, 403) is an error badge; Failed (other 4xx, 5xx) is a muted badge;
  Unknown stays muted. One macro, `ui::audit_result`, draws the cell on every
  audit table.
- With `KEYRING_AUDIT_WORKSPACE_ID`, a `.view-switch` under the heading:
  "Key Vault's log" and "Keyring activity", the open one with
  `aria-current="page"`, as on the expiry views. Keyring activity is the
  same ledger with When (UTC), Who, What, Item, Result, Why, From. What is
  the action's plain label ("Bulk change to secrets", "Email sent", "Share
  revoked") from `Action::label` in `src/audit/mod.rs`, the one place
  labels live; a test fails if an action has none. The dotted code
  (`secret.bulk_update`) is in the Action filter's options and in Log
  Analytics. An event with no person is Who "Keyring" with a muted
  `badge-muted` "System" badge. Result: Done is an ok badge; "Denied by
  Azure" and "Refused by Keyring" are error badges; Failed is a muted
  badge; the reason code follows on the same line, muted and mono. Why is
  the reason, then "Ticket ..." muted on the same line, or muted "None".
- Across vaults (`/audit`): the fixed reports first, as a `.card-list` of
  links. The open one has `aria-current="page"`, the accent tint, an accent
  border and an underline, so it isn't colour alone. Then the same ledger
  table with a Vault column and a "Vault audit" link per row to that
  vault's own page. The refused report counts by person and vault, with the
  count in an error badge. Vaults and workspaces left out are warn notices
  listing each with its reason; vaults with no logging are a plain notice
  with a "What to ask for" hint.

### Vault health

- Filters (one vault or all, and Download CSV), a one-line summary of
  warnings and unknowns, then one ledger table: a row per vault, a column
  per check, each cell a Pass, Warn or Unknown badge. A check left for the
  one-vault view is muted text, "Pick this vault", not a badge.
- Under it, "What to look at": a plain list, one line per warning or
  unknown, with its badge, the vault in the UI font, the check, one sentence on
  why it matters and what to do, and a link to Microsoft's guide.
- No score, no chart and no totals per vault. Unknown never reads as a pass.
- On the vault list, the Audit logs column is plain "On", a warn badge
  "Off", or muted "Unknown" with the reason.

### Used by in the last 30 days

- A section at the foot of an item's page, and under the form on Set a new
  value, Roll back, Disable, Rotate and Delete, so the form comes first.
- One ledger table: Who (sign-in name in the UI font; technical IDs in mono), Kind, Object ID,
  Last, Reads (Uses for a key), From (IP in mono, client info muted under
  it). Latest first.
- Nothing found is an empty state in neutral words, never a promise: "No
  secret reads found in the available logs for this period. Logs may be
  delayed or incomplete; check consumers before changing this secret." (key
  use or certificate private-key access in place of secret reads). A log
  that can't be read, or one with no events from the vault yet, is an
  empty state that says why and "You can still go ahead", with a "What to
  ask for" hint, or, when there is no hint, "Check what uses this ...
  before you change it." before it. It is never an error notice, because it never stops the
  action.
- Workspaces left out, workspaces with no events from the vault, and a
  partial answer are warn notices under the table.
- One short muted line under the heading says what it is, with "See every
  event". The count line over the table says that anything listed may
  break if the item changes; it stays visible.
- Last, in every state, a closed `details.about`, "How this is worked
  out": what was looked at (workspaces answered of how many, the 30 days,
  the newest event) and what the log can't show.
### Access

- The vault's Access page: heading, a Download CSV link, a closed "How
  this is worked out" saying principals are object IDs with portal links
  and names aren't looked up, then one ledger table: Who (object ID in mono, linked to the portal), Type,
  Role, Comes from. Eligible is a muted badge; "Can grant itself access" is
  a warn badge. Notes on what wasn't read are warn notices under the table.
- Access policy vaults: a sentence saying so, then a ledger table of object
  ID and what each policy allows in plain words, with a warn badge "Reads
  secret values". Then the roles that can grant access.
- Each secret, certificate and key page ends with an Access section (`h2`)
  using the same tables: one short line ("Who can reach this secret.") and
  a link to the whole vault's Access page, then the count. Where the
  assignments come from (the item, the vault, its resource group, its
  subscription and any management group above it), how principals are shown and what "Can grant
  itself access" and "Eligible" mean sit in a closed "How this is worked
  out". Badges, empty states and notes stay visible.
- When it can't be read: an empty state with the reason and a "What to ask
  for" hint, never an empty table.

### Access review

- The vault's Access page and its Access review share a `.view-switch`
  under the heading: "Who has access" and "Access review", the open one
  with `aria-current="page"`, as on the expiry and audit views.
- Heading, one line on what it is, a Download CSV link, then three
  sections: Used by in the last 90 days (what couldn't be read as warn
  notices, with a "What to ask for" hint, then the muted coverage and
  limits line), Who has access to the whole vault (the Access page's own
  tables, once), then Items: one ledger table. Name (row header, linked to
  the item), Type, Expires, Owner, Description, Value changed, Used by (90
  days), Access on this item, Rotation.
- A cell Keyring couldn't fill says muted "Not known", never blank and
  never "None". "None found" is muted, and only when the whole log was
  read. Item access is muted "As the vault", or "As the vault, and:" with
  the item's own assignments. Rotation uses the rotation badges, or muted
  "Not tagged".

### PIM activation

- On the 403 page, under "What to ask for": one sentence saying the person is eligible, and a primary "Activate {role}" button. Nothing else on the page changes.
- The activation form follows the other forms: breadcrumb, heading with the role muted, one sentence on what turning it on means, a warn notice when PIM needs approval (with approvers as PIM names them), the error summary, then How long (a select up to PIM's maximum), Why you need it (with the note not to type secrets or personal details), Ticket system and Ticket number, each marked optional unless PIM asks for it.
- The result is a narrow panel: "Role turned on" with Try again, "Waiting for approval" with a link to PIM in the portal, or "PIM didn't turn the role on" with ARM's code under "Details:".
- My access: heading, one sentence, warn notices for anything not read, then ledger tables, "On now" (Role with an ok badge "Activated", Comes from, Time left, a secondary Deactivate button), "Starting later" only when there is one (Role, Comes from, When it starts and ends, no button), "Eligible" (Role, Comes from, Eligible until, Activate, or a muted badge "On now", "Waiting for approval" or "Eligible from" a date) and "Waiting for approval" only when there is one (Role, Comes from, a muted badge). Empty states say what isn't there.
### Request access

- On the 403 page, only when no PIM Activate is offered: one sentence saying the person can ask the vault's owners and that Keyring can't grant access itself, and a primary "Request access" button. Nothing else on the page changes.
- The form follows the activation form: breadcrumb, heading "Request access" with the role muted, one sentence on who gets it, the error summary, then "For" (two radios, this item or the whole vault, only when the page was an item's), "Why you need it" with the note not to type secrets, and "Ticket" marked optional. Primary "Send request" and Cancel.
- The answer is a narrow panel "Sent to the vault's owners", the same for every accepted request, with Back and My access. A repeat within the hour gets a narrow panel "You've already asked". Neither names the owners.
- My access: a "Request access" heading, one sentence, and a list of "Request {role}" links, only when there is a role to request.

### Reason (KEYRING_REQUIRE_REASON)

- When a reason is asked for, the reveal form and each confirmation page get
  a plain text field, "Reason", with field help that says it's recorded with
  the person's name and not to type secrets, passwords or personal details.
  A "Ticket" field follows only when a ticket pattern is set, showing the
  pattern in mono.
- A form that reaches an action without it gets one narrow panel asking
  "Why ...?", with the usual error summary, the same button words as the
  form it came from, and Cancel. It never shows a secret value: a create or
  "set a new value" form, plain or typed, sends the person back to it
  instead.
- No new colours, badges or script. It works as a form post without
  JavaScript.

### Rollback, rotate

Read as "make a new version". The primary button is the accent, never danger.

### Copy to another vault

- A secondary "Copy to another vault" link button on a secret's page,
  disabled with the role named when the hints say the person can't read the
  value. Never shown for a certificate's backing secret.
- The form is one stacked form: a select of the vaults the person can see,
  the name, and a fieldset of plain checkboxes for what to bring, all ticked.
  It is a GET to the review, so nothing is read until the review.
- The review is a narrow panel: a `dl.props` of From and To, then one line on
  what is at the target (a warn notice for a new version, an error notice
  for a deleted name or a certificate's, with no copy button), and a bold
  "The value isn't shown". The primary button names the target vault.

### Change many at once

- The secrets, certificates and keys lists have a first column of plain
  checkboxes, each with a visually hidden "Select {name}" label. Above the
  table, a second toolbar (the `.filters` box, after the filter form, never
  inside it) holds "With selected": the change, tag name and value, expiry
  date where it applies, and a primary **Review changes** button, disabled
  with the role as text when the hint says so.
- The review page is a framed table of names with a badge each (Will
  change, No change, Can't change, Not found) and a muted sentence saying
  exactly what happens. The button is primary, or danger for disable, which
  also asks for the count typed. Cancel is a text link back to the list.
- The results page follows the import results: a count heading, an ok or
  warn notice, and a badge and reason per item.

### Description (the `description` tag)

- Create and edit forms for secrets, certificates and keys have a
  **Description** textarea (optional) after the name, with field help that
  says it is saved as a tag anyone who can see the tags can read, and not to
  type secrets, passwords or personal details. A second help line under it
  says the 256-character limit; the script turns it into a count of
  characters left. It isn't a live region: it is read with the field.
- Certificates and keys get a secondary **Edit details** link button on
  their page, disabled with the role named like the others. Its form is the
  description and the tag rows, nothing else.
- Detail pages show the description under the heading in ink-2, line
  breaks kept (`.item-note`). No label, no box.
- Lists have a Description column after Status, at `--text-caption`, cut to 80
  characters on one line with an ellipsis; the whole note is the cell's
  visually hidden text. "None" in muted when empty, like other cells.
- The tag rows and tag lists never show `description`, `owner` or `notify`.

### Owner and notify (the `owner` and `notify` tags)

- Every form with a Description field has **Owner** and **Notify** text
  inputs straight after it, each with help that says it is saved as a tag
  anyone who can see the tags can read. Owner is "(optional)" unless
  `KEYRING_REQUIRE_OWNER` is on, when its help says so instead. Notify says
  how many addresses it takes. No script.
- A value set elsewhere that isn't plain addresses gets a second help line
  under the field, in ink-2: it was set outside Keyring and is kept unless
  changed. It is read with the field.
- Errors sit under their own field, and name an entry by its place, never
  by quoting it.
- On an item's page, Owner and Notify are rows in the facts list. A parsed
  address is a plain link (`mailto:`); anything else is mono text with
  "(not a plain address)" in muted small text. "None" in muted when empty.
- Lists have an Owner column after Description, on one line with
  "(not a plain address)" as a muted caption suffix that doesn't wrap. The expiry and age pages have no Description column, but have
  an Owner column before Tags, styled the same (`td.owner-cell`), so
  addresses stay out of the Tags text and a link per address works. Notify
  is in their CSVs only: the pages have no room for up to five addresses.
- **Owned by me** is a plain checkbox in the filter row, its help line
  under it, between the last filter and the Filter button.
- The vault list has an Owners column after Location, and a muted line
  above the table saying where the tag is set. Vault health has a "Named
  owners" column after the vault name, and an **Owners** check like the
  others.

### Reveal limit (the `keyring-reveal` tag)

- A **Reveal limit** select after Owner and Notify on a secret's create,
  Set a new value and Edit details forms, and on a certificate's Edit
  details. Never on keys. Options: No limit, Copy only, No reveal (the
  certificate's Copy only says it blocks the private key download). Help
  says what each does, that it is a tag, that the CLI and portal aren't
  limited, and that loosening it asks you to confirm it's you.
- A value set elsewhere adds a first option, "Keep as set elsewhere
  (treated as no reveal)", selected, and a second help line in ink-2
  quoting the tag as set. Same pattern as an odd owner.
- With `KEYRING_REQUIRE_REASON=reveal`, the Reason fields sit under the
  select, with a line saying they are only needed when loosening.
- The secret's page: `none` replaces the Show value form with a plain
  notice (no colour) saying why and what to use instead; Copy to another
  vault is left out. `copy-only` keeps the form, with a muted line above
  it and the button reading **Copy value**. Versions follow the same.
  A Reveal limit row sits in the facts list.
- The reveal page under `copy-only`: a notice under the Value heading
  saying the value isn't shown and is still sent to the browser; only the
  Copy buttons, the countdown and Hide show. No textarea, no Show for
  longer. Driven by markup only: the value is in hidden inputs the existing
  script already reads.
- A refused reveal, copy or download is the standard problem page,
  heading "Not shown in Keyring", with a Details line saying it is a
  Keyring control.
- A certificate with any limit: no **Download with private key** button,
  and a plain notice above the actions. Public downloads stay.

### Tags (rows, suggestions, links)

- On every form that sets tags, a `fieldset.tag-rows` with the legend
  **Tags (optional)**, a help line, then one row per tag: a name input and a
  value input side by side (`.tag-row`, wrapping on a small screen), each
  with a visible label "Tag n name" and "Tag n value", in the mono face.
  Three empty rows follow the item's tags. A row's error sits under its own
  input and the summary links to it.
- Tags a row can't show (a line break in them) are listed under the help
  line in mono, with a line saying they are kept as they are.
- Suggestions are native `<datalist>` dropdowns: no custom menu, no script
  needed.
- With the script, each row ends in a small secondary **Remove** button
  (its tag number visually hidden), and a small secondary **Add a tag**
  button follows the rows. Removing moves focus to Add; adding focuses the
  new name.
- On an item's page, tags are a wrapping list of `.tag` chips, each a link
  in ink with an accent border and underline on hover and focus. A tag the
  filter can't find again stays a plain chip.
- Filter boxes for tags (and the search box) suggest `name` and
  `name=value` with a `<datalist>`. Never `description`, `owner` or
  `notify`, though the filters find `owner` and `notify` when typed.

### Pinned and recently opened

- Kept in the browser by `static/pins.js`, never on the server. Without
  JavaScript, or when the browser refuses `localStorage`, nothing shows and
  nothing changes.
- A small **Pin** button (`button.pin-button`) sits in the title row of
  each vault list page (secrets, certificates, keys) and each secret,
  certificate and key page. It looks like a command bar button: no frame,
  a 14px accent star and the label. It has `aria-pressed` and a visually
  hidden item name. The star is an outline when off; pinned, it is filled
  and the button gets the accent tint and rule, so state isn't colour
  alone.
- The home page and the vault list show **Pinned** and **Recently opened**
  (last 10) in one compact white card straight after the page header
  (after the description and About, before the command bar), never above
  the description. Each is a caption-size `h2` and a wrapping row of
  resource-name links with the kind and vault muted after them. Only when
  non-empty.
- The card's last line, muted, says the list is kept in this browser only
  and is cleared on sign-out, with a **Clear** text button.

### Share picker

- On the Share form only, `static/share.js` turns the "Share with" box into
  a search. Results are a plain bordered list (`ul.share-results`) of
  `.button-link` rows under the box: the name and type in ink, the address
  muted after them. Picking one fills the box and a hidden object ID.
- A polite status line under the box says how many were found, or why the
  directory couldn't be searched. Without JavaScript the box takes an exact
  email address or object ID and nothing else changes.
- The secret's **Shared with** section is a ledger table under Used by. A
  share past its date has the danger **Overdue** badge; Revoke is a
  secondary button that opens a typed-name confirmation.

## Interaction behaviours

`static/behaviors.js` adds keyboard behaviour to markup that already works
without script. The model is Vercel's UI SDK (github.com/vercel-labs/ui,
Apache-2.0, https://ui-sdk.dev/docs), re-implemented by hand: no npm, no
vendored code. Each behaviour attaches by a data attribute.

| Behaviour | Where | Keys | ARIA |
| --- | --- | --- | --- |
| Menu | `details[data-behavior="menu"]`: the More menu on secret, certificate and key pages | Enter or Space on the summary opens it and focuses the first item. Arrow Down or Up on the summary opens it at the first or last item. Arrow Up and Down, Home and End move between items, skipping disabled ones. Letters jump to the next item that starts with them. Escape closes it and returns focus to the summary. A click outside or Tab away closes it | A disclosure, not `role="menu"`: the items are links and forms, so they keep their own roles. The summary has `aria-expanded` |
| Combobox | The share picker's "Share with" box | Arrow Down and Up open the results and move the highlight. Enter picks the highlighted one. Alt+Arrow Down opens without moving, Alt+Arrow Up closes. Escape closes the list, then a second Escape clears the box. Tab closes it | `role="combobox"`, `aria-expanded`, `aria-controls`, `aria-autocomplete="list"` and `aria-activedescendant` on the box; `role="listbox"` on the list and `role="option"` with `aria-selected` on each result. The count is said in the existing polite status line |
| Focus recovery | Removing a tag row | Focus moves to the next row's Remove, else the one before, else Add a tag | None |
| Tabs | The tab strip on item pages | None added: Tab moves between them | A `nav` of links with `aria-current="page"`. They are links to separate pages, so this is navigation, not an ARIA tabs widget, and arrow keys are left to the browser |

- Without script, the menus are `<details>` elements, the share picker takes
  an exact email address or object ID, and tag rows post as they are.
- The highlighted option has a 2px accent outline and a tint, since focus
  stays in the box.
- The tag name and tag value pickers stay native `<datalist>` inputs: the
  browser already gives them a combobox role, arrow keys and Escape, with
  no script. `static/tags.js` only swaps a row's list.
- The vault switcher in the top bar is a link to the vault list, not a
  menu, so it needs no behaviour.
- The revealed value's Hide already moves focus to the Hide link
  (`static/app.js`), so it is unchanged.

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
  glyphs are drawn in `CanvasText`, and the current nav item, open tab and
  open view keep `Highlight` and an underline.
- The breadcrumb is a `nav` with `aria-label="Breadcrumb"`; its last item
  carries `aria-current="page"`. One h1 per page; headings in order.
- Targets are at least 24 by 24px. Menus are `<details>`, so they open with
  Enter or Space and need no script.
- `@media print` hides `[data-secret-value]`.
- No inline styles, no `<style>` blocks, no fonts from other sites, no images or data: URIs. Icons
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
  --color-chrome-2: oklch(32% 0.02 250);
  --font-body: "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
  --font-mono: ui-monospace, "Cascadia Mono", Consolas, SFMono-Regular, Menlo, monospace;
  --text-caption: 0.75rem; --lh-caption: 1rem;
  --text-body: 0.875rem; --lh-body: 1.25rem;
  --text-mono: 0.8125rem; --lh-mono: 1.25rem;
  --text-subtitle: 1rem; --lh-subtitle: 1.375rem;
  --text-title: 1.25rem; --lh-title: 1.75rem;
  --text-large: 1.5rem; --lh-large: 2rem;
  --space-3xs: 0.25rem; --space-2xs: 0.5rem; --space-xs: 0.75rem;
  --space-sm: 1rem; --space-md: 1.5rem; --space-lg: 2rem; --space-xl: 3rem;
  --control-h: 2rem; --control-h-sm: 1.5rem;
  --radius: 4px; --radius-sm: 2px;
}
```
