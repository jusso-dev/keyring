#!/usr/bin/env python3
"""Draws the threat model diagram used by the README and docs/threat-model.md.

Outputs docs/images/threat-model.svg and, when rsvg-convert is on PATH, a 1.5x
docs/images/threat-model.png for the PDF and Word editions.

T-numbers match the STRIDE register in docs/design/08-security-design.md and
the table in docs/threat-model.md. Python 3 standard library only.
"""
import os
import shutil
import subprocess
from html import escape

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SVG = os.path.join(ROOT, "docs", "images", "threat-model.svg")
PNG = os.path.join(ROOT, "docs", "images", "threat-model.png")

# design.md tokens, as in docs/diagrams/drawio/build_drawio.py
INK, INK2 = "#1c222a", "#515963"
PAPER, SURFACE = "#f5f7fa", "#ffffff"
RULE, RULE_STRONG = "#dadee3", "#737b84"
ACCENT, ACCENT_TINT = "#186575", "#e3f4f8"
WARN, WARN_TINT = "#804d0c", "#fdf2dd"
DANGER, DANGER_TINT = "#b02a2d", "#fcf1ef"
OK_TINT = "#e3f8e9"
FONT = "-apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"

PERSON = ACCENT    # the signed-in person's own tokens
IDENTITY = WARN    # Keyring's managed identity
INBOUND = DANGER   # Event Grid's delivery, and the attacker
PLAIN = INK2       # browser traffic and calls inside Keyring

W, H = 1564, 850
ROW0, ROW_STEP, ROW_H = 160, 102, 86
LX, LW = 372, 240    # Keyring, left column
RX, RW = 652, 250    # Keyring, right column
AX, AW = 1080, 448    # Microsoft cloud
PX, PW = 24, 284     # people and attackers
TB1, TB2 = 332, 1036  # trust boundaries
ZONE_H = 700         # zones run from y=96; boundary labels sit below them

parts = []


def row(i):
    return ROW0 + i * ROW_STEP


def text(x, y, s, size=12, colour=INK, weight="normal", anchor="start", extra=""):
    parts.append(f'<text x="{x}" y="{y}" font-size="{size}" fill="{colour}" font-weight="{weight}" '
                 f'text-anchor="{anchor}" {extra}>{escape(s)}</text>')


def badges(x_right, y, ids):
    x = x_right - 8
    for tid in reversed(ids):
        w = 12 + 7.2 * len(tid)
        x -= w
        parts.append(f'<rect x="{x:.1f}" y="{y - 10}" width="{w:.1f}" height="20" rx="10" fill="{DANGER}" '
                     f'stroke="#ffffff" stroke-width="1.5"/>')
        text(f"{x + w / 2:.1f}", y + 4, tid, 11, "#ffffff", "bold", "middle")
        x -= 4


def card(x, y, w, h, title, lines, threats=(), fill=SURFACE, stroke=RULE_STRONG, dashed=False, title_colour=INK):
    dash = ' stroke-dasharray="6 4"' if dashed else ""
    parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{fill}" stroke="{stroke}" '
                 f'stroke-width="1.3"{dash}/>')
    text(x + 12, y + 26, title, 14, title_colour, "bold")
    for n, line in enumerate(lines):
        # Keep every line inside its card at 12px (about 6.3px a character).
        assert len(line) * 6.3 < w - 20, f"line too long for its card: {line!r}"
        text(x + 12, y + 46 + n * 17, line, 12, INK2)
    if threats:
        badges(x + w, y, threats)


def zone(x, y, w, h, title, sub, fill):
    parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{fill}" stroke="{RULE}" '
                 f'stroke-width="1.3"/>')
    text(x + 16, y + 26, title, 15, INK, "bold")
    text(x + 16, y + 45, sub, 12, INK2)


def arrow(points, colour, dashed=False, label=None, label_at=None):
    d = "M " + " L ".join(f"{px} {py}" for px, py in points)
    dash = ' stroke-dasharray="7 5"' if dashed else ""
    marker = {PERSON: "a-person", IDENTITY: "a-identity", INBOUND: "a-inbound"}.get(colour, "a-plain")
    parts.append(f'<path d="{d}" fill="none" stroke="{colour}" stroke-width="2"{dash} marker-end="url(#{marker})"/>')
    if label:
        lx, ly = label_at
        w = 6.4 * len(label) + 10
        parts.append(f'<rect x="{lx - w / 2:.1f}" y="{ly - 12}" width="{w:.1f}" height="17" rx="4" fill="#ffffff"/>')
        text(lx, ly, label, 11, colour, "bold", "middle")


def boundary(x, label):
    parts.append(f'<line x1="{x}" y1="96" x2="{x}" y2="{H - 40}" stroke="{DANGER}" stroke-width="2" '
                 f'stroke-dasharray="9 6"/>')
    text(x, H - 18, label, 11.5, DANGER, "bold", "middle")


def build():
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" '
        f'aria-labelledby="tm-title tm-desc" font-family="{FONT}">')
    parts.append('<title id="tm-title">Keyring threat model</title>')
    parts.append(
        '<desc id="tm-desc">Three zones: people and attackers on the internet, Keyring in your Azure subscription, '
        'and the Microsoft cloud. Two trust boundaries separate them. Every call that reads or changes a vault '
        'carries the signed-in person\'s on-behalf-of token; Keyring\'s managed identity only writes audit rows '
        'and sends email. Red T-numbers mark where each threat in the STRIDE table is stopped.</desc>')
    parts.append("<defs>")
    for name, colour in (("a-person", PERSON), ("a-identity", IDENTITY), ("a-inbound", INBOUND), ("a-plain", PLAIN)):
        parts.append(f'<marker id="{name}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
                     f'orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="{colour}"/></marker>')
    parts.append("</defs>")
    parts.append(f'<rect width="{W}" height="{H}" fill="#ffffff"/>')

    text(24, 44, "Keyring threat model", 24, INK, "bold")
    text(24, 70, "Trust boundaries, data flows and where each threat is stopped. Red T-numbers match the STRIDE "
         "table in docs/threat-model.md.", 13, INK2)

    zone(PX - 8, 96, PW + 16, ZONE_H, "Trusted networks only", "VPN, ExpressRoute or allowed IPs only", PAPER)
    zone(352, 96, 570, ZONE_H, "Keyring, in your Azure subscription",
         "Holds tokens in memory, stores nothing, has no vault access of its own", ACCENT_TINT)
    zone(AX - 12, 96, AW + 24, ZONE_H, "Microsoft cloud", "Makes every authorisation decision, as the person",
         PAPER)

    # People and attackers
    card(PX, row(0), PW, ROW_H, "Web browser", ["Holds a random session ID only.", "Never sees a token."],
         ["T2", "T13"])
    card(PX, row(1) + 30, PW, ROW_H, "Attacker",
         ["Stolen cookie, forged forms, crafted", "names and text, floods of requests"],
         ["T4", "T5", "T14", "T21"], fill=DANGER_TINT, stroke=DANGER, dashed=True, title_colour=DANGER)

    # Keyring, left column
    card(LX, row(0), LW, ROW_H, "Request edge", ["Private or trusted IPs only, CSP,", "Origin and form token, limits"],
         ["T5", "T14", "T21", "T39"])
    card(LX, row(1), LW, ROW_H, "Gates before any Azure call",
         ["Typed names, purge off, step-up,", "reason, reveal limits, safe KQL"], ["T15", "T18", "T28"])
    card(LX, row(2), LW, ROW_H, "Values in memory only",
         ["Redacted and zeroised, never", "logged, no-store on every page"], ["T12", "T13", "T19"])
    card(LX, row(3), LW, ROW_H + ROW_STEP, "Keyring's managed identity",
         ["Proves Keyring is the app,", "writes audit rows, sends email.", "", "No role on any vault or",
          "workspace. App registration", "is delegated-only."], ["T3", "T6", "T7"], fill=WARN_TINT, stroke=WARN)
    card(LX, row(5), LW, ROW_H, "Build and runtime",
         ["Distroless, non-root, read-only,", "no unsafe code, pinned crates"], ["T23"])

    # Keyring, right column
    card(RX, row(0), RW, ROW_H, "Sign-in and sessions",
         ["OIDC with PKCE, state and nonce.", "Memory-only, 1 h idle, 12 h max"], ["T2", "T4"])
    card(RX, row(1), RW, ROW_H + ROW_STEP, "Azure clients",
         ["Every call that reads or changes", "a vault carries the signed-in", "person's on-behalf-of token.", "",
          "Shares are made as the person,", "so Azure decides."], ["T1", "T17", "T29"])
    card(RX, row(3), RW, ROW_H, "Audit events",
         ["One per action, refusals included.", "Optional sink to KeyringAudit_CL"], ["T20"])
    card(RX, row(4), RW, ROW_H, "Email sender",
         ["Allow-list, per-recipient limits,", "fixed text, never a value"], ["T8", "T9"])
    card(RX, row(5), RW, ROW_H, "Event Grid webhook",
         ["App-only Entra token, topic and", "subscription checks, size limits"], ["T10", "T11"])

    # Microsoft cloud
    card(AX, row(0), AW, ROW_H, "Microsoft Entra ID",
         ["Sign-in, MFA and Conditional Access; issues the", "on-behalf-of tokens for each Azure service"])
    card(AX, row(1), AW, ROW_H, "Azure Key Vault",
         ["RBAC or access policies decide every request.", "Its own diagnostic log records every call"])
    card(AX, row(2), AW, ROW_H, "ARM, Resource Graph, Log Analytics, Graph",
         ["Read and changed as the person. Graph only", "with sharing on, to find people by name"])
    card(AX, row(3), AW, ROW_H, "Logs Ingestion API (audit sink)",
         ["Monitoring Metrics Publisher on one rule:", "append-only, can't read or delete rows"])
    card(AX, row(4), AW, ROW_H, "Azure Communication Services",
         ["Custom role, Read and Write on one resource", "in Keyring's own resource group; no keys"])
    card(AX, row(5), AW, ROW_H, "Azure Event Grid",
         ["Only for a self-built public front end;", "templates send expiry via action groups"])

    mid = ROW_H // 2
    LABEL_X = (RX + RW + TB2) // 2
    # Browser and attacker into the request edge
    arrow([(PX + PW, row(0) + 30), (LX, row(0) + 30)], PLAIN)
    arrow([(PX + PW, row(1) + 30 + mid), (342, row(1) + 30 + mid), (342, row(0) + 64), (LX, row(0) + 64)],
          INBOUND, dashed=True)
    # Inside Keyring
    arrow([(LX + LW, row(0) + mid), (RX, row(0) + mid)], PLAIN)
    arrow([(LX + LW, row(1) + mid), (RX, row(1) + mid)], PLAIN)
    arrow([(LX + LW, row(3) + mid), (RX, row(3) + mid)], IDENTITY)
    arrow([(LX + LW, row(4) + mid), (RX, row(4) + mid)], IDENTITY)
    # Out to Microsoft cloud
    arrow([(RX + RW, row(0) + mid), (AX, row(0) + mid)], PERSON, label="person's token", label_at=(LABEL_X, row(0) + mid - 8))
    arrow([(RX + RW, row(1) + mid), (AX, row(1) + mid)], PERSON, label="on-behalf-of", label_at=(LABEL_X, row(1) + mid - 8))
    arrow([(RX + RW, row(2) + 20), (AX, row(2) + 20)], PERSON)
    arrow([(RX + RW, row(3) + mid), (AX, row(3) + mid)], IDENTITY, label="managed identity",
          label_at=(LABEL_X, row(3) + mid - 8))
    arrow([(RX + RW, row(4) + mid), (AX, row(4) + mid)], IDENTITY)
    arrow([(AX, row(5) + mid), (RX + RW, row(5) + mid)], INBOUND, label="signed delivery",
          label_at=(LABEL_X, row(5) + mid - 8))

    boundary(TB1, "Trust boundary: no public internet (T39)")
    boundary(TB2, "Trust boundary: Keyring to Azure")

    # Legend
    lx, ly = PX, row(3) + 6
    parts.append(f'<rect x="{lx}" y="{ly}" width="{PW}" height="{96 + ZONE_H - ly - 12}" rx="8" fill="#ffffff" '
                 f'stroke="{RULE}" stroke-width="1.3"/>')
    text(lx + 12, ly + 24, "Legend", 13, INK, "bold")
    items = [
        (PERSON, False, "Signed-in person's own token"),
        (IDENTITY, False, "Keyring's managed identity"),
        (INBOUND, False, "Event Grid (not in templates)"),
        (INBOUND, True, "Attacker's requests"),
        (PLAIN, False, "Browser traffic and inside Keyring"),
    ]
    for n, (colour, dashed, label) in enumerate(items):
        y = ly + 48 + n * 24
        arrow([(lx + 14, y - 4), (lx + 58, y - 4)], colour, dashed)
        text(lx + 70, y, label, 12, INK)
    y = ly + 48 + len(items) * 24
    parts.append(f'<line x1="{lx + 14}" y1="{y - 4}" x2="{lx + 58}" y2="{y - 4}" stroke="{DANGER}" '
                 f'stroke-width="2" stroke-dasharray="9 6"/>')
    text(lx + 70, y, "Trust boundary", 12, INK)
    y += 26
    badges(lx + 58 + 8, y - 4, ["T1"])
    text(lx + 70, y, "Threat, stopped here (see table)", 12, INK)

    parts.append("</svg>")
    with open(SVG, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(parts) + "\n")
    print(f"wrote {os.path.relpath(SVG, ROOT)}")

    if shutil.which("rsvg-convert"):
        subprocess.run(["rsvg-convert", "-z", "1.5", "-o", PNG, SVG], check=True)
        if shutil.which("pngquant"):
            subprocess.run(["pngquant", "--quality=80-95", "--speed", "1", "--strip", "--force", "--output", PNG,
                            PNG], check=True)
        print(f"wrote {os.path.relpath(PNG, ROOT)}")
    else:
        print("rsvg-convert not found: PNG not written")


if __name__ == "__main__":
    build()
