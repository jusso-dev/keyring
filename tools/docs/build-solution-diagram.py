#!/usr/bin/env python3
"""Builds the Keyring Enterprise Solution Architecture and SOC Logging & Telemetry
diagrams using official Microsoft Azure icons extracted from the repository's
exported draw.io SVGs.

Outputs:
  - docs/diagrams/drawio/export/00-solution-architecture.{svg,png}
  - docs/diagrams/drawio/export/07-soc-logging-telemetry.{svg,png}
  - /tmp/keyring-diagrams-inline.html  (theme-adaptive preview of both diagrams)

Python 3 standard library only (plus Playwright via npx for 2x PNG rasterisation).
"""
import glob
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from html import escape

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DRAWIO = os.path.join(ROOT, "docs", "diagrams", "drawio", "keyring-design.drawio")
EXPORT_DIR = os.path.join(ROOT, "docs", "diagrams", "drawio", "export")

SOL_SVG = os.path.join(EXPORT_DIR, "00-solution-architecture.svg")
SOL_PNG = os.path.join(EXPORT_DIR, "00-solution-architecture.png")
SOC_SVG = os.path.join(EXPORT_DIR, "07-soc-logging-telemetry.svg")
SOC_PNG = os.path.join(EXPORT_DIR, "07-soc-logging-telemetry.png")
INLINE_HTML = "/tmp/keyring-diagrams-inline.html"

# Palette aligned with Keyring's CyberArk-inspired PAM design system
BG = "#ffffff"
CANVAS = "#f5f7fb"
NAVY = "#0d1a2e"
INK = "#162133"
INK2 = "#4b5a72"
RULE = "#d4dce8"

BLUE = "#0e5ae5"
BLUE_SOFT = "#eef4ff"
BLUE_RULE = "#8ab4f8"

AMBER = "#b45309"
AMBER_SOFT = "#fff7ed"
AMBER_RULE = "#f3b36d"

CRIMSON = "#c81e32"
CRIMSON_SOFT = "#fef2f2"
CRIMSON_RULE = "#f2a4ad"

EMERALD = "#117a49"
EMERALD_SOFT = "#ecfdf3"
EMERALD_RULE = "#86d7ad"

PURPLE = "#6d28d9"
PURPLE_SOFT = "#f5f3ff"
PURPLE_RULE = "#c4b5fd"

SLATE_SOFT = "#f8fafd"


def extract_azure_icons():
    """Extract all official Microsoft Azure SVG data URIs from draw.io's exported SVGs."""
    tree = ET.parse(DRAWIO)
    icons = {}
    for idx, diag in enumerate(tree.findall("diagram")):
        svg_files = sorted(glob.glob(os.path.join(EXPORT_DIR, f"{idx + 1:02d}-*.svg")))
        if not svg_files:
            continue
        svg_txt = open(svg_files[0], encoding="utf-8").read()

        defs_by_id = {}
        defs_m = re.search(r"<defs>(.*?)</defs>", svg_txt, flags=re.S)
        if defs_m:
            defs_txt = defs_m.group(1)
            for tag in ("symbol", "g"):
                for m in re.finditer(rf'<{tag}\b[^>]*\bid="([^"]+)"[^>]*>(.*?)</{tag}>', defs_txt, flags=re.S):
                    uri = re.search(r'(?:xlink:)?href="(data:image/svg\+xml;base64,[A-Za-z0-9+/=]+)"', m.group(2))
                    if uri:
                        defs_by_id[m.group(1)] = uri.group(1)
            for m in re.finditer(r"<image\b([^>]*)>", defs_txt):
                attrs = m.group(1)
                iid = re.search(r'\bid="([^"]+)"', attrs)
                uri = re.search(r'(?:xlink:)?href="(data:image/svg\+xml;base64,[A-Za-z0-9+/=]+)"', attrs)
                if iid and uri:
                    defs_by_id[iid.group(1)] = uri.group(1)

        rendered = []
        body = re.sub(r"<defs>.*?</defs>", "", svg_txt, flags=re.S)
        for m in re.finditer(r"<(image|use)\b([^>]*)>", body):
            tag, attrs = m.group(1), m.group(2)
            if tag == "image":
                uri = re.search(r'(?:xlink:)?href="(data:image/svg\+xml;base64,[A-Za-z0-9+/=]+)"', attrs)
                if uri:
                    rendered.append(uri.group(1))
            else:
                ref = re.search(r'(?:xlink:)?href="#([^"]+)"', attrs)
                if ref and ref.group(1) in defs_by_id:
                    rendered.append(defs_by_id[ref.group(1)])

        drawio_icons = [
            re.search(r"image=img/lib/azure2/([^;]+)", c.attrib.get("style", "")).group(1)
            for c in diag.findall(".//mxCell")
            if "image=img/lib/azure2/" in c.attrib.get("style", "")
        ]
        if len(drawio_icons) == len(rendered):
            for name, uri in zip(drawio_icons, rendered):
                icons[name] = uri
    return icons


def svg_preamble(W, H, title_id, title_text, desc_text, header_title, header_sub, pill_text, top_color=BLUE):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-labelledby="{title_id}-t {title_id}-d">
  <title id="{title_id}-t">{escape(title_text)}</title>
  <desc id="{title_id}-d">{escape(desc_text)}</desc>
  <defs>
    <style>
      .t-title {{ font: 700 22px -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Helvetica, Arial, sans-serif; fill: {INK}; letter-spacing: -0.02em; }}
      .t-sub {{ font: 400 12.5px -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Helvetica, Arial, sans-serif; fill: {INK2}; }}
      .t-zone {{ font: 700 11.5px -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Helvetica, Arial, sans-serif; fill: {INK}; text-transform: uppercase; letter-spacing: 0.055em; }}
      .t-zsub {{ font: 400 11px -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Helvetica, Arial, sans-serif; fill: {INK2}; }}
      .t-card {{ font: 600 12px -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Helvetica, Arial, sans-serif; fill: {INK}; }}
      .t-csub {{ font: 400 10.5px -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Helvetica, Arial, sans-serif; fill: {INK2}; }}
      .t-badge {{ font: 700 9px -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Helvetica, Arial, sans-serif; letter-spacing: 0.04em; }}
      .t-edge {{ font: 600 10px -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Helvetica, Arial, sans-serif; }}
      .t-mono {{ font: 500 10px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; fill: {INK2}; }}
      .t-leg {{ font: 500 11px -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Helvetica, Arial, sans-serif; fill: {INK}; }}
    </style>
    <filter id="{title_id}-sh" x="-4%" y="-6%" width="108%" height="118%">
      <feDropShadow dx="0" dy="1.5" stdDeviation="2.5" flood-color="#0d1a2e" flood-opacity="0.06"/>
    </filter>
    <marker id="{title_id}-ab" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1.2 L 9 5 L 0 8.8 z" fill="{BLUE}"/>
    </marker>
    <marker id="{title_id}-aa" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1.2 L 9 5 L 0 8.8 z" fill="{AMBER}"/>
    </marker>
    <marker id="{title_id}-ac" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1.2 L 9 5 L 0 8.8 z" fill="{CRIMSON}"/>
    </marker>
    <marker id="{title_id}-ae" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1.2 L 9 5 L 0 8.8 z" fill="{EMERALD}"/>
    </marker>
    <marker id="{title_id}-ap" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1.2 L 9 5 L 0 8.8 z" fill="{PURPLE}"/>
    </marker>
    <marker id="{title_id}-as" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1.2 L 9 5 L 0 8.8 z" fill="{NAVY}"/>
    </marker>
  </defs>
  <rect x="0" y="0" width="{W}" height="{H}" rx="12" fill="{BG}"/>
  <rect x="0" y="0" width="{W}" height="5" fill="{top_color}"/>
  <text x="28" y="37" class="t-title">{escape(header_title)}</text>
  <text x="28" y="56" class="t-sub">{escape(header_sub)}</text>
  <rect x="{W - 268}" y="19" width="240" height="32" rx="16" fill="{NAVY}"/>
  <text x="{W - 148}" y="39" text-anchor="middle" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="11.5" font-weight="600" fill="#ffffff">{escape(pill_text)}</text>
  <line x1="28" y1="70" x2="{W - 28}" y2="70" stroke="{RULE}" stroke-width="1"/>
'''


def make_helpers(parts, icons, tid):
    def ico(key):
        if key not in icons:
            raise KeyError(f"Missing Azure icon {key}; available: {sorted(icons)}")
        return icons[key]

    def zone(x, y, w, h, title, sub, fill=CANVAS, stroke=RULE, accent=None, dashed=False):
        dash = ' stroke-dasharray="6 4"' if dashed else ""
        parts.append(f'  <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{fill}" stroke="{stroke}" stroke-width="1.25"{dash}/>')
        if accent:
            parts.append(f'  <rect x="{x}" y="{y}" width="{w}" height="4" rx="2" fill="{accent}"/>')
        parts.append(f'  <text x="{x + 14}" y="{y + 22}" class="t-zone">{escape(title)}</text>')
        if sub:
            parts.append(f'  <text x="{x + 14}" y="{y + 37}" class="t-zsub">{escape(sub)}</text>')

    def card(x, y, w, h, icon_key, title, line1="", line2="", fill="#ffffff", stroke=RULE, badge=None, badge_fill=BLUE_SOFT, badge_fg=BLUE):
        parts.append(f'  <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{fill}" stroke="{stroke}" stroke-width="1.15" filter="url(#{tid}-sh)"/>')
        if icon_key:
            parts.append(f'  <image x="{x + 11}" y="{y + (h - 34)/2:.1f}" width="34" height="34" xlink:href="{ico(icon_key)}"/>')
            tx = x + 54
        else:
            tx = x + 14
        ty = y + (22 if line2 else 25)
        parts.append(f'  <text x="{tx}" y="{ty}" class="t-card">{escape(title)}</text>')
        if line1:
            parts.append(f'  <text x="{tx}" y="{ty + 15}" class="t-csub">{escape(line1)}</text>')
        if line2:
            parts.append(f'  <text x="{tx}" y="{ty + 29}" class="t-csub">{escape(line2)}</text>')
        if badge:
            bw = max(44, len(badge) * 5.9 + 14)
            bx = x + w - bw - 8
            by = y + 8
            parts.append(f'  <rect x="{bx:.1f}" y="{by}" width="{bw:.1f}" height="17" rx="8.5" fill="{badge_fill}" stroke="{badge_fg}" stroke-opacity="0.35" stroke-width="1"/>')
            parts.append(f'  <text x="{bx + bw/2:.1f}" y="{by + 11.8}" text-anchor="middle" class="t-badge" fill="{badge_fg}">{escape(badge)}</text>')

    def edge_label(x, y, text, color, bg="#ffffff"):
        tw = len(text) * 5.8 + 14
        parts.append(f'  <rect x="{x - tw/2:.1f}" y="{y - 9.5}" width="{tw:.1f}" height="18" rx="4" fill="{bg}" stroke="{color}" stroke-opacity="0.35" stroke-width="1"/>')
        parts.append(f'  <text x="{x:.1f}" y="{y + 3}" text-anchor="middle" class="t-edge" fill="{color}">{escape(text)}</text>')

    return ico, zone, card, edge_label


def build_solution_svg(icons):
    W, H = 1480, 920
    tid = "sol"
    parts = [svg_preamble(
        W, H, tid,
        "Keyring Enterprise Solution Architecture",
        "End-to-end Azure solution architecture for Keyring showing users, Microsoft Entra ID OIDC and OBO authentication, stateless Keyring runtime on App Service or Container Apps with a single managed identity, multi-environment Azure Key Vaults (dev, test, prod) over Private Endpoints, and audit, Microsoft Sentinel, Event Grid and Azure Communication Services integrations.",
        "Keyring: Enterprise Solution Architecture",
        "Stateless Rust PAM front end for Azure Key Vault · Multi-environment governance (Dev / Test / Prod) · Zero stored credentials",
        "Zero Vault Identity · 100% OBO",
        top_color=BLUE,
    )]
    a = parts.append
    ico, zone, card, edge_label = make_helpers(parts, icons, tid)

    # ZONE 1 (LEFT): People & Browsers + Inbound Event Grid + Zero-Storage Callout
    zone(24, 88, 240, 372, "People & Browsers", "Zero tokens in browser", fill=SLATE_SOFT, accent=NAVY)
    card(38, 140, 212, 70, "identity/Users.svg", "Enterprise Users", "Developers, Platform Ops,", "Security & Auditors")
    card(38, 224, 212, 70, "general/Browser.svg", "Web Browser", "Server HTML + strict CSP", "Random http-only session ID")
    a(f'  <rect x="38" y="308" width="212" height="136" rx="8" fill="#ffffff" stroke="{RULE}" stroke-width="1"/>')
    a(f'  <text x="50" y="330" class="t-card">Client-side guarantees</text>')
    a(f'  <text x="50" y="350" class="t-csub">• Session cookie only (256-bit)</text>')
    a(f'  <text x="50" y="367" class="t-csub">• Zero Entra/KV tokens in JS</text>')
    a(f'  <text x="50" y="384" class="t-csub">• 30s reveal auto-hide +</text>')
    a(f'  <text x="58" y="399" class="t-csub">clipboard clear on copy</text>')
    a(f'  <text x="50" y="416" class="t-csub">• Pins in localStorage (names)</text>')
    a(f'  <text x="50" y="433" class="t-csub">• Print CSS hides values</text>')

    zone(24, 480, 240, 172, "Inbound Push (Optional)", "Entra JWT verified · No session", fill=CRIMSON_SOFT, stroke=CRIMSON_RULE, accent=CRIMSON)
    card(38, 532, 212, 102, "integration/Event_Grid_Topics.svg", "Azure Event Grid", "*NearExpiry & *Expired push", "to POST /hooks/eventgrid")

    a(f'  <rect x="24" y="672" width="240" height="166" rx="10" fill="{NAVY}"/>')
    a(f'  <text x="40" y="698" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="11" font-weight="700" fill="#93c5fd" letter-spacing="0.06em">ZERO-STORAGE PAM</text>')
    a(f'  <text x="40" y="720" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="11" fill="#e2e8f0">• No database or disk state</text>')
    a(f'  <text x="40" y="739" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="11" fill="#e2e8f0">• Secret values pass in memory</text>')
    a(f'  <text x="48" y="754" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="11" fill="#e2e8f0">only, zeroised on drop</text>')
    a(f'  <text x="40" y="773" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="11" fill="#e2e8f0">• Never logged (TRACE-tested)</text>')
    a(f'  <text x="40" y="792" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="11" fill="#e2e8f0">• Key Vault RBAC decides every</text>')
    a(f'  <text x="48" y="807" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="11" fill="#e2e8f0">read and write action</text>')
    a(f'  <text x="40" y="826" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="11" fill="#93c5fd">• Restart cleanly drops sessions</text>')

    # ZONE 2 (TOP CENTRE): Microsoft Entra ID
    zone(324, 88, 532, 206, "Microsoft Entra ID (Single Tenant)", "Authentication, Conditional Access, Delegated OBO & PIM", fill=BLUE_SOFT, stroke=BLUE_RULE, accent=BLUE)
    card(340, 138, 244, 66, "identity/Azure_Active_Directory.svg", "Microsoft Entra ID", "OIDC + PKCE sign-in, ID token", "verification & OBO broker")
    card(596, 138, 244, 66, "identity/App_Registrations.svg", "App Registration", "Delegated scopes only;", "trusts federated Managed ID")
    card(340, 214, 244, 66, "security/Conditional_Access.svg", "Conditional Access", "MFA enforcement & step-up", "auth contexts (acrs) on reveal")
    card(596, 214, 244, 66, "identity/Entra_Privileged_Identity_Management.svg", "Entra PIM", "Just-in-time role activation", "& time-bound secret sharing")

    # ZONE 3 (BOTTOM CENTRE): Keyring Hosting Resource Group
    zone(324, 344, 532, 494, "Keyring Hosting Resource Group", "Single 8 MB Rust container (Axum + Askama, forbid(unsafe_code), zero npm)", fill=CANVAS, stroke=RULE, accent=NAVY)
    card(340, 394, 244, 68, "app_services/App_Services.svg", "App Service", "HTTPS only, /healthz probe,", "VNet integration & sticky", badge="PATH A")
    card(596, 394, 244, 68, "other/Worker_Container_App.svg", "Container Apps", "Serverless/internal ingress,", "sticky sessions > 1 replica", badge="PATH B")

    a(f'  <rect x="340" y="476" width="500" height="104" rx="8" fill="#ffffff" stroke="{BLUE_RULE}" stroke-width="1.25" filter="url(#{tid}-sh)"/>')
    a(f'  <text x="354" y="497" class="t-card">In-Process Security Controls &amp; Multi-Environment Engine</text>')
    a(f'  <text x="354" y="516" class="t-csub">• Pre-Azure guards: Origin check, vault-bound CSRF, typed delete name, purge off</text>')
    a(f'  <text x="354" y="533" class="t-csub">• Governance gates: Step-up acrs, Reason/Ticket, Password policy, Owner, Reveal limit</text>')
    a(f'  <text x="354" y="550" class="t-csub">• Multi-Env Matrix &amp; Writer: Value-blind dev/test/prod parity &amp; duplicate guard</text>')
    a(f'  <text x="354" y="567" class="t-csub">• In-memory sessions: Per-user OBO cache &amp; 60s metadata cache (zero shared state)</text>')

    card(340, 594, 244, 74, "identity/Managed_Identities.svg", "Managed Identity", "3 uses: Federated cred,", "Audit sink & ACS email", fill=AMBER_SOFT, stroke=AMBER_RULE, badge="NO RBAC", badge_fill="#ffffff", badge_fg=AMBER)
    card(596, 594, 244, 74, "security/Key_Vaults.svg", "Config Key Vault", "Keyring's SESSION_SECRET", "(soft delete + purge prot.)")
    card(340, 682, 244, 70, "networking/Private_Endpoint.svg", "VNet & Private Link", "Optional outbound VNet", "& inbound private ingress")
    card(596, 682, 244, 70, "containers/Container_Registries.svg", "Container Registry", "Distroless static image,", "non-root, read-only rootfs")

    a(f'  <rect x="340" y="766" width="500" height="56" rx="7" fill="{EMERALD_SOFT}" stroke="{EMERALD_RULE}" stroke-width="1"/>')
    a(f'  <text x="354" y="787" class="t-card" fill="{EMERALD}">Strict Principle of Least Privilege</text>')
    a(f'  <text x="354" y="805" class="t-csub">Keyring\'s managed identity holds zero roles on any customer Key Vault.</text>')

    # ZONE 4 (TOP RIGHT): Customer Azure Subscriptions & Multi-Environment Key Vaults
    zone(924, 88, 532, 404, "Customer Azure Subscriptions (Called as Signed-In User)", "Every read & write uses the person's OBO token · Key Vault RBAC decides", fill=BLUE_SOFT, stroke=BLUE_RULE, accent=BLUE)

    a(f'  <rect x="940" y="138" width="500" height="152" rx="8" fill="#ffffff" stroke="{BLUE_RULE}" stroke-width="1.25" filter="url(#{tid}-sh)"/>')
    a(f'  <text x="954" y="159" class="t-card">Multi-Environment Azure Key Vaults (Promotion-Ordered)</text>')
    a(f'  <text x="954" y="175" class="t-csub">Value-blind parity matrix (/environments) &amp; per-env writes (/environments/set)</text>')

    envs = [
        (954, "kv-payments-dev", "DEV", SLATE_SOFT, RULE, INK2),
        (1117, "kv-payments-test", "TEST", SLATE_SOFT, RULE, INK2),
        (1280, "kv-payments-prod", "PROD", AMBER_SOFT, AMBER_RULE, AMBER),
    ]
    for ex, ename, ebadge, efill, estroke, efg in envs:
        a(f'  <rect x="{ex}" y="188" width="146" height="88" rx="7" fill="{efill}" stroke="{estroke}" stroke-width="1.2"/>')
        a(f'  <image x="{ex + 10}" y="198" width="30" height="30" xlink:href="{ico("security/Key_Vaults.svg")}"/>')
        a(f'  <rect x="{ex + 92}" y="200" width="44" height="17" rx="8.5" fill="#ffffff" stroke="{estroke}" stroke-width="1"/>')
        a(f'  <text x="{ex + 114}" y="211.8" text-anchor="middle" class="t-badge" fill="{efg}">{ebadge}</text>')
        a(f'  <text x="{ex + 10}" y="244" class="t-card">{ename}</text>')
        a(f'  <text x="{ex + 10}" y="258" class="t-csub">Secrets · Certs · Keys</text>')
        a(f'  <text x="{ex + 10}" y="270" class="t-mono">RBAC / Tags / Soft-Del</text>')

    a(f'  <line x1="1100" y1="232" x2="1114" y2="232" stroke="{BLUE}" stroke-width="1.8" marker-end="url(#{tid}-ab)"/>')
    a(f'  <line x1="1263" y1="232" x2="1277" y2="232" stroke="{BLUE}" stroke-width="1.8" marker-end="url(#{tid}-ab)"/>')

    card(940, 304, 244, 78, "management_governance/Resource_Graph_Explorer.svg", "Resource Graph", "Vault discovery, ARM tags", "(app, env, keyring-owners)")
    card(1196, 304, 244, 78, "general/Resource_Groups.svg", "Resource Manager", "RBAC assignments, PIM,", "diagnostic settings & shares")
    card(940, 396, 244, 78, "networking/Private_Endpoint.svg", "Private Endpoints", "Private link access to", "firewalled vaults over VNet")
    card(1196, 396, 244, 78, "networking/DNS_Zones.svg", "Private DNS Zone", "privatelink.vaultcore.azure.net", "linked to Keyring VNet")

    # ZONE 5 (BOTTOM RIGHT): Audit, SIEM & Notifications
    zone(924, 534, 532, 304, "Audit, SIEM & Notifications", "Dual audit trail (Key Vault + KeyringAudit_CL), Sentinel & ACS Email", fill=AMBER_SOFT, stroke=AMBER_RULE, accent=AMBER)
    card(940, 584, 244, 74, "other/Data_Collection_Rules.svg", "Logs Ingestion", "KeyringAudit_CL written by", "Managed ID (gzip batch)", badge="MI WRITE", badge_fill=AMBER_SOFT, badge_fg=AMBER)
    card(1196, 584, 244, 74, "analytics/Log_Analytics_Workspaces.svg", "Log Analytics", "KV AuditEvent (OBO read)", "& KeyringAudit_CL table")
    card(940, 670, 244, 72, "security/Azure_Sentinel.svg", "Microsoft Sentinel", "ASIM parser, 8 rules,", "hunting & workbook")
    card(1196, 670, 244, 72, "management_governance/Monitor.svg", "Azure Monitor", "Log search alerts (watched", "reads, purges, bursts)")
    card(940, 754, 500, 68, "other/Azure_Communication_Services.svg", "Azure Communication Services (Email)", "Health, expiry, access request, watched-read, destructive & share notices", "Sent via Managed ID only · domain allow-list, rate limits & zero secrets", badge="MI SEND", badge_fill=AMBER_SOFT, badge_fg=AMBER)

    # CONNECTORS (Zero overlaps — every path routes strictly through open gutters!)
    # 1. Users -> Browser -> Keyring (HTTPS)
    a(f'  <line x1="144" y1="210" x2="144" y2="221" stroke="{NAVY}" stroke-width="1.8" marker-end="url(#{tid}-as)"/>')
    a(f'  <path d="M 250 259 L 294 259 L 294 426 L 321 426" fill="none" stroke="{NAVY}" stroke-width="2.2" marker-end="url(#{tid}-as)"/>')
    edge_label(294, 344, "HTTPS", NAVY)

    # 2. Event Grid -> Keyring webhook (Crimson dashed)
    a(f'  <path d="M 250 582 L 294 582 L 294 528 L 321 528" fill="none" stroke="{CRIMSON}" stroke-width="2" stroke-dasharray="6 4" marker-end="url(#{tid}-ac)"/>')
    edge_label(294, 582, "Entra JWT", CRIMSON, bg=CRIMSON_SOFT)

    # 3. Keyring <-> Entra ID (OIDC + OBO) in open horizontal gap (y=294..344)
    a(f'  <line x1="462" y1="344" x2="462" y2="297" stroke="{BLUE}" stroke-width="2.2" marker-end="url(#{tid}-ab)"/>')
    edge_label(462, 319, "OIDC / PKCE / OBO", BLUE, bg=BLUE_SOFT)

    # 4. Keyring (MI) -> Entra App Registration (Federated Credential) in open gap (y=294..344)
    a(f'  <line x1="718" y1="344" x2="718" y2="297" stroke="{AMBER}" stroke-width="2.1" marker-end="url(#{tid}-aa)"/>')
    edge_label(718, 319, "MI Federated Cred", AMBER, bg=AMBER_SOFT)

    # 5. Keyring -> Customer Azure Subscriptions / Multi-Env Key Vaults (OBO)
    a(f'  <path d="M 856 426 L 890 426 L 890 232 L 921 232" fill="none" stroke="{BLUE}" stroke-width="2.4" marker-end="url(#{tid}-ab)"/>')
    edge_label(890, 326, "User OBO", BLUE, bg=BLUE_SOFT)

    # 6. Keyring -> Log Analytics (OBO audit read) routed cleanly through open gap y=513!
    a(f'  <path d="M 856 462 L 890 462 L 890 513 L 1318 513 L 1318 581" fill="none" stroke="{BLUE}" stroke-width="1.6" stroke-dasharray="4 3" marker-end="url(#{tid}-ab)"/>')
    edge_label(1120, 513, "OBO Audit Read (Log Analytics)", BLUE, bg=BLUE_SOFT)

    # 7. Keyring Managed Identity -> Logs Ingestion & ACS Email
    a(f'  <path d="M 856 626 L 890 626 L 890 620 L 921 620" fill="none" stroke="{AMBER}" stroke-width="2.2" marker-end="url(#{tid}-aa)"/>')
    a(f'  <path d="M 890 626 L 890 788 L 937 788" fill="none" stroke="{AMBER}" stroke-width="2.2" marker-end="url(#{tid}-aa)"/>')
    edge_label(890, 706, "MI Token", AMBER, bg=AMBER_SOFT)

    # 8. Logs Ingestion -> Log Analytics -> Sentinel / Monitor
    a(f'  <line x1="1184" y1="621" x2="1193" y2="621" stroke="{AMBER}" stroke-width="1.8" marker-end="url(#{tid}-aa)"/>')
    a(f'  <line x1="1318" y1="658" x2="1318" y2="667" stroke="{INK2}" stroke-width="1.5" marker-end="url(#{tid}-as)"/>')
    a(f'  <path d="M 1244 658 L 1244 664 L 1062 664 L 1062 667" fill="none" stroke="{INK2}" stroke-width="1.5" marker-end="url(#{tid}-as)"/>')

    # Legend bar
    a(f'  <rect x="24" y="856" width="{W - 48}" height="46" rx="8" fill="{SLATE_SOFT}" stroke="{RULE}" stroke-width="1"/>')
    a(f'  <text x="42" y="883" class="t-zone">Legend</text>')
    items = [
        (120, BLUE, False, "ab", "User OBO Token (Key Vaults, ARM, Graph, Audit Reads)"),
        (540, AMBER, False, "aa", "Managed Identity (Federated Cred, Audit Sink, ACS Email)"),
        (985, CRIMSON, True, "ac", "Event Grid Push (Entra JWT)"),
        (1245, NAVY, False, "as", "Browser HTTPS"),
    ]
    for lx, col, dashed, mk, lbl in items:
        dash = ' stroke-dasharray="5 3"' if dashed else ""
        a(f'  <line x1="{lx}" y1="879" x2="{lx + 32}" y2="879" stroke="{col}" stroke-width="2.2"{dash} marker-end="url(#{tid}-{mk})"/>')
        a(f'  <text x="{lx + 42}" y="883" class="t-leg">{escape(lbl)}</text>')

    a("</svg>")
    return "\n".join(parts)


def build_soc_svg(icons):
    """Diagram 2: SOC Logging, Correlation & Microsoft Sentinel Telemetry Pipeline."""
    W, H = 1480, 920
    tid = "soc"
    parts = [svg_preamble(
        W, H, tid,
        "Keyring SOC Logging, Correlation and Sentinel Telemetry Architecture",
        "End-to-end SOC telemetry pipeline showing the four log sources (Keyring audit events via Logs Ingestion DCR, Azure Key Vault diagnostic audit logs, Entra ID sign-in and PIM logs, and runtime health telemetry), the redaction boundary, Log Analytics correlation keys (KvRequestId, ActorObjectId, SessionRef), ASIM normalisation (vimAuditEventKeyring), and Microsoft Sentinel detections, hunting queries and Azure Monitor alerts.",
        "Keyring: SOC Logging, Correlation & Sentinel Telemetry Pipeline",
        "Four correlated telemetry streams · Zero secret leakage (TRACE-verified) · ASIM normalisation & 8 ready-to-enable Sentinel rules",
        "SOC-Ready Telemetry · ASIM 1.0",
        top_color=NAVY,
    )]
    a = parts.append
    ico, zone, card, edge_label = make_helpers(parts, icons, tid)

    # COLUMN 1 (LEFT): 4 High-Value Telemetry Sources
    zone(24, 88, 392, 566, "1. Telemetry Sources (SOC Inputs)", "Every layer emits structured, zero-secret events", fill=SLATE_SOFT, accent=BLUE)

    card(38, 140, 364, 112, "app_services/App_Services.svg", "A. Keyring Audit Events",
         "Browser ClientIp, UserAgent, SessionRef, Reason, Ticket,",
         "pre-Azure refusals, shares & multi-env writes (47 actions)",
         fill="#ffffff", stroke=AMBER_RULE, badge="KEYRINGAUDIT_CL", badge_fill=AMBER_SOFT, badge_fg=AMBER)

    card(38, 266, 364, 110, "security/Key_Vaults.svg", "B. Key Vault Audit Logs",
         "Ground-truth data plane: SecretGet, SecretSet, Delete,",
         "Purge, KeyRotate — covers Keyring, Portal, CLI & apps",
         fill="#ffffff", stroke=BLUE_RULE, badge="AZKVAUDITLOGS", badge_fill=BLUE_SOFT, badge_fg=BLUE)

    card(38, 390, 364, 110, "identity/Azure_Active_Directory.svg", "C. Entra Sign-In & PIM",
         "MFA/acrs step-up outcomes, Conditional Access grants,",
         "OBO token issuance & PIM elevation approvals",
         fill="#ffffff", stroke=PURPLE_RULE, badge="SIGNINLOGS / PIM", badge_fill=PURPLE_SOFT, badge_fg=PURPLE)

    card(38, 514, 364, 122, "other/Worker_Container_App.svg", "D. Runtime & Health",
         "JSON stdout request lines (method, path, status, ms),",
         "/healthz/audit (503 on sink degradation) & /healthz/notify",
         fill="#ffffff", stroke=RULE, badge="STDOUT JSON", badge_fill=SLATE_SOFT, badge_fg=INK2)

    # Hard Redaction Boundary
    a(f'  <rect x="24" y="672" width="392" height="166" rx="10" fill="{NAVY}"/>')
    a(f'  <text x="40" y="698" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="11" font-weight="700" fill="#fca5a5" letter-spacing="0.06em">HARD REDACTION BOUNDARY (TRACE-TESTED)</text>')
    a(f'  <text x="40" y="719" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="11" fill="#e2e8f0">Guaranteed NEVER written to stdout, DCR, or ACS email:</text>')
    a(f'  <text x="40" y="740" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="11" fill="#cbd5e1">✕ Secret values, typed secret fields &amp; PFX passwords</text>')
    a(f'  <text x="40" y="758" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="11" fill="#cbd5e1">✕ Entra access/refresh/OBO tokens &amp; Managed ID tokens</text>')
    a(f'  <text x="40" y="776" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="11" fill="#cbd5e1">✕ Session cookies, CSRF tokens &amp; URL query strings</text>')
    a(f'  <text x="40" y="794" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="11" fill="#cbd5e1">✕ Descriptions, owner/notify emails &amp; raw Azure errors</text>')
    a(f'  <text x="40" y="819" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="10" fill="#93c5fd">Enforced on every PR by tests/no_secrets_in_logs.rs</text>')

    # COLUMN 2 (CENTRE): Ingestion, Storage & Correlation Hub
    zone(494, 88, 424, 750, "2. Ingestion, Storage & Correlation", "Write-only sink + 3 deterministic SOC join keys", fill=CANVAS, stroke=RULE, accent=AMBER)

    card(510, 140, 384, 88, "other/Data_Collection_Rules.svg", "Logs Ingestion API (DCR)",
         "Managed ID writes gzip batches (5s / 500 rows, 10k queue)",
         "Monitoring Metrics Publisher ONLY · zero read/delete rights",
         fill=AMBER_SOFT, stroke=AMBER_RULE, badge="WRITE-ONLY MI", badge_fill="#ffffff", badge_fg=AMBER)

    a(f'  <rect x="510" y="242" width="384" height="62" rx="8" fill="{CRIMSON_SOFT}" stroke="{CRIMSON_RULE}" stroke-width="1.15"/>')
    a(f'  <text x="524" y="263" class="t-card" fill="{CRIMSON}">Fail-Closed Gate (KEYRING_AUDIT_REQUIRED=true)</text>')
    a(f'  <text x="524" y="280" class="t-csub">Refuses reveals, copies, shares &amp; key downloads if sink degrades &gt;60s.</text>')
    a(f'  <text x="524" y="294" class="t-csub">Every event writes to stdout first so zero audit records are lost.</text>')

    card(510, 318, 384, 98, "analytics/Log_Analytics_Workspaces.svg", "Log Analytics Workspace",
         "Stores KeyringAudit_CL, AZKVAuditLogs / AzureDiagnostics,",
         "SigninLogs, AuditLogs & ContainerApp/AppService logs",
         fill="#ffffff", stroke=BLUE_RULE, badge="90-730d RETENTION", badge_fill=BLUE_SOFT, badge_fg=BLUE)

    # 3 Correlation Keys box
    a(f'  <rect x="510" y="432" width="384" height="196" rx="8" fill="#ffffff" stroke="{BLUE}" stroke-width="1.4" filter="url(#{tid}-sh)"/>')
    a(f'  <rect x="510" y="432" width="384" height="29" rx="7" fill="{BLUE_SOFT}"/>')
    a(f'  <text x="524" y="451" class="t-card" fill="{BLUE}">Three Deterministic SOC Join Keys</text>')

    a(f'  <text x="524" y="481" class="t-card">1. End-to-End API Correlation (Browser → Key Vault)</text>')
    a(f'  <text x="524" y="497" class="t-mono">KeyringAudit_CL.KvRequestId == AZKVAuditLogs.CorrelationId</text>')
    a(f'  <text x="524" y="512" class="t-csub">Links browser IP, UPN, Reason &amp; Ticket to Key Vault\'s API call.</text>')

    a(f'  <text x="524" y="537" class="t-card">2. Identity &amp; Conditional Access Posture</text>')
    a(f'  <text x="524" y="553" class="t-mono">KeyringAudit_CL.ActorObjectId == SigninLogs.UserId</text>')
    a(f'  <text x="524" y="568" class="t-csub">Verifies MFA method, device compliance, risk &amp; PIM approval.</text>')

    a(f'  <text x="524" y="593" class="t-card">3. Full Browser Session Timeline (Cookie-Free)</text>')
    a(f'  <text x="524" y="609" class="t-mono">KeyringAudit_CL.SessionRef (HMAC-SHA256 of session ID)</text>')

    card(510, 642, 384, 92, "security/Azure_Sentinel.svg", "ASIM Audit Parser",
         "vimAuditEventKeyring -> Sentinel ASIM AuditEvent v1.0.0:",
         "EventType, ActorUsername, SrcIpAddr, Object, Ticket",
         fill=EMERALD_SOFT, stroke=EMERALD_RULE, badge="ASIM 1.0.0", badge_fill="#ffffff", badge_fg=EMERALD)

    a(f'  <rect x="510" y="748" width="384" height="74" rx="8" fill="{SLATE_SOFT}" stroke="{RULE}" stroke-width="1"/>')
    a(f'  <text x="524" y="769" class="t-card">Cross-Source Tamper Detection</text>')
    a(f'  <text x="524" y="787" class="t-csub">Comparing KeyringAudit_CL against Key Vault\'s own audit log</text>')
    a(f'  <text x="524" y="803" class="t-csub">catches unmatched SecretGet calls or a silenced audit sink.</text>')

    # COLUMN 3 (RIGHT): High-Value SOC Detections, Hunting & Response
    zone(994, 88, 462, 750, "3. SOC Detections, Hunting & Response", "Deployed via infra/sentinel/main.bicep & infra/alerts/access.bicep", fill=BLUE_SOFT, stroke=BLUE_RULE, accent=NAVY)

    a(f'  <rect x="1010" y="140" width="430" height="314" rx="8" fill="#ffffff" stroke="{BLUE_RULE}" stroke-width="1.25" filter="url(#{tid}-sh)"/>')
    a(f'  <image x="1022" y="150" width="32" height="32" xlink:href="{ico("security/Azure_Sentinel.svg")}"/>')
    a(f'  <text x="1062" y="164" class="t-card">Microsoft Sentinel Scheduled Rules (8)</text>')
    a(f'  <text x="1062" y="179" class="t-csub">Entity-mapped (Account, IP, Resource) · Delay-aware</text>')
    a(f'  <line x1="1022" y1="192" x2="1428" y2="192" stroke="{RULE}" stroke-width="1"/>')

    rules = [
        ("1. Many secret reveals", "T1555 · Credential Harvest", CRIMSON),
        ("2. Reveal from new IP", "T1078 · Session Hijack", CRIMSON),
        ("3. Denied probing (3+ vaults)", "T1087 · Discovery / Recon", AMBER),
        ("4. Off-hours purge / bulk / key", "T1485 · Destructive Action", CRIMSON),
        ("5. Forged CSRF / cross-site", "T1190 · Web App Attack", AMBER),
        ("6. Guest share / share burst", "T1098 · Account Manipulation", AMBER),
        ("7. Audit sink gap vs KV logs", "T1562 · Defence Evasion", CRIMSON),
        ("8. Unmatched KV SecretGet", "T1555 · Bypass / Tamper", CRIMSON),
    ]
    ry = 213
    for rname, rmitre, rcol in rules:
        a(f'  <circle cx="1030" cy="{ry - 4}" r="3.5" fill="{rcol}"/>')
        a(f'  <text x="1041" y="{ry}" class="t-card" font-size="11.5">{escape(rname)}</text>')
        a(f'  <text x="1256" y="{ry}" class="t-mono" font-size="10">{escape(rmitre)}</text>')
        ry += 30

    card(1010, 468, 430, 90, "analytics/Log_Analytics_Workspaces.svg", "SOC Workbook & 6 Hunting Queries",
         "Keyring Audit Workbook: reveal trends, actors, denials, health",
         "Hunting: values-read, private-keys, deletes/purges, side-by-side",
         fill="#ffffff", stroke=RULE, badge="WORKBOOK", badge_fill=BLUE_SOFT, badge_fg=BLUE)

    card(1010, 572, 430, 86, "management_governance/Monitor.svg", "Azure Monitor Access Alerts",
         "Log search rules on Key Vault workspace (infra/alerts/access):",
         "Watched secret reads, any purge & refusal bursts (15m)",
         fill="#ffffff", stroke=RULE, badge="ACTION GROUP", badge_fill=EMERALD_SOFT, badge_fg=EMERALD)

    card(1010, 672, 430, 80, "other/Azure_Communication_Services.svg", "Security & Health Notices (ACS)",
         "Admins: sink outage (>5m) & refusal bursts; Vault owners:",
         "watched reads, deletes, bulk edits, PIM use & secret shares",
         fill=AMBER_SOFT, stroke=AMBER_RULE, badge="NO SECRETS", badge_fill="#ffffff", badge_fg=AMBER)

    a(f'  <rect x="1010" y="766" width="430" height="56" rx="7" fill="{EMERALD_SOFT}" stroke="{EMERALD_RULE}" stroke-width="1"/>')
    a(f'  <text x="1024" y="787" class="t-card" fill="{EMERALD}">Multi-Env &amp; Governance Signal Coverage</text>')
    a(f'  <text x="1024" y="805" class="t-csub">Captures secret.multi_env_set (partly_written), Reason &amp; Ticket.</text>')

    # CONNECTORS (Clean gutter channels — ZERO overlaps!)
    # Stream A -> DCR (Amber)
    a(f'  <path d="M 402 184 L 507 184" fill="none" stroke="{AMBER}" stroke-width="2.3" marker-end="url(#{tid}-aa)"/>')
    edge_label(455, 166, "HTTPS / MI", AMBER, bg=AMBER_SOFT)

    # Stream B -> Log Analytics (Blue)
    a(f'  <path d="M 402 320 L 456 320 L 456 350 L 507 350" fill="none" stroke="{BLUE}" stroke-width="2.2" marker-end="url(#{tid}-ab)"/>')
    edge_label(455, 304, "Diag Settings", BLUE, bg=BLUE_SOFT)

    # Stream C -> Log Analytics (Purple)
    a(f'  <path d="M 402 445 L 466 445 L 466 376 L 507 376" fill="none" stroke="{PURPLE}" stroke-width="2" marker-end="url(#{tid}-ap)"/>')
    edge_label(442, 428, "Entra Export", PURPLE, bg=PURPLE_SOFT)

    # Stream D -> Log Analytics (Slate dashed)
    a(f'  <path d="M 402 575 L 478 575 L 478 400 L 507 400" fill="none" stroke="{NAVY}" stroke-width="1.8" stroke-dasharray="5 3" marker-end="url(#{tid}-as)"/>')
    edge_label(446, 558, "Console Logs", NAVY)

    # DCR -> Log Analytics routed cleanly inside right margin of Zone 2 (x=906, clear of all text!)
    a(f'  <path d="M 894 184 L 906 184 L 906 346 L 897 346" fill="none" stroke="{AMBER}" stroke-width="2.2" marker-end="url(#{tid}-aa)"/>')

    # Log Analytics -> Correlation -> ASIM
    a(f'  <line x1="702" y1="416" x2="702" y2="429" stroke="{BLUE}" stroke-width="2" marker-end="url(#{tid}-ab)"/>')
    a(f'  <line x1="702" y1="628" x2="702" y2="639" stroke="{EMERALD}" stroke-width="2" marker-end="url(#{tid}-ae)"/>')

    # Workspace -> Sentinel Rules & Monitor Alerts (channel x=944)
    a(f'  <path d="M 894 368 L 944 368 L 944 290 L 1007 290" fill="none" stroke="{BLUE}" stroke-width="2.2" marker-end="url(#{tid}-ab)"/>')
    a(f'  <path d="M 944 368 L 944 615 L 1007 615" fill="none" stroke="{BLUE}" stroke-width="1.8" marker-end="url(#{tid}-ab)"/>')

    # ASIM -> Workbook & Hunting (channel x=962)
    a(f'  <path d="M 894 688 L 962 688 L 962 513 L 1007 513" fill="none" stroke="{EMERALD}" stroke-width="2.2" marker-end="url(#{tid}-ae)"/>')
    edge_label(956, 488, "KQL / ASIM", EMERALD, bg=EMERALD_SOFT)

    # Keyring Health/Activity Observer -> ACS Email (clean dedicated right channel x=978)
    a(f'  <path d="M 918 184 L 978 184 L 978 712 L 1007 712" fill="none" stroke="{AMBER}" stroke-width="1.8" stroke-dasharray="5 3" marker-end="url(#{tid}-aa)"/>')

    # Legend bar
    a(f'  <rect x="24" y="856" width="{W - 48}" height="46" rx="8" fill="{SLATE_SOFT}" stroke="{RULE}" stroke-width="1"/>')
    a(f'  <text x="42" y="883" class="t-zone">Legend</text>')
    items = [
        (120, AMBER, False, "aa", "KeyringAudit_CL & ACS (Managed ID)"),
        (455, BLUE, False, "ab", "Key Vault Audit & Monitor Queries"),
        (765, PURPLE, False, "ap", "Entra Sign-In & PIM Logs"),
        (1025, EMERALD, False, "ae", "ASIM Normalised Stream"),
        (1275, NAVY, True, "as", "JSON stdout"),
    ]
    for lx, col, dashed, mk, lbl in items:
        dash = ' stroke-dasharray="5 3"' if dashed else ""
        a(f'  <line x1="{lx}" y1="879" x2="{lx + 32}" y2="879" stroke="{col}" stroke-width="2.2"{dash} marker-end="url(#{tid}-{mk})"/>')
        a(f'  <text x="{lx + 42}" y="883" class="t-leg">{escape(lbl)}</text>')

    a("</svg>")
    return "\n".join(parts)


def rasterise_all(pairs):
    """Render each (svg_path, png_path) pair at 2x scale using Playwright Chromium."""
    js = r'''
import { createRequire } from "node:module";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

function loadPlaywright() {
  for (const dir of (process.env.PATH || "").split(":")) {
    if (dir.endsWith(join("node_modules", ".bin")) && existsSync(join(dir, "..", "playwright", "package.json"))) {
      return createRequire(join(dir, "..", "noop.js"))("playwright");
    }
  }
  throw new Error("Playwright not found");
}

const { chromium } = loadPlaywright();
const jobs = JSON.parse(process.env.JOBS);
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1480, height: 920 }, deviceScaleFactor: 2 });
for (const [svgIn, pngOut] of jobs) {
  const svg = readFileSync(svgIn, "utf8");
  const html = `<!doctype html><html><head><meta charset="utf-8"><style>html,body{margin:0;padding:0;background:#ffffff;}svg{display:block;width:1480px;height:920px;}</style></head><body>${svg}</body></html>`;
  await page.setContent(html, { waitUntil: "load" });
  await page.screenshot({ path: pngOut, type: "png" });
}
await browser.close();
'''
    tmp_js = "/tmp/rasterise_diagrams.mjs"
    with open(tmp_js, "w", encoding="utf-8") as f:
        f.write(js)
    env = os.environ.copy()
    env["JOBS"] = json.dumps(pairs)
    try:
        res = subprocess.run(
            ["npx", "-y", "-p", "playwright@1.65.0", "-c", f"node {tmp_js}"],
            env=env,
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            print(res.stdout + "\n" + res.stderr, file=sys.stderr)
            sys.exit(res.returncode)
    finally:
        if os.path.exists(tmp_js):
            os.remove(tmp_js)


def write_inline_html(sol_svg, soc_svg, out_html):
    """Write a responsive HTML page showing both diagrams with switcher tabs for T3 Code html_render."""
    html = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; font-family: var(--font-sans, system-ui, sans-serif); color: var(--foreground); }}
  .tabs {{
    display: flex;
    gap: 8px;
    margin-bottom: 10px;
    flex-wrap: wrap;
  }}
  .tab {{
    font: 600 12.5px/1.2 var(--font-sans, system-ui, sans-serif);
    padding: 7px 12px;
    border-radius: var(--radius, 6px);
    border: 1px solid var(--border, #d4dce8);
    background: var(--card, transparent);
    color: var(--foreground);
    cursor: pointer;
  }}
  .tab[aria-selected="true"] {{
    background: var(--primary, #0e5ae5);
    color: var(--primary-foreground, #ffffff);
    border-color: var(--primary, #0e5ae5);
  }}
  .frame {{
    width: 100%;
    border-radius: var(--radius, 8px);
    overflow: hidden;
    border: 1px solid var(--border, #d4dce8);
    background: #ffffff;
  }}
  .frame svg {{
    display: block;
    width: 100%;
    height: auto;
  }}
  .pane[hidden] {{ display: none; }}
</style>
</head>
<body>
  <div class="tabs" role="tablist" aria-label="Architecture diagrams">
    <button type="button" class="tab" role="tab" aria-selected="true" data-target="pane-sol">Solution Architecture (Azure Icons)</button>
    <button type="button" class="tab" role="tab" aria-selected="false" data-target="pane-soc">SOC Logging &amp; Sentinel Telemetry</button>
  </div>
  <div id="pane-sol" class="pane frame">{sol_svg}</div>
  <div id="pane-soc" class="pane frame" hidden>{soc_svg}</div>
  <script>
    const tabs = document.querySelectorAll(".tab");
    const panes = document.querySelectorAll(".pane");
    tabs.forEach((btn) => {{
      btn.addEventListener("click", () => {{
        tabs.forEach((t) => t.setAttribute("aria-selected", String(t === btn)));
        panes.forEach((p) => p.hidden = p.id !== btn.dataset.target);
      }});
    }});
  </script>
</body>
</html>
'''
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html)


def main():
    icons = extract_azure_icons()
    print(f"Extracted {len(icons)} official Microsoft Azure SVG icons")
    sol_svg = build_solution_svg(icons)
    soc_svg = build_soc_svg(icons)
    with open(SOL_SVG, "w", encoding="utf-8") as f:
        f.write(sol_svg)
    with open(SOC_SVG, "w", encoding="utf-8") as f:
        f.write(soc_svg)
    rasterise_all([(SOL_SVG, SOL_PNG), (SOC_SVG, SOC_PNG)])
    write_inline_html(sol_svg, soc_svg, INLINE_HTML)
    print(f"Wrote {SOL_SVG} ({len(sol_svg) // 1024} KB) and {SOL_PNG} ({os.path.getsize(SOL_PNG) // 1024} KB)")
    print(f"Wrote {SOC_SVG} ({len(soc_svg) // 1024} KB) and {SOC_PNG} ({os.path.getsize(SOC_PNG) // 1024} KB)")
    print(f"Wrote {INLINE_HTML}")


if __name__ == "__main__":
    main()
