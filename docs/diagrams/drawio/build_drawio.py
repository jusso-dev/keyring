#!/usr/bin/env python3
"""Writes docs/diagrams/drawio/keyring-design.drawio: the diagrams for the Keyring solution design document,
one page each.

Python 3 standard library only. The output is deterministic: cell IDs are numbered in the order cells are
added, pages are in a fixed order and nothing depends on the clock, so the file diffs cleanly and opens for
editing in draw.io desktop or diagrams.net. export.sh turns each page into SVG and PNG.

Icons come from draw.io's built-in Azure library (img/lib/azure2). The product name is written next to every
icon, as Microsoft's icon terms ask.

Colours are Keyring's own tokens from design.md.

Usage: python3 docs/diagrams/drawio/build_drawio.py
"""
import os
from html import escape
from xml.sax.saxutils import quoteattr

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "keyring-design.drawio")

# design.md tokens
INK, INK2 = "#1c222a", "#515963"
PAPER, PAPER2, SURFACE = "#f5f7fa", "#ebeff2", "#ffffff"
RULE, RULE_STRONG = "#dadee3", "#737b84"
ACCENT, ACCENT_TINT, ACCENT_RULE = "#186575", "#e3f4f8", "#9ac7d2"
CHROME = "#1d252d"
OK, OK_TINT, OK_RULE = "#17653c", "#e3f8e9", "#9accaa"
WARN, WARN_TINT, WARN_RULE = "#804d0c", "#fdf2dd", "#dcb783"
DANGER, DANGER_TINT, DANGER_RULE = "#b02a2d", "#fcf1ef", "#e8ada7"

# What each flow colour means, the same on every page.
PERSON = ACCENT     # the signed-in person's own tokens (sign-in and on-behalf-of)
IDENTITY = WARN     # Keyring's managed identity
INBOUND = DANGER    # Event Grid's delivery to the webhook
PLAIN = INK2        # browser traffic and everything else
FONT = "Helvetica"

AZ = "img/lib/azure2/"
ICON = {
    "users": AZ + "identity/Users.svg",
    "browser": AZ + "general/Browser.svg",
    "entra": AZ + "identity/Azure_Active_Directory.svg",
    "appreg": AZ + "identity/App_Registrations.svg",
    "mi": AZ + "identity/Managed_Identities.svg",
    "pim": AZ + "identity/Entra_Privileged_Identity_Management.svg",
    "ca": AZ + "security/Conditional_Access.svg",
    "keyvault": AZ + "security/Key_Vaults.svg",
    "appservice": AZ + "app_services/App_Services.svg",
    "plan": AZ + "app_services/App_Service_Plans.svg",
    "containerapp": AZ + "other/Worker_Container_App.svg",
    "cae": AZ + "other/Container_App_Environments.svg",
    "arm": AZ + "general/Resource_Groups.svg",
    "rg": AZ + "general/Resource_Groups.svg",
    "graph": AZ + "management_governance/Resource_Graph_Explorer.svg",
    "law": AZ + "analytics/Log_Analytics_Workspaces.svg",
    "dcr": AZ + "other/Data_Collection_Rules.svg",
    "monitor": AZ + "management_governance/Monitor.svg",
    "acs": AZ + "other/Azure_Communication_Services.svg",
    "eventgrid": AZ + "integration/Event_Grid_Topics.svg",
    "egsub": AZ + "integration/Event_Grid_Subscriptions.svg",
    "sentinel": AZ + "security/Azure_Sentinel.svg",
    "workbook": AZ + "analytics/Azure_Workbooks.svg",
    "vnet": AZ + "networking/Virtual_Networks.svg",
    "subnet": AZ + "networking/Subnet.svg",
    "pe": AZ + "networking/Private_Endpoint.svg",
    "dns": AZ + "networking/DNS_Zones.svg",
    "acr": AZ + "containers/Container_Registries.svg",
}


def esc(s):
    return escape(s, quote=False)


def icon_style(key):
    return f"image;aspect=fixed;html=1;image={ICON[key]};"


class Page:
    def __init__(self, pid, name, w, h):
        self.pid, self.name, self.w, self.h = pid, name, w, h
        self.cells, self.n = [], 0

    def _id(self):
        self.n += 1
        return f"{self.pid}-{self.n:03d}"

    def vertex(self, x, y, w, h, value, style):
        cid = self._id()
        self.cells.append(
            f'<mxCell id="{cid}" value={quoteattr(value)} style={quoteattr(style)} vertex="1" parent="1">'
            f'<mxGeometry x="{x:g}" y="{y:g}" width="{w:g}" height="{h:g}" as="geometry"/></mxCell>')
        return cid

    def edge(self, src, tgt, value, style, points=()):
        cid = self._id()
        pts = "".join(f'<mxPoint x="{x:g}" y="{y:g}"/>' for x, y in points)
        arr = f'<Array as="points">{pts}</Array>' if points else ""
        self.cells.append(
            f'<mxCell id="{cid}" value={quoteattr(value)} style={quoteattr(style)} edge="1" parent="1" '
            f'source="{src}" target="{tgt}"><mxGeometry relative="1" as="geometry">{arr}</mxGeometry></mxCell>')
        return cid

    def xml(self):
        return (f'<diagram id="{self.pid}" name={quoteattr(self.name)}>'
                f'<mxGraphModel dx="0" dy="0" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" '
                f'fold="1" page="1" pageScale="1" pageWidth="{self.w}" pageHeight="{self.h}" background="#ffffff" '
                f'math="0" shadow="0"><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
                + "".join(self.cells) + "</root></mxGraphModel></diagram>")

    # ---- building blocks ----

    def title(self, text, sub):
        self.vertex(20, 12, self.w - 40, 28, f"<b>{esc(text)}</b>",
                    f"text;html=1;align=left;verticalAlign=middle;fontFamily={FONT};fontSize=21;fontColor={INK};")
        self.vertex(20, 40, self.w - 40, 20, esc(sub),
                    f"text;html=1;align=left;verticalAlign=middle;fontFamily={FONT};fontSize=13;fontColor={INK2};")

    def zone(self, x, y, w, h, title, sub="", fill=PAPER, stroke=RULE_STRONG, dashed=False):
        value = f"<b>{esc(title)}</b>" + (f'<br><font style="font-size:11.5px" color="{INK2}">{esc(sub)}</font>' if sub else "")
        style = (f"rounded=1;absoluteArcSize=1;arcSize=16;html=1;whiteSpace=wrap;fillColor={fill};strokeColor={stroke};"
                 f"strokeWidth=1.5;align=left;verticalAlign=top;spacingLeft=12;spacingTop=4;fontFamily={FONT};"
                 f"fontSize=14;fontColor={INK};" + ("dashed=1;dashPattern=8 4;" if dashed else ""))
        return self.vertex(x, y, w, h, value, style)

    def card(self, x, y, w, h, icon, title, lines=(), fill=SURFACE, stroke=RULE_STRONG, dashed=False, isz=36, fs=13):
        value = f"<b>{esc(title)}</b>" + "".join(
            f'<br><font color="{INK2}" style="font-size:{fs - 1.5:g}px">{esc(line)}</font>' for line in lines)
        style = (f"rounded=1;absoluteArcSize=1;arcSize=10;html=1;whiteSpace=wrap;fillColor={fill};strokeColor={stroke};"
                 f"align=left;verticalAlign=middle;spacingLeft={(isz + 16) if icon else 10};spacingRight=6;"
                 f"fontFamily={FONT};fontSize={fs};fontColor={INK};" + ("dashed=1;dashPattern=6 4;" if dashed else ""))
        cid = self.vertex(x, y, w, h, value, style)
        if icon:
            self.vertex(x + 9, y + (h - isz) / 2, isz, isz, "", icon_style(icon))
        return cid

    def box(self, x, y, w, h, value, fill=SURFACE, stroke=RULE_STRONG, fs=12, align="left", dashed=False):
        return self.vertex(x, y, w, h, value,
                           f"rounded=1;absoluteArcSize=1;arcSize=10;html=1;whiteSpace=wrap;fillColor={fill};"
                           f"strokeColor={stroke};align={align};verticalAlign=top;spacing=8;fontFamily={FONT};"
                           f"fontSize={fs};fontColor={INK};" + ("dashed=1;dashPattern=6 4;" if dashed else ""))

    def text(self, x, y, w, h, value, fs=12, colour=INK, align="left"):
        return self.vertex(x, y, w, h, value,
                           f"text;html=1;whiteSpace=wrap;align={align};verticalAlign=top;fontFamily={FONT};"
                           f"fontSize={fs};fontColor={colour};")

    def badge(self, x, y, label, colour=ACCENT, d=28):
        return self.vertex(x, y, d, d, f"<b>{esc(label)}</b>",
                           f"ellipse;html=1;fillColor={colour};strokeColor=#ffffff;strokeWidth=1.5;fontColor=#ffffff;"
                           f"fontFamily={FONT};fontSize=10.5;align=center;verticalAlign=middle;")

    def flow(self, src, tgt, label="", colour=PLAIN, dashed=False, exit=None, entry=None, points=(), width=2,
             both=False, fs=11):
        style = (f"html=1;rounded=1;edgeStyle=orthogonalEdgeStyle;strokeColor={colour};strokeWidth={width};"
                 f"endArrow=block;endFill=1;endSize=7;fontFamily={FONT};fontSize={fs};fontColor={INK};"
                 f"labelBackgroundColor=#ffffff;align=center;verticalAlign=middle;")
        if dashed:
            style += "dashed=1;dashPattern=8 5;"
        if both:
            style += "startArrow=block;startFill=1;startSize=7;"
        if exit:
            style += f"exitX={exit[0]:g};exitY={exit[1]:g};exitDx=0;exitDy=0;exitPerimeter=0;"
        if entry:
            style += f"entryX={entry[0]:g};entryY={entry[1]:g};entryDx=0;entryDy=0;entryPerimeter=0;"
        return self.edge(src, tgt, label, style, points)

    def legend(self, x, y, items, w=260):
        h = 34 + 22 * len(items)
        self.box(x, y, w, h, "<b>Legend</b>", fs=12)
        for i, (colour, dashed, label) in enumerate(items):
            yy = y + 38 + 22 * i
            a = self.vertex(x + 12, yy, 1, 1, "", "text;html=1;")
            b = self.vertex(x + 52, yy, 1, 1, "", "text;html=1;")
            st = f"html=1;strokeColor={colour};strokeWidth=2;endArrow=block;endFill=1;endSize=5;"
            st += "dashed=1;dashPattern=8 5;" if dashed else ""
            self.edge(a, b, "", st)
            self.text(x + 60, yy - 9, w - 66, 18, esc(label), fs=11.5)


def rows(items, fs=11.5, colour=INK2):
    return "<br>".join(f'<font color="{colour}" style="font-size:{fs:g}px">{esc(r)}</font>' for r in items)


LEGEND = [
    (PERSON, False, "The person's OBO token"),
    (IDENTITY, False, "Keyring's identity"),
    (INBOUND, False, "Event Grid delivery"),
    (PLAIN, False, "Browser and other"),
]


# =====================================================================================================
# 1. Logical architecture
# =====================================================================================================
def page_logical():
    p = Page("logical", "1 Logical architecture", 1400, 900)
    p.title("Keyring: logical architecture",
            "One stateless web app in front of Azure Key Vault. Every call that reads or changes a person's data is made as that person.")

    p.zone(20, 80, 230, 360, "People", "Browser only holds a session ID")
    users = p.card(32, 130, 206, 60, "users", "People", ["Staff who use Key Vault"])
    browser = p.card(32, 220, 206, 70, "browser", "Web browser", ["HTML, CSS, three small", "same-origin scripts"])
    p.box(32, 310, 206, 116, "<b>Kept in the browser</b><br>" + rows([
        "Session cookie (random ID)", "Pinned and recent names", "(localStorage, keyring.pins)", "Nothing else"]))
    p.flow(users, browser, "", PLAIN, exit=(0.5, 1), entry=(0.5, 0), width=1.5)
    p.zone(20, 470, 230, 130, "Inbound", "No session: an Entra token instead", fill=DANGER_TINT, stroke=DANGER_RULE)
    eg = p.card(32, 520, 206, 64, "eventgrid", "Azure Event Grid", ["Key Vault expiry events"], stroke=DANGER_RULE)

    p.zone(290, 80, 470, 790, "Keyring", "Rust, Axum and Askama, one container")
    web = p.card(305, 130, 440, 70, "appservice", "Web server and routes",
                 ["src/routes: pages, forms, CSV, /healthz, /hooks/eventgrid"])
    p.card(305, 215, 215, 92, None, "Guards before any Azure call",
           ["Origin, form token, typed", "name, step-up, reason, policy,", "owner rule, audit required"])
    auth = p.card(530, 215, 215, 92, None, "Sign-in and sessions",
                  ["src/auth: OIDC with PKCE,", "in-memory sessions, step-up,", "Event Grid token check"])
    p.card(305, 322, 215, 92, None, "Audit events",
           ["src/audit: one event per", "audited request, to stdout", "and the optional sink"])
    azc = p.card(530, 322, 215, 92, None, "Azure clients",
                 ["src/azure: Key Vault, ARM,", "Resource Graph, Log Analytics,", "PIM. All as the person"])
    p.card(305, 429, 215, 92, None, "Email sender",
           ["src/notify: queue, rate limit,", "health notices, expiry", "notices from Event Grid"])
    mi = p.card(530, 429, 215, 92, "mi", "Managed identity",
                ["src/auth/assertion.rs:", "one identity, three uses"], stroke=WARN_RULE, fill=WARN_TINT)
    p.box(305, 536, 440, 200, "<b>What Keyring holds</b><br>" + rows([
        "Per session, in memory only: the person's tokens, exchanged tokens per",
        "resource, each vault's item list for 60 seconds, permission hints for",
        "5 minutes, a pending upload or import for 10 minutes.",
        "",
        "No database, no disk, no cache shared between sessions.",
        "Secret values pass through memory on the way to the browser",
        "and are never logged, cached or written down.",
        "A restart signs everyone out."]))
    p.flow(browser, web, "HTTPS", PLAIN, exit=(1, 0.5), entry=(0, 0.5), points=((262, 255), (262, 165)))
    p.flow(eg, web, "webhook", INBOUND, exit=(1, 0.5), entry=(0, 0.85), points=((276, 552), (276, 189)))

    p.zone(800, 80, 580, 260, "Microsoft Entra ID", "One tenant")
    entra = p.card(815, 130, 270, 64, "entra", "Microsoft Entra ID", ["Sign-in, OBO, Conditional Access"])
    appreg = p.card(1095, 130, 270, 64, "appreg", "App registration", ["Delegated permissions only"])
    p.card(815, 230, 270, 64, "pim", "Entra PIM for Azure resources", ["Read and requested through ARM"])
    p.card(1095, 230, 270, 64, "ca", "Conditional Access", ["Authentication context for step-up"])

    p.zone(800, 360, 580, 510, "Azure", "People's subscriptions, plus Keyring's own resource group")
    asp = p.zone(815, 410, 550, 170, "Called as the signed-in person", "", fill=ACCENT_TINT, stroke=ACCENT_RULE)
    p.card(830, 440, 260, 56, "keyvault", "Azure Key Vault", ["People's vaults, data plane"])
    p.card(1095, 440, 255, 56, "arm", "Azure Resource Manager", ["Settings, roles, PIM"])
    p.card(830, 506, 260, 56, "graph", "Azure Resource Graph", ["Vault discovery"])
    law = p.card(1095, 506, 255, 56, "law", "Log Analytics", ["Key Vault logs, KeyringAudit_CL"])
    asi = p.zone(815, 600, 550, 110, "Called as Keyring's managed identity", "", fill=WARN_TINT, stroke=WARN_RULE)
    dcr = p.card(830, 630, 260, 64, "dcr", "Logs Ingestion API", ["One data collection rule"])
    p.card(1095, 630, 255, 64, "acs", "Azure Communication Services", ["Email, one resource"])
    p.flow(dcr, law, "rows", IDENTITY, exit=(1, 0.3), entry=(0.3, 1), points=((1110, 649), (1110, 600), (1171, 600)), width=1.5)
    p.legend(1095, 728, LEGEND, w=270)

    p.flow(auth, entra, "OIDC, refresh, OBO", PERSON, exit=(1, 0.5), entry=(0, 0.5), points=((780, 261), (780, 162)))
    p.flow(azc, asp, "", PERSON, exit=(1, 0.5), entry=(0, 0.35), points=((780, 368), (780, 470)))
    p.flow(mi, appreg, "federated credential", IDENTITY, exit=(1, 0.3), entry=(1, 0.5), points=((795, 457), (795, 318), (1374, 318), (1374, 162)))
    p.flow(mi, asi, "audit rows, email", IDENTITY, exit=(1, 0.8), entry=(0, 0.5), points=((785, 503), (785, 655)))
    return p


# =====================================================================================================
# 2. Identity and token flows
# =====================================================================================================
def page_identity():
    p = Page("identity", "2 Identity and token flows", 1400, 860)
    p.title("Keyring: identity and token flows",
            "Left: the person's tokens, used for every read or change of their data. Right: Keyring's one managed identity and its three uses.")

    p.zone(20, 80, 680, 760, "As the signed-in person", "Delegated permissions, on-behalf-of (OBO)",
           fill=ACCENT_TINT, stroke=ACCENT_RULE)
    person = p.card(40, 130, 200, 64, "users", "Person", ["Signs in with Entra ID"])
    browser = p.card(40, 230, 200, 64, "browser", "Browser", ["Holds a session ID only"])
    keyring = p.card(280, 230, 200, 64, "appservice", "Keyring", ["Server-side session"])
    entra = p.card(480, 130, 200, 64, "entra", "Microsoft Entra ID", ["login.microsoftonline.com"])
    p.flow(person, browser, "", PLAIN, exit=(0.5, 1), entry=(0.5, 0), width=1.5)
    p.flow(browser, keyring, "", PLAIN)
    p.flow(keyring, entra, "1. Code + PKCE", PERSON, exit=(0.5, 0), entry=(0, 0.5), points=((380, 162),))
    p.box(40, 320, 640, 120, "<b>1. Sign-in</b><br>" + rows([
        "Authorisation code flow with PKCE (S256), state and nonce. Scopes: openid, profile, offline_access",
        "and Keyring's own API scope (api://&lt;client ID&gt;/access_as_user, or ENTRA_API_SCOPE).",
        "The ID token is checked (signature, issuer, audience, expiry, nonce). The access token for Keyring's API",
        "and the refresh token stay in the server's memory. Step-up adds acrs claims or prompt=login with max_age."], colour=INK))
    p.box(40, 455, 640, 150, "<b>2. On-behalf-of exchange, per resource, cached per session until 5 minutes before expiry</b><br>" + rows([
        "https://vault.azure.net/.default           Key Vault data plane",
        "https://management.azure.com/.default   ARM and Resource Graph (roles, PIM, diagnostic settings)",
        "https://api.loganalytics.io/.default       Log Analytics queries (audit pages, Used by, Keyring activity)",
        "Grant: urn:ietf:params:oauth:grant-type:jwt-bearer with requested_token_use=on_behalf_of.",
        "Keyring authenticates the exchange with its client secret or the federated credential (right)."], colour=INK))
    kv = p.card(40, 630, 200, 64, "keyvault", "Azure Key Vault", ["As the person"])
    arm = p.card(260, 630, 200, 64, "arm", "ARM and Resource Graph", ["As the person"])
    law = p.card(480, 630, 200, 64, "law", "Log Analytics", ["As the person"])
    p.text(40, 710, 640, 110, rows([
        "No client-credentials grant, app-only token or managed identity is ever used on this side.",
        "Key Vault RBAC (or access policies) decides every request. Keyring's permission hints only grey out buttons.",
        "PIM activation is a PUT to roleAssignmentScheduleRequests with the person's ARM token."], colour=INK, fs=12), fs=12)
    for t, x in ((kv, 140), (arm, 360), (law, 580)):
        p.flow(keyring, t, "", PERSON, exit=(1, 0.5), entry=(0.5, 0), points=((690, 262), (690, 615), (x, 615)), width=1.5)

    p.zone(720, 80, 660, 760, "As Keyring's managed identity", "One user-assigned identity: KEYRING_MANAGED_IDENTITY_CLIENT_ID",
           fill=WARN_TINT, stroke=WARN_RULE)
    k2 = p.card(740, 130, 220, 64, "appservice", "Keyring", ["Asks the local token service"])
    imds = p.card(1000, 130, 360, 64, "mi", "Managed identity", ["IDENTITY_ENDPOINT on localhost or 169.254.0.0/16"])
    p.flow(k2, imds, "", IDENTITY)
    fed = p.card(740, 240, 620, 90, "entra", "1. Federated credential (optional, replaces the client secret)",
                 ["Audience api://AzureADTokenExchange, sent to Entra as client_assertion",
                  "on sign-in, refresh and OBO. Never sent with a client secret."])
    ing = p.card(740, 350, 620, 90, "dcr", "2. Audit sink (optional)",
                 ["Audience https://monitor.azure.com. Writes Keyring's audit events through one",
                  "data collection rule. Role: Monitoring Metrics Publisher on that rule only."])
    acs = p.card(740, 460, 620, 90, "acs", "3. Email (optional)",
                 ["Audience https://communication.azure.com. POST /emails:send on one resource.",
                  "Role: custom, CommunicationServices/Read and /Write on that resource, assigned directly."])
    for t, y in ((fed, 285), (ing, 395), (acs, 505)):
        p.flow(imds, t, "", IDENTITY, exit=(1, 0.5), entry=(1, 0.5), points=((1372, 162), (1372, y)), width=1.5)
    p.card(740, 570, 620, 80, "keyvault", "Platform only: Keyring's own config vault",
           ["App Service or Container Apps resolves Key Vault references at start. Role: Key Vault",
            "Secrets User on the config vault (client secret, session secret). Keyring's code never calls it."],
           dashed=True)
    p.box(740, 665, 620, 155, "<b>What the identity does not have</b><br>" + rows([
        "No role on any vault people use, on Resource Graph, or on any workspace's data.",
        "It never reads KeyringAudit_CL: the audit page reads it as the person.",
        "No access key, connection string, SMTP password or second identity.",
        "The app registration holds delegated permissions only, so the federated credential gives",
        "no vault access while nobody is signed in. Adding an application permission is a security change."], colour=INK))
    return p


# =====================================================================================================
# 3. Network and data flows
# =====================================================================================================
def page_network():
    p = Page("network", "3 Network and data flows", 1400, 880)
    p.title("Keyring: network and data flows",
            "All traffic is HTTPS on port 443. Private vaults need Keyring inside a network that reaches their private endpoints.")

    browser = p.card(20, 140, 200, 70, "browser", "Web browser", ["People's network"])
    eg = p.card(20, 420, 200, 70, "eventgrid", "Azure Event Grid", ["Delivers to the public", "address only"], stroke=DANGER_RULE)

    p.zone(260, 80, 640, 640, "Azure virtual network (optional)", "Needed for private vaults and internal ingress",
           fill=PAPER, dashed=True)
    p.zone(280, 130, 300, 300, "Keyring subnet", "Delegated to Microsoft.Web or Microsoft.App", fill=SURFACE)
    keyring = p.card(295, 190, 270, 80, "containerapp", "Keyring",
                     ["App Service with VNet integration", "or a Container Apps environment"])
    p.box(295, 285, 215, 130, "<b>Ingress</b><br>" + rows([
        "Public, HTTPS only, or private:",
        "internal Container Apps or an",
        "App Service private endpoint.",
        "The webhook needs it public."]))
    p.zone(610, 130, 270, 300, "Private endpoint subnet", "", fill=SURFACE)
    pe = p.card(625, 240, 240, 64, "pe", "Private endpoint", ["One per private vault"])
    dns = p.card(625, 330, 240, 80, "dns", "Private DNS zone", ["privatelink.vaultcore.azure.net", "linked to Keyring's VNet"])
    p.flow(keyring, pe, "", PERSON, exit=(1, 0.5), entry=(0, 0.5))
    p.flow(keyring, dns, "name lookup", PLAIN, dashed=True, exit=(1, 0.85), entry=(0, 0.5), width=1.5)
    pkv = p.card(625, 460, 240, 70, "keyvault", "Private Key Vault", ["Public access off"])
    p.flow(pe, pkv, "", PERSON, exit=(1, 0.5), entry=(1, 0.5), points=((890, 272), (890, 495)))
    cfg = p.card(295, 460, 270, 70, "keyvault", "Keyring config vault", ["Optional private endpoint"])
    p.flow(keyring, cfg, "platform only", WARN_RULE, exit=(0.9, 1), entry=(0.9, 0), dashed=True, width=1.5)
    p.box(280, 560, 600, 145, "<b>What crosses the network</b><br>" + rows([
        "Browser to Keyring: pages, forms and one revealed value at a time, with Cache-Control: no-store.",
        "Keyring to Azure: the person's OBO token on every data call; Keyring's identity token only",
        "for the federated credential, the audit sink and email. TLS through rustls with the ring provider,",
        "operating system roots or SSL_CERT_FILE. No redirects followed, no plain HTTP except localhost.",
        "Outbound proxies: HTTPS_PROXY and NO_PROXY are honoured; the local token service never uses one."], colour=INK))

    p.zone(940, 80, 440, 780, "Public Azure endpoints (port 443)", "Reached directly or through the egress path", fill=PAPER)
    hosts = [
        ("entra", "login.microsoftonline.com", ["Sign-in, refresh, OBO, metadata, keys"], PERSON),
        ("arm", "management.azure.com", ["ARM and Resource Graph"], PERSON),
        ("law", "api.loganalytics.io", ["Audit queries as the person"], PERSON),
        ("keyvault", "<vault>.vault.azure.net", ["Vaults reached publicly"], PERSON),
        ("dcr", "<rule>.<region>.ingest.monitor.azure.com", ["Audit sink, as the identity"], IDENTITY),
        ("acs", "<resource>.communication.azure.com", ["Email, as the identity"], IDENTITY),
        ("acr", "Container registry", ["Image pulls by the platform"], PLAIN),
    ]
    y = 130
    for icon, name, lines, colour in hosts:
        c = p.card(960, y, 400, 64, icon, name, lines,
                   stroke={PERSON: RULE_STRONG, IDENTITY: WARN_RULE, PLAIN: RULE}[colour])
        p.flow(keyring, c, "", colour, exit=(1, 0.2), entry=(0, 0.5), points=((920, 206), (920, y + 32)), width=1.5)
        y += 80
    p.flow(browser, keyring, "HTTPS", PLAIN, exit=(1, 0.5), entry=(0, 0.3))
    p.flow(eg, keyring, "webhook", INBOUND, exit=(1, 0.5), entry=(0, 0.75), points=((250, 455), (250, 250)))
    p.legend(20, 560, LEGEND, w=225)
    return p


# =====================================================================================================
# 4. Notification flows
# =====================================================================================================
def page_notify():
    p = Page("notify", "4 Notification flows", 1400, 800)
    p.title("Keyring: notification flows",
            "Every email leaves through one sender and one Azure Communication Services resource, as Keyring's managed identity.")

    p.zone(20, 80, 420, 330, "Expiry, pushed by Event Grid", "notify type expiry", fill=DANGER_TINT, stroke=DANGER_RULE)
    kv = p.card(35, 130, 180, 64, "keyvault", "Azure Key Vault", ["Near expiry, expired"])
    topic = p.card(245, 130, 180, 64, "eventgrid", "Event Grid", ["System topic"])
    sub = p.card(245, 220, 180, 80, "egsub", "Subscription", ["Entra auth, header", "keyring-notify"])
    p.flow(kv, topic, "", PLAIN)
    p.flow(topic, sub, "", PLAIN, exit=(0.5, 1), entry=(0.5, 0))
    p.box(35, 220, 195, 175, "<b>Six events</b><br>" + rows([
        "SecretNearExpiry", "SecretExpired", "KeyNearExpiry", "KeyExpired",
        "CertificateNearExpiry", "CertificateExpired"]))

    p.zone(470, 80, 450, 690, "Keyring", "")
    hook = p.card(485, 130, 420, 110, None, "POST /hooks/eventgrid",
                  ["Entra token: RS256, issuer, audience, tenant, expiry,",
                   "Event Grid's app ID, the subscriber app role, app-only.",
                   "1 MB, 1 to 50 events, topic must be a Key Vault ID.",
                   "120 good and 60 bad deliveries a minute. Dedupe 24 hours."])
    p.flow(sub, hook, "Entra token", INBOUND, exit=(1, 0.5), entry=(0, 0.5), points=((450, 260), (450, 185)))
    health = p.card(485, 260, 420, 110, None, "Health notices (timer, every 30 seconds)",
                    ["Audit sink degraded for 5 minutes, and recovered.",
                     "Refusal burst: over KEYRING_NOTIFY_BURST_THRESHOLD refused",
                     "or denied events from one person or IP in 15 minutes.",
                     "Client secret expiry: 30, 14, 7 and 1 days, and passed."])
    obs = p.card(485, 390, 420, 64, None, "Audit observer", ["Counts refused and denied events as they are written"])
    p.flow(obs, health, "", PLAIN, exit=(0.5, 0), entry=(0.5, 1), width=1.5)
    sender = p.card(485, 490, 420, 130, None, "Sender (src/notify/sender.rs)",
                    ["Strict address parsing, KEYRING_NOTIFY_ALLOWED_DOMAINS,",
                     "KEYRING_NOTIFY_RATE_PER_HOUR per recipient per type.",
                     "Queue of 1,000, retries with Retry-After, one Repeatability-",
                     "Request-Id per email, given up after five minutes.",
                     "One notify.sent or notify.failed audit event per email."], stroke=WARN_RULE)
    p.flow(hook, sender, "admins, or the header", PLAIN, exit=(0, 0.8), entry=(0, 0.5), points=((477, 218), (477, 555)))
    p.flow(health, sender, "admins only", PLAIN, exit=(1, 0.5), entry=(1, 0.25), points=((913, 315), (913, 522)))
    p.box(485, 640, 420, 115, "<b>What an email holds</b><br>" + rows([
        "Fixed subject: [Keyring], the type, the item.",
        "Fixed text, checked names, counts, dates, reason codes,",
        "a link built from APP_BASE_URL. Never a value, token,",
        "private key, Azure message or a typed reason."]))

    p.zone(950, 80, 430, 690, "Out", "", fill=WARN_TINT, stroke=WARN_RULE)
    mi = p.card(965, 130, 400, 70, "mi", "Managed identity token", ["Audience https://communication.azure.com"])
    acs = p.card(965, 230, 400, 80, "acs", "Azure Communication Services",
                 ["POST /emails:send?api-version=2025-09-01", "Custom role: Read and Write on this resource"])
    mail = p.card(965, 340, 400, 70, None, "Recipients", ["To addresses only. No cc or bcc. Tracking off"])
    p.flow(mi, acs, "", IDENTITY, exit=(0.5, 1), entry=(0.5, 0))
    p.flow(acs, mail, "", PLAIN, exit=(0.5, 1), entry=(0.5, 0))
    p.flow(sender, acs, "", IDENTITY, exit=(1, 0.75), entry=(0, 0.5), points=((935, 587), (935, 270)))
    p.box(965, 440, 400, 150, "<b>Health of email itself</b><br>" + rows([
        "/healthz/notify: ok, degraded or off, with counts.",
        "503 while sending has failed for a minute.",
        "A failing sender is logged once per incident",
        "and never emailed about."]))
    p.legend(965, 620, LEGEND[1:], w=400)
    return p


# =====================================================================================================
# 5. Deployment
# =====================================================================================================
def page_deploy():
    p = Page("deploy", "5 Deployment", 1400, 860)
    p.title("Keyring: deployment",
            "Bicep in infra/. Two hosting paths share the same modules. Nothing in the repository deploys by itself.")

    p.zone(20, 80, 900, 760, "Keyring's resource group", "az deployment group create, run by the deployer")
    p.zone(40, 130, 420, 330, "App Service path", "infra/app-service/main.bicep", fill=SURFACE)
    p.card(55, 180, 390, 64, "plan", "App Service plan", ["<name>-plan, default P0v3"])
    p.card(55, 254, 390, 64, "appservice", "Web app", ["<name>, HTTPS only, /healthz probe, port 3000"])
    p.box(55, 328, 390, 118, "<b>Options</b><br>" + rows([
        "vnetIntegrationSubnetId (route all) for private vaults",
        "inboundPrivateEndpointSubnetId for private ingress",
        "logAnalyticsWorkspaceId for console and HTTP logs",
        "useManagedIdentityForRegistry for a private ACR"]))

    p.zone(480, 130, 420, 330, "Container Apps path", "infra/container-apps/main.bicep", fill=SURFACE)
    p.card(495, 180, 390, 64, "law", "Log Analytics workspace", ["<name>-logs, console logs"])
    p.card(495, 254, 390, 64, "cae", "Container Apps environment", ["<name>-env, external or internal"])
    p.card(495, 328, 390, 64, "containerapp", "Container app", ["<name>, sticky sessions above 1 replica"])
    p.box(495, 402, 390, 44, rows(["Two runs: configOnly=true first, then the app"], colour=INK))

    p.zone(40, 480, 860, 140, "Shared modules (both paths)", "infra/modules", fill=SURFACE)
    p.card(55, 530, 270, 74, "mi", "Managed identity", ["<name>-id, user-assigned"], stroke=WARN_RULE)
    p.card(340, 530, 270, 74, "keyvault", "Config vault", ["config-vault.bicep: RBAC, soft", "delete, purge protection"])
    p.card(625, 530, 260, 74, "pe", "Private endpoints, DNS", ["private-endpoint.bicep,", "private-dns.bicep"])

    p.zone(40, 640, 860, 185, "Optional, by parameter", "", fill=SURFACE, dashed=True)
    p.card(55, 690, 270, 120, "dcr", "Audit sink: auditWorkspaceId",
           ["audit-sink.bicep: KeyringAudit_CL,", "Direct rule, Monitoring Metrics", "Publisher on the rule"], stroke=WARN_RULE)
    p.card(340, 690, 270, 120, "acs", "Email: notifyDomain",
           ["notify.bicep: Email service and", "domain, <name>-acs, custom role", "Keyring email sender (<name>)"], stroke=WARN_RULE)
    p.card(625, 690, 260, 120, "entra", "useFederatedCredential",
           ["The app registration trusts", "<name>-id. No client secret", "in the config vault"])

    p.zone(950, 80, 430, 760, "Separate deployments", "Run against other scopes when wanted", fill=PAPER)
    p.card(965, 130, 400, 110, "eventgrid", "Expiry alerts: infra/alerts/main.bicep",
           ["expiry-events.bicep: system topic and", "subscription per vault, to an action", "group or (notifyVia = 'keyring') the webhook"])
    p.card(965, 255, 400, 100, "monitor", "Access alerts: infra/alerts/access.bicep",
           ["Log search alerts on the vault's workspace:", "watched reads, purges, refusals. Run as", "Azure Monitor's own identity"])
    p.card(965, 370, 400, 110, "sentinel", "Sentinel: infra/sentinel/main.bicep",
           ["ASIM parsers, analytic rules (created off),", "hunting queries and a workbook for", "KeyringAudit_CL"])
    p.card(965, 495, 400, 100, "dns", "Private DNS: infra/modules/private-dns.bicep",
           ["privatelink.vaultcore.azure.net zone and", "VNet link, run on its own"])
    p.box(965, 610, 400, 215, "<b>Settings</b><br>" + rows([
        "Every app setting is listed in the template, so a setting",
        "added by hand is removed by the next deployment.",
        "Secrets are set after deployment with az keyvault secret",
        "set, never in a template or parameter file.",
        "CI runs az bicep build on every template and example",
        "parameter file. CI deploys nothing."]))
    return p


# =====================================================================================================
# 6. Security controls overlay
# =====================================================================================================
def page_controls():
    p = Page("controls", "6 Security controls", 1400, 900)
    p.title("Keyring: security controls overlay",
            "C-numbers match the controls table in chapter 8. Each badge sits where the control is enforced.")

    browser = p.card(20, 130, 230, 80, "browser", "Web browser", ["Session ID cookie only"])
    p.badge(222, 116, "C4")
    p.badge(190, 116, "C21")

    p.zone(290, 80, 560, 780, "Keyring", "")
    edge = p.card(305, 130, 530, 70, None, "Request edge", ["Header timeout, body limits, 90 s limit, 512 connections, security headers"])
    p.badge(807, 116, "C18")
    p.badge(775, 116, "C6")
    sess = p.card(305, 215, 260, 90, None, "Sign-in and sessions", ["OIDC with PKCE, state, nonce.", "In-memory sessions, timeouts"])
    p.badge(537, 201, "C3")
    p.badge(505, 201, "C4")
    guard = p.card(575, 215, 260, 90, None, "Form guards", ["Origin check and form token", "bound to the vault"])
    p.badge(807, 201, "C5")
    gates = p.card(305, 320, 530, 90, None, "Gates before any Azure call",
                   ["Typed name and purge off, step-up, reason, password policy, owner rule,", "audit required, input checked against Key Vault's rules"])
    p.badge(807, 306, "C9")
    p.badge(775, 306, "C10")
    p.badge(743, 306, "C11")
    p.badge(711, 306, "C16")
    p.badge(679, 306, "C7")
    obo = p.card(305, 425, 260, 90, None, "Azure clients", ["Person's OBO token on every", "data call. Key Vault decides"])
    p.badge(537, 411, "C1")
    p.badge(505, 411, "C22")
    http = p.card(575, 425, 260, 90, None, "Outbound HTTP client", ["rustls and ring, HTTPS only,", "no redirects, fixed hosts"])
    p.badge(807, 411, "C17")
    sec = p.card(305, 530, 260, 90, None, "Secret handling", ["Secret and AccessToken print", "[redacted], zeroised, never logged"])
    p.badge(537, 516, "C8")
    aud = p.card(575, 530, 260, 90, None, "Audit events", ["One per audited request,", "coverage tested"])
    p.badge(807, 516, "C12")
    p.badge(775, 516, "C13")
    hook = p.card(305, 635, 260, 90, None, "Event Grid webhook", ["Entra token checked first,", "topic check, limits, dedupe"])
    p.badge(537, 621, "C15")
    mail = p.card(575, 635, 260, 90, None, "Email sender", ["Allow-list, rate limit,", "fixed content"])
    p.badge(807, 621, "C14")
    p.card(305, 740, 530, 100, None, "Build and runtime",
           ["Distroless static image, non-root, read-only, no capabilities.",
            "forbid(unsafe_code), cargo deny and cargo audit, pinned toolchain and actions, SBOM."])
    p.badge(807, 826, "C19")
    p.badge(775, 826, "C20")

    p.zone(890, 80, 490, 780, "Microsoft cloud", "")
    entra = p.card(905, 130, 460, 80, "entra", "Microsoft Entra ID", ["Delegated-only app registration, Conditional Access"])
    p.badge(1337, 116, "C2")
    kv = p.card(905, 230, 460, 80, "keyvault", "Azure Key Vault", ["RBAC or access policies decide every request"])
    p.badge(1337, 216, "C1")
    mi = p.card(905, 330, 460, 80, "mi", "Keyring's managed identity", ["No role on people's vaults or workspace data"], stroke=WARN_RULE)
    p.badge(1337, 316, "C2")
    dcr = p.card(905, 430, 460, 80, "dcr", "Logs Ingestion API", ["Monitoring Metrics Publisher on one rule"], stroke=WARN_RULE)
    p.badge(1337, 416, "C13")
    acs = p.card(905, 530, 460, 80, "acs", "Azure Communication Services", ["Custom role, Read and Write, one resource"], stroke=WARN_RULE)
    p.badge(1337, 516, "C14")
    eg = p.card(905, 630, 460, 80, "eventgrid", "Azure Event Grid", ["Secure webhook delivery with an Entra token"], stroke=DANGER_RULE)
    p.badge(1337, 616, "C15")

    p.flow(browser, edge, "HTTPS", PLAIN, exit=(1, 0.5), entry=(0, 0.5), points=((275, 170), (275, 165)))
    p.flow(obo, http, "", PERSON, exit=(1, 0.5), entry=(0, 0.5), width=1.5)
    p.flow(http, kv, "", PERSON, exit=(1, 0.15), entry=(0, 0.5), points=((875, 438.5), (875, 270)))
    p.flow(http, entra, "", PERSON, exit=(1, 0.05), entry=(0, 0.5), points=((885, 429.5), (885, 170)))
    p.flow(aud, dcr, "", IDENTITY, exit=(1, 0.5), entry=(0, 0.5), points=((865, 575), (865, 470)))
    p.flow(mail, acs, "", IDENTITY, exit=(1, 0.5), entry=(0, 0.5), points=((855, 680), (855, 570)))
    p.flow(eg, hook, "", INBOUND, exit=(0.5, 1), entry=(0.5, 1), points=((1135, 733), (435, 733)))
    p.legend(20, 640, LEGEND, w=255)
    return p


def build():
    pages = [page_logical(), page_identity(), page_network(), page_notify(), page_deploy(), page_controls()]
    xml = ('<mxfile host="build_drawio.py" agent="Keyring diagram generator" version="1" compressed="false">'
           + "".join(pg.xml() for pg in pages) + "</mxfile>\n")
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(xml)
    print(f"Wrote {OUT} ({len(pages)} pages)")


if __name__ == "__main__":
    build()
