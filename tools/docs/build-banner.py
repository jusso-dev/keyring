#!/usr/bin/env python3
"""Renders Keyring's high-resolution 3200x1400 Retina hero banner
(docs/images/keyring-banner.png) using headless Chromium via Playwright.

Uses the exact Keyring split-ring + precision-key logo geometry at 2x Retina
scale so typography, glassmorphic vault nodes and vector strokes stay razor
sharp on high-DPI displays in both GitHub README and the Docusaurus docs site.

Usage: python3 tools/docs/build-banner.py
"""
import json
import os
import shlex
import subprocess
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT_PNG = os.path.join(REPO, "docs", "images", "keyring-banner.png")

BANNER_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body {
    width: 1600px;
    height: 700px;
    overflow: hidden;
    background: #050c1b;
    font-family: "Inter", "SF Pro Display", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    text-rendering: geometricPrecision;
  }
  .stage {
    position: relative;
    width: 1600px;
    height: 700px;
    background:
      radial-gradient(ellipse 820px 620px at 26% 52%, rgba(27, 94, 235, 0.34), transparent 70%),
      radial-gradient(ellipse 680px 520px at 84% 16%, rgba(56, 189, 248, 0.16), transparent 68%),
      radial-gradient(ellipse 520px 360px at 78% 88%, rgba(37, 99, 235, 0.18), transparent 70%),
      linear-gradient(135deg, #040915 0%, #08142b 48%, #0b1c3c 100%);
    overflow: hidden;
  }
  /* Precision architectural grid fading softly at the edges */
  .grid {
    position: absolute;
    inset: 0;
    background-image:
      linear-gradient(to right, rgba(148, 197, 255, 0.055) 1px, transparent 1px),
      linear-gradient(to bottom, rgba(148, 197, 255, 0.055) 1px, transparent 1px);
    background-size: 40px 40px;
    -webkit-mask-image: radial-gradient(ellipse 86% 86% at 46% 50%, #000 35%, transparent 100%);
    mask-image: radial-gradient(ellipse 86% 86% at 46% 50%, #000 35%, transparent 100%);
  }
  /* Diagonal volumetric light sheen */
  .beam {
    position: absolute;
    inset: -120px;
    background: linear-gradient(
      118deg,
      transparent 18%,
      rgba(56, 189, 248, 0.05) 36%,
      rgba(147, 197, 253, 0.09) 43%,
      transparent 56%
    );
    pointer-events: none;
  }
  /* Crisp subtle frame border */
  .frame-border {
    position: absolute;
    inset: 0;
    border: 1px solid rgba(148, 197, 255, 0.14);
    pointer-events: none;
  }
  /* Full-canvas background vector layer: vault dial rings, fibre streams, isometric vault cubes */
  .bg-svg {
    position: absolute;
    inset: 0;
    width: 1600px;
    height: 700px;
  }
  /* Main flex layout */
  .layout {
    position: relative;
    z-index: 2;
    width: 100%;
    height: 100%;
    display: flex;
    align-items: center;
    padding: 0 92px 0 112px;
    gap: 88px;
  }
  /* Left hero emblem zone */
  .hero-left {
    position: relative;
    width: 470px;
    height: 470px;
    flex: none;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  /* 3D-elevated squircle logo card */
  .emblem-wrap {
    position: relative;
    width: 268px;
    height: 268px;
    transform: perspective(950px) rotateY(10deg) rotateX(5deg);
    filter: drop-shadow(0 32px 54px rgba(2, 8, 24, 0.82)) drop-shadow(0 0 42px rgba(37, 117, 252, 0.42));
  }
  .emblem-depth {
    position: absolute;
    inset: 0;
    border-radius: 62px;
    background: linear-gradient(150deg, #0d2b66 0%, #07193d 100%);
    transform: translate(-11px, 12px);
    box-shadow: inset 0 1px 1px rgba(147, 197, 253, 0.25);
  }
  .emblem-face {
    position: relative;
    width: 268px;
    height: 268px;
    display: block;
  }
  /* Right copy zone */
  .hero-right {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 18px;
    padding-right: 12px;
  }
  .kicker {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    padding: 7px 16px;
    border-radius: 999px;
    background: rgba(14, 38, 84, 0.62);
    border: 1px solid rgba(125, 211, 252, 0.28);
    color: #bae6fd;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    box-shadow: 0 4px 18px rgba(3, 10, 26, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.08);
  }
  .kicker-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #38bdf8;
    box-shadow: 0 0 10px #38bdf8, 0 0 18px rgba(56, 189, 248, 0.75);
  }
  h1 {
    font-size: 112px;
    line-height: 0.98;
    font-weight: 800;
    letter-spacing: -0.04em;
    background: linear-gradient(180deg, #ffffff 30%, #dbeafe 100%);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
    filter: drop-shadow(0 6px 24px rgba(4, 12, 32, 0.5));
  }
  .subtitle {
    font-size: 32px;
    line-height: 1.2;
    font-weight: 600;
    letter-spacing: -0.015em;
    color: #7dd3fc;
    margin-top: -2px;
  }
  .lead {
    max-width: 740px;
    font-size: 19px;
    line-height: 1.5;
    font-weight: 400;
    color: #cbd5e1;
    margin-top: 2px;
  }
  .pills {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-top: 14px;
  }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 9px;
    padding: 10px 18px;
    border-radius: 999px;
    background: linear-gradient(180deg, rgba(19, 43, 92, 0.72), rgba(11, 25, 56, 0.78));
    border: 1px solid rgba(147, 197, 253, 0.28);
    color: #f1f5f9;
    font-size: 15.5px;
    font-weight: 600;
    letter-spacing: 0.005em;
    box-shadow: 0 6px 20px rgba(2, 8, 24, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.12);
  }
  .pill svg {
    width: 17px;
    height: 17px;
    color: #38bdf8;
    flex: none;
  }
</style>
</head>
<body>
<div class="stage">
  <div class="grid"></div>
  <div class="beam"></div>

  <!-- Precision SVG vault rings, calibrated ticks, fibre paths & translucent Azure vault nodes -->
  <svg class="bg-svg" viewBox="0 0 1600 700" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <radialGradient id="floor-glow" cx="347" cy="542" r="240" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.30"/>
        <stop offset="55%" stop-color="#1d63ed" stop-opacity="0.12"/>
        <stop offset="100%" stop-color="#1d63ed" stop-opacity="0"/>
      </radialGradient>
      <linearGradient id="ring-grad" x1="120" y1="120" x2="580" y2="580" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.45"/>
        <stop offset="50%" stop-color="#60a5fa" stop-opacity="0.14"/>
        <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.40"/>
      </linearGradient>
      <linearGradient id="stream-l" x1="115" y1="418" x2="275" y2="375" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.85"/>
        <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.08"/>
      </linearGradient>
      <linearGradient id="stream-r" x1="465" y1="295" x2="596" y2="200" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stop-color="#60a5fa" stop-opacity="0.10"/>
        <stop offset="100%" stop-color="#7dd3fc" stop-opacity="0.90"/>
      </linearGradient>
      <linearGradient id="stream-t" x1="186" y1="158" x2="290" y2="255" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stop-color="#7dd3fc" stop-opacity="0.75"/>
        <stop offset="100%" stop-color="#60a5fa" stop-opacity="0.06"/>
      </linearGradient>
      <linearGradient id="cube-top" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="#7dd3fc" stop-opacity="0.34"/>
        <stop offset="100%" stop-color="#2563eb" stop-opacity="0.18"/>
      </linearGradient>
      <linearGradient id="cube-left" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.28"/>
        <stop offset="100%" stop-color="#0f2554" stop-opacity="0.52"/>
      </linearGradient>
      <linearGradient id="cube-right" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#1d4ed8" stop-opacity="0.34"/>
        <stop offset="100%" stop-color="#09183a" stop-opacity="0.62"/>
      </linearGradient>
      <linearGradient id="core-cube" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="#7dd3fc"/>
        <stop offset="55%" stop-color="#2563eb"/>
        <stop offset="100%" stop-color="#1e3a8a"/>
      </linearGradient>
      <filter id="soft-blur" x="-30%" y="-30%" width="160%" height="160%">
        <feGaussianBlur stdDeviation="6"/>
      </filter>
    </defs>

    <!-- Grounded perspective vault dial beneath emblem -->
    <ellipse cx="347" cy="542" rx="238" ry="62" fill="url(#floor-glow)"/>
    <ellipse cx="347" cy="542" rx="224" ry="56" fill="none" stroke="#60a5fa" stroke-opacity="0.24" stroke-width="1.2"/>
    <ellipse cx="347" cy="542" rx="180" ry="44" fill="none" stroke="#7dd3fc" stroke-opacity="0.36" stroke-width="1.5" stroke-dasharray="14 8 3 8"/>
    <ellipse cx="347" cy="542" rx="126" ry="30" fill="none" stroke="#bae6fd" stroke-opacity="0.58" stroke-width="1.8"/>

    <!-- Concentric upright security dial rings framing the emblem -->
    <circle cx="347" cy="350" r="246" fill="none" stroke="url(#ring-grad)" stroke-width="1.2" stroke-dasharray="5 9"/>
    <circle cx="347" cy="350" r="208" fill="none" stroke="url(#ring-grad)" stroke-width="1.4"/>
    <circle cx="347" cy="350" r="172" fill="none" stroke="#38bdf8" stroke-opacity="0.16" stroke-width="1" stroke-dasharray="48 18 10 18"/>

    <!-- Calibrated vault-dial radial ticks on r=222 -->
    <g id="dial-ticks" stroke="#7dd3fc" stroke-opacity="0.28" stroke-width="1.2" stroke-linecap="round"></g>

    <!-- Glowing fibre-optic streams linking 3 vault nodes to the Keyring console -->
    <g fill="none">
      <path d="M 108 424 C 168 418, 206 398, 254 378" stroke="url(#stream-l)" stroke-width="2.2"/>
      <path d="M 108 424 C 170 434, 212 414, 256 392" stroke="url(#stream-l)" stroke-width="1.1" stroke-dasharray="4 6" opacity="0.8"/>

      <path d="M 454 294 C 508 264, 544 238, 594 196" stroke="url(#stream-r)" stroke-width="2.4"/>
      <path d="M 458 310 C 516 286, 552 252, 594 196" stroke="url(#stream-r)" stroke-width="1.1" stroke-dasharray="5 7" opacity="0.8"/>

      <path d="M 176 154 C 216 198, 248 228, 286 254" stroke="url(#stream-t)" stroke-width="1.8"/>
    </g>

    <!-- Signal pulse beads along streams -->
    <circle cx="178" cy="408" r="3" fill="#bae6fd"/>
    <circle cx="534" cy="242" r="3.4" fill="#7dd3fc"/>
    <circle cx="564" cy="218" r="2.2" fill="#ffffff"/>
    <circle cx="222" cy="198" r="2.4" fill="#7dd3fc"/>

    <!-- Isometric Crystalline Vault Node 1 (upper right of emblem: prod vault) -->
    <g transform="translate(596, 186)">
      <circle cx="0" cy="0" r="34" fill="#38bdf8" fill-opacity="0.16" filter="url(#soft-blur)"/>
      <polygon points="0,-42 36,-21 0,0 -36,-21" fill="url(#cube-top)" stroke="#93c5fd" stroke-opacity="0.55" stroke-width="1.2"/>
      <polygon points="-36,-21 0,0 0,42 -36,21" fill="url(#cube-left)" stroke="#60a5fa" stroke-opacity="0.4" stroke-width="1.2"/>
      <polygon points="36,-21 0,0 0,42 36,21" fill="url(#cube-right)" stroke="#60a5fa" stroke-opacity="0.35" stroke-width="1.2"/>
      <!-- Glowing inner vault core -->
      <polygon points="0,-16 14,-8 0,0 -14,-8" fill="#bae6fd"/>
      <polygon points="-14,-8 0,0 0,16 -14,8" fill="url(#core-cube)"/>
      <polygon points="14,-8 0,0 0,16 14,8" fill="#1d4ed8"/>
    </g>

    <!-- Isometric Crystalline Vault Node 2 (lower left: dev vault) -->
    <g transform="translate(106, 424) scale(0.86)">
      <circle cx="0" cy="0" r="32" fill="#2563eb" fill-opacity="0.22" filter="url(#soft-blur)"/>
      <polygon points="0,-42 36,-21 0,0 -36,-21" fill="url(#cube-top)" stroke="#93c5fd" stroke-opacity="0.5" stroke-width="1.2"/>
      <polygon points="-36,-21 0,0 0,42 -36,21" fill="url(#cube-left)" stroke="#60a5fa" stroke-opacity="0.35" stroke-width="1.2"/>
      <polygon points="36,-21 0,0 0,42 36,21" fill="url(#cube-right)" stroke="#60a5fa" stroke-opacity="0.3" stroke-width="1.2"/>
      <polygon points="0,-15 13,-7.5 0,0 -13,-7.5" fill="#7dd3fc"/>
      <polygon points="-13,-7.5 0,0 0,15 -13,7.5" fill="url(#core-cube)"/>
      <polygon points="13,-7.5 0,0 0,15 13,7.5" fill="#1e40af"/>
    </g>

    <!-- Isometric Crystalline Vault Node 3 (upper left: test/staging vault) -->
    <g transform="translate(174, 152) scale(0.68)">
      <circle cx="0" cy="0" r="28" fill="#38bdf8" fill-opacity="0.16" filter="url(#soft-blur)"/>
      <polygon points="0,-42 36,-21 0,0 -36,-21" fill="url(#cube-top)" stroke="#93c5fd" stroke-opacity="0.45" stroke-width="1.3"/>
      <polygon points="-36,-21 0,0 0,42 -36,21" fill="url(#cube-left)" stroke="#60a5fa" stroke-opacity="0.32" stroke-width="1.3"/>
      <polygon points="36,-21 0,0 0,42 36,21" fill="url(#cube-right)" stroke="#60a5fa" stroke-opacity="0.28" stroke-width="1.3"/>
      <polygon points="0,-14 12,-7 0,0 -12,-7" fill="#bae6fd"/>
      <polygon points="-12,-7 0,0 0,14 -12,7" fill="url(#core-cube)"/>
      <polygon points="12,-7 0,0 0,14 12,7" fill="#1e3a8a"/>
    </g>

    <!-- Subtle decorative telemetry reticle in far top-right corner -->
    <g opacity="0.22" stroke="#7dd3fc" fill="none">
      <circle cx="1510" cy="96" r="145" stroke-width="1" stroke-dasharray="6 10"/>
      <circle cx="1510" cy="96" r="96" stroke-width="1"/>
    </g>
  </svg>

  <div class="layout">
    <div class="hero-left">
      <div class="emblem-wrap">
        <div class="emblem-depth"></div>
        <!-- Exact Keyring logo geometry scaled crisply with studio specular lighting -->
        <svg class="emblem-face" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <linearGradient id="kr-bg" x1="5" y1="3" x2="59" y2="61" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stop-color="#13316d"/>
              <stop offset="46%" stop-color="#1b5be0"/>
              <stop offset="100%" stop-color="#2f7dff"/>
            </linearGradient>
            <radialGradient id="kr-glow" cx="16" cy="12" r="38" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stop-color="#7dd3fc" stop-opacity="0.42"/>
              <stop offset="60%" stop-color="#38bdf8" stop-opacity="0.08"/>
              <stop offset="100%" stop-color="#38bdf8" stop-opacity="0"/>
            </radialGradient>
            <linearGradient id="kr-rim" x1="6" y1="3" x2="58" y2="61" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stop-color="#dbeafe" stop-opacity="0.88"/>
              <stop offset="45%" stop-color="#60a5fa" stop-opacity="0.35"/>
              <stop offset="100%" stop-color="#93c5fd" stop-opacity="0.55"/>
            </linearGradient>
            <linearGradient id="kr-ring" x1="12" y1="12" x2="46" y2="46" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stop-color="#7dd3fc"/>
              <stop offset="55%" stop-color="#bae6fd"/>
              <stop offset="100%" stop-color="#e0f2fe"/>
            </linearGradient>
            <filter id="mark-shadow" x="-20%" y="-20%" width="140%" height="140%">
              <feDropShadow dx="0" dy="1.4" stdDeviation="1.4" flood-color="#051330" flood-opacity="0.45"/>
            </filter>
          </defs>
          <rect x="2" y="2" width="60" height="60" rx="15" fill="url(#kr-bg)"/>
          <rect x="2" y="2" width="60" height="60" rx="15" fill="url(#kr-glow)"/>
          <!-- Inner subtle glass bevel -->
          <rect x="2.75" y="2.75" width="58.5" height="58.5" rx="14.25" fill="none" stroke="url(#kr-rim)" stroke-width="1.5"/>
          <rect x="5" y="5" width="54" height="54" rx="12" fill="none" stroke="#ffffff" stroke-opacity="0.09" stroke-width="0.75"/>
          <!-- Split-keyring + precision key -->
          <g filter="url(#mark-shadow)">
            <path d="M 33.94 44.22 A 16 16 0 1 1 44.22 33.94" fill="none" stroke="url(#kr-ring)" stroke-width="4.2" stroke-linecap="round"/>
            <circle cx="29" cy="29" r="6.5" fill="none" stroke="#ffffff" stroke-width="4"/>
            <path d="M 33.8 33.8 L 50.5 50.5 M 42.8 42.8 L 38.3 47.3 M 48.0 48.0 L 44.5 51.5" fill="none" stroke="#ffffff" stroke-width="4.2" stroke-linecap="round" stroke-linejoin="round"/>
            <circle cx="29" cy="29" r="2.1" fill="#7dd3fc"/>
          </g>
        </svg>
      </div>
    </div>

    <div class="hero-right">
      <div class="kicker">
        <span class="kicker-dot"></span>
        <span>Enterprise Privileged Access</span>
      </div>
      <h1>Keyring</h1>
      <div class="subtitle">Zero-Storage Azure Key Vault PAM</div>
      <p class="lead">Acts strictly as the signed-in person via Entra ID OBO. No secret database, no sync credentials, and zero standing vault roles.</p>
      <div class="pills">
        <div class="pill">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
          <span>Entra ID OBO</span>
        </div>
        <div class="pill">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
          <span>Sentinel Ready</span>
        </div>
        <div class="pill">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
          <span>Multi-Environment</span>
        </div>
        <div class="pill">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <span>Zero Storage</span>
        </div>
      </div>
    </div>
  </div>

  <div class="frame-border"></div>
</div>
<script>
  const g = document.getElementById("dial-ticks");
  const cx = 347, cy = 350;
  for (let i = 0; i < 72; i++) {
    const a = (i * 5) * Math.PI / 180;
    const major = i % 6 === 0;
    const r1 = major ? 214 : 219;
    const r2 = 228;
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", (cx + r1 * Math.cos(a)).toFixed(2));
    line.setAttribute("y1", (cy + r1 * Math.sin(a)).toFixed(2));
    line.setAttribute("x2", (cx + r2 * Math.cos(a)).toFixed(2));
    line.setAttribute("y2", (cy + r2 * Math.sin(a)).toFixed(2));
    if (major) {
      line.setAttribute("stroke-opacity", "0.52");
      line.setAttribute("stroke-width", "1.6");
    }
    g.appendChild(line);
  }
</script>
</body>
</html>
"""


def main():
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as tf:
        tf.write(BANNER_HTML)
        html_path = tf.name

    js_source = f"""
const {{ createRequire }} = require("node:module");
const fs = require("node:fs");
const path = require("node:path");
const pwDir = process.env.PATH.split(":").find(
  d => d.endsWith("node_modules/.bin") && fs.existsSync(path.join(d, "..", "playwright", "package.json"))
);
const {{ chromium }} = createRequire(path.join(pwDir, "..", "noop.js"))("playwright");
(async () => {{
  const browser = await chromium.launch();
  const page = await browser.newPage({{
    viewport: {{ width: 1600, height: 700 }},
    deviceScaleFactor: 2
  }});
  await page.goto("file://" + {json.dumps(html_path)}, {{ waitUntil: "networkidle" }});
  await page.screenshot({{
    path: {json.dumps(OUT_PNG)},
    type: "png"
  }});
  await browser.close();
}})();
"""
    with tempfile.NamedTemporaryFile("w", suffix=".cjs", delete=False) as jf:
        jf.write(js_source)
        js_path = jf.name

    try:
        subprocess.run(
            ["npx", "-y", "-p", "playwright@1.65.0", "-c", f"node {shlex.quote(js_path)}"],
            check=True,
        )
    finally:
        for p in (html_path, js_path):
            if os.path.exists(p):
                os.remove(p)
    print(f"Wrote {OUT_PNG} ({os.path.getsize(OUT_PNG) // 1024} KB)")


if __name__ == "__main__":
    main()
