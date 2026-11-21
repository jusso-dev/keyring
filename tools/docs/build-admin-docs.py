#!/usr/bin/env python3
"""Builds Keyring's administrator documents (Deployment Guide, Administrator
SOPs and Developer Guide) as branded PDF and editable Word DOCX via
tools/docs/build-doc.sh.

The Markdown files in docs/deploy.md and docs/admin/ stay readable on GitHub.
This script prepares a temporary build directory for each document, strips
hand-written document control / contents sections (replaced by the cover and
generated TOC), shifts heading levels so `##` becomes numbered chapter `#`,
and converts relative repository links to plain text so Word has no dead links.

Usage: python3 tools/docs/build-admin-docs.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUILD = os.path.join(REPO, "tools", "docs", "build-doc.sh")
DATE = "21-11-2026"

DOCS = [
    (
        os.path.join(REPO, "docs", "deploy.md"),
        "Keyring-Deployment-Guide",
        "Deployment Guide",
        "Keyring Deployment Guide",
        "Deploy, configure, harden, monitor and upgrade Keyring on Azure",
        "1.2",
    ),
    (
        os.path.join(REPO, "docs", "admin", "admin-sops.md"),
        "Keyring-Admin-SOPs",
        "Administrator SOPs",
        "Keyring Administrator SOPs",
        "Standard operating procedures for the people who run Keyring",
        "1.2",
    ),
    (
        os.path.join(REPO, "docs", "admin", "developer-guide.md"),
        "Keyring-Developer-Guide",
        "Developer Guide",
        "Keyring Developer Guide",
        "Build, test, verify, change and release Keyring",
        "1.0",
    ),
]


def control_table(lines):
    rows, inside = [], False
    for line in lines:
        if line.startswith("## Document control"):
            inside = True
            continue
        if inside and line.startswith("## "):
            break
        if inside and line.startswith("|") and not line.startswith("| ---") and not line.startswith("|---") and "Item" not in line:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) >= 2:
                rows.append((cells[0], cells[1]))
    return rows


def convert(text, src_dir):
    lines = text.splitlines()
    title = lines[0].lstrip("# ").strip()
    rows = control_table(lines)
    body, skip = [], False
    for line in lines[1:]:
        if line.startswith("## Document control") or line.startswith("## Contents"):
            skip = True
            continue
        if skip and line.startswith("## "):
            skip = False
        if skip:
            continue
        body.append(line)

    out, fenced = [], False
    for line in body:
        if line.lstrip().startswith("```"):
            fenced = not fenced
        if not fenced:
            m = re.match(r"^(#{2,6})\s+(?:\d+(?:\.\d+)*\.?\s+)?(.*)$", line)
            if m:
                line = "#" * (len(m.group(1)) - 1) + " " + m.group(2)
            # Rewrite relative images to absolute paths.
            line = re.sub(
                r"!\[([^\]]*)\]\((?!https?://)([^)\s]+)\)",
                lambda mm: f"![{mm.group(1)}]({os.path.normpath(os.path.join(src_dir, mm.group(2)))})",
                line,
            )
            # Strip non-HTTP links so Word has no broken relative links.
            line = re.sub(r"(?<!!)\[([^\]]+)\]\((?!https?://)(?!mailto:)[^)]*\)", r"\1", line)
        out.append(line)

    first = next((i for i, l in enumerate(out) if l.startswith("# ")), len(out))
    intro = "\n".join(out[:first]).strip()
    rest = "\n".join(out[first:])
    md = (f"# About this document {{.unnumbered}}\n\n{intro}\n\n" if intro else "") + rest + "\n"
    return title, rows, md


def metadata(title, kicker, running, note, version, rows, rel_src):
    ver = next((v for k, v in rows if k == "Version"), version)
    date = next((v for k, v in rows if k == "Date"), DATE)
    if not rows:
        rows = [
            ("Document", running),
            ("Version", ver),
            ("Date", date),
            ("Status", "Draft for review"),
            ("Owner", "Keyring maintainer"),
        ]
    table = "\n".join(f"  | {k} | {v} |" for k, v in rows)
    return f'''title: "{running}"
running-title: "{running}"
kicker: "{kicker}"
cover-title: "Keyring"
cover-name: "{title}"
cover-sub: "{note}"
cover-note: "Draft for review. Commands and settings reflect the repository at this version."
version: "{ver}"
date: "{date}"
status: "Draft for review"
lang: en-AU
toc-title: Contents
control: |
  ## Document control

  | Item | Value |
  |---|---|
{table}
  | Source | `{rel_src}` in the `jusso-dev/keyring` repository; rebuilt with `python3 tools/docs/build-admin-docs.py` |
'''


def main():
    for src_path, out_name, kicker, running, note, version in DOCS:
        with open(src_path, encoding="utf-8") as fh:
            title, rows, md = convert(fh.read(), os.path.dirname(src_path))
        rel_src = os.path.relpath(src_path, REPO)
        work = tempfile.mkdtemp(prefix="keyring-admin-")
        try:
            with open(os.path.join(work, "01-body.md"), "w", encoding="utf-8") as fh:
                fh.write(md)
            with open(os.path.join(work, "metadata.yaml"), "w", encoding="utf-8") as fh:
                fh.write(metadata(title, kicker, running, note, version, rows, rel_src))
            result = subprocess.run([BUILD, work, out_name], cwd=REPO, capture_output=True, text=True)
            if result.returncode != 0:
                sys.stderr.write(result.stdout + result.stderr)
                sys.exit(result.returncode)
            print(result.stdout.strip())
        finally:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
