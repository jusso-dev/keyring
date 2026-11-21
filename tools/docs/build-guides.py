#!/usr/bin/env python3
"""Builds Keyring's user walkthrough guides as branded PDF and editable Word DOCX.

Sources:
  docs/guides/NN-*.md      one walkthrough each, in number order

Writes, through the shared builder tools/docs/build-doc.sh:
  docs/Keyring-Walkthrough-Guides.pdf and .docx      combined edition (all guides)
  docs/Keyring-Walkthrough-NN-<Name>.pdf and .docx   one standalone file per guide

Usage: python3 tools/docs/build-guides.py [--combined-only]
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUILD = os.path.join(REPO, "tools", "docs", "build-doc.sh")
GUIDES = os.path.join(REPO, "docs", "guides")
VERSION = "1.2"
DATE = "21-11-2026"


def sources():
    names = sorted(f for f in os.listdir(GUIDES) if re.match(r"^\d\d-.*\.md$", f))
    out = []
    for f in names:
        with open(os.path.join(GUIDES, f), encoding="utf-8") as fh:
            text = fh.read()
        title = text.splitlines()[0].lstrip("# ").strip()
        out.append((f, title, text))
    return out


def rewrite(text):
    """Rewrite relative image paths to absolute paths and drop relative .md links."""
    def image(m):
        alt, target = m.group(1), m.group(2)
        if "://" in target:
            return m.group(0)
        return f"![{alt}]({os.path.normpath(os.path.join(GUIDES, target))})"

    text = re.sub(r"!\[([^\]]*)\]\(([^)\s]+)\)", image, text)
    text = re.sub(r"(?<!!)\[([^\]]+)\]\((?!https?://)(?!mailto:)(?!#)[^)]*\)", r"\1", text)
    return text


def file_name(number, title):
    words = re.sub(r"[^A-Za-z0-9 ]+", " ", title).split()
    return f"Keyring-Walkthrough-{number}-" + "-".join(w[:1].upper() + w[1:] for w in words[:6])


def metadata(title, running, note, chapters):
    rows = "\n".join(f"  | {n} | {t} |" for n, t in chapters)
    return f'''title: "{title}"
running-title: "{running}"
kicker: "User Walkthrough"
cover-title: "Keyring"
cover-name: "{title}"
cover-sub: "{note}"
cover-note: "Draft for review. Button, field and message text matches the Keyring templates at this version."
version: "{VERSION}"
date: "{DATE}"
status: "Draft for review"
lang: en-AU
toc-title: Contents
control: |
  ## Document control

  | Item | Value |
  |---|---|
  | Document | {title} |
  | Version | {VERSION} |
  | Date | {DATE} |
  | Status | Draft for review |
  | Owner | Keyring maintainer |
  | Source | `docs/guides/` in `jusso-dev/keyring`; rebuilt with `python3 tools/docs/build-guides.py` |
  | Related | Administrator SOPs; Deployment Guide; Security Architecture and Controls; Solution Design Document; Enterprise Comparison and Migration Guide |

  ## Contents of this edition

  | Chapter | Walkthrough |
  |---|---|
{rows}
'''


def build(out_name, title, running, note, files):
    work = tempfile.mkdtemp(prefix="keyring-guides-")
    try:
        chapters = []
        for i, (src, chapter_title, text) in enumerate(files, start=1):
            cleaned = rewrite(text)
            with open(os.path.join(work, f"{i:02d}-{src[3:]}"), "w", encoding="utf-8") as fh:
                fh.write(cleaned if cleaned.endswith("\n") else cleaned + "\n")
            chapters.append((src[:2], chapter_title))
        with open(os.path.join(work, "metadata.yaml"), "w", encoding="utf-8") as fh:
            fh.write(metadata(title, running, note, chapters))
        result = subprocess.run([BUILD, work, out_name], cwd=REPO, capture_output=True, text=True)
        if result.returncode != 0:
            sys.stderr.write(result.stdout + result.stderr)
            sys.exit(result.returncode)
        print(result.stdout.strip())
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    args = set(sys.argv[1:])
    unknown = args - {"--combined-only"}
    if unknown:
        sys.exit(f"unknown option {' '.join(sorted(unknown))}")

    files = sources()
    build(
        "Keyring-Walkthrough-Guides",
        "Keyring User Walkthroughs",
        "Keyring User Walkthroughs",
        "Step-by-step guides for every page, for the people who use Keyring",
        files,
    )
    if "--combined-only" in args:
        return

    for src, title, text in files:
        number = src[:2]
        build(
            file_name(number, title),
            f"Walkthrough {number}: {title}",
            f"Keyring Walkthrough {number}: {title}",
            "One Keyring user journey, step by step",
            [(src, title, text)],
        )


if __name__ == "__main__":
    main()
