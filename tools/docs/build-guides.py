#!/usr/bin/env python3
"""Builds Keyring's walkthrough guides and administrator SOPs as PDF and DOCX.

Sources:
  docs/guides/NN-*.md      one walkthrough each, in number order
  docs/admin/admin-sops.md  the administrator SOPs

Writes:
  docs/Keyring-Walkthrough-Guides.pdf and .docx
  docs/Keyring-Admin-SOPs.pdf and .docx

Needs pandoc 3 and WeasyPrint on PATH. Python standard library only. The
output is the same on every run: SOURCE_DATE_EPOCH fixes every date pandoc,
WeasyPrint and the DOCX writer stamp, and the zip entries in the DOCX get a
fixed time and order. The styling follows design.md (the palette, the
system fonts, roman headings, no italic).

Usage: python3 tools/docs/build-guides.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCS = os.path.join(REPO, "docs")
GUIDES = os.path.join(DOCS, "guides")
ADMIN = os.path.join(DOCS, "admin", "admin-sops.md")
HERE = os.path.dirname(os.path.abspath(__file__))
CSS = os.path.join(HERE, "print.css")

# 18-11-2026 00:00 UTC. Change it when the documents are reissued.
EPOCH = "1794873600"
DATE = "18-11-2026"


def run(cmd, **kw):
    env = dict(os.environ, SOURCE_DATE_EPOCH=EPOCH, TZ="UTC", LC_ALL="C")
    result = subprocess.run(cmd, env=env, capture_output=True, text=True, **kw)
    if result.returncode != 0:
        sys.stderr.write(result.stdout + result.stderr)
        sys.exit(f"failed: {' '.join(cmd[:2])}")
    return result


def need(tool):
    if not shutil.which(tool):
        sys.exit(f"{tool} is needed to build the documents.")


def guide_files():
    names = sorted(f for f in os.listdir(GUIDES) if re.match(r"^\d\d-.*\.md$", f))
    return [os.path.join(GUIDES, n) for n in names]


def rewrite(text, src_dir, work):
    """Make links work inside one combined document: images by absolute
    path, links to other walkthroughs as in-document anchors, and links to
    other repository files as plain text with the file name."""

    def image(m):
        alt, target = m.group(1), m.group(2)
        path = os.path.normpath(os.path.join(src_dir, target))
        return f"![{alt}]({path})"

    text = re.sub(r"!\[([^\]]*)\]\(([^)\s]+)\)", image, text)

    def link(m):
        label, target = m.group(1), m.group(2)
        if "://" in target or target.startswith(("#", "mailto:")):
            return m.group(0)
        file, _, anchor = target.partition("#")
        path = os.path.normpath(os.path.join(src_dir, file))
        if path.startswith(GUIDES) and path.endswith(".md"):
            return f"[{label}](#{guide_id(path)})"
        if path == ADMIN:
            return f"[{label}](#{anchor})" if anchor and work == "admin" else label
        return label

    return re.sub(r"(?<!!)\[([^\]]+)\]\(([^)\s]+)\)", link, text)


def guide_id(path):
    return "guide-" + os.path.basename(path)[:2]


def combined_guides():
    parts = []
    for path in guide_files():
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        first, _, rest = text.partition("\n")
        title = first.lstrip("# ").strip()
        number = os.path.basename(path)[:2]
        heading = f"# {number}. {title} {{#{guide_id(path)}}}\n"
        parts.append(heading + rewrite(rest, GUIDES, "guides"))
    return "\n\n".join(parts)


def admin_text():
    with open(ADMIN, encoding="utf-8") as fh:
        text = fh.read()
    first, _, rest = text.partition("\n")
    # The SOPs keep their own contents list; the PDF's is generated.
    rest = re.sub(r"\n## Contents\n.*?\n---\n", "\n", rest, flags=re.S)
    return rewrite(rest, os.path.dirname(ADMIN), "admin")


def metadata(title, subtitle):
    return (
        "---\n"
        f'title: "{title}"\n'
        f'subtitle: "{subtitle}"\n'
        f'date: "{DATE}"\n'
        "lang: en-AU\n"
        "toc-title: Contents\n"
        "---\n\n"
    )


def build(name, title, subtitle, body, work):
    md = os.path.join(work, f"{name}.md")
    with open(md, "w", encoding="utf-8") as fh:
        fh.write(metadata(title, subtitle) + body)
    html = os.path.join(work, f"{name}.html")
    pdf = os.path.join(DOCS, f"{name}.pdf")
    docx = os.path.join(DOCS, f"{name}.docx")
    common = [
        "pandoc", md, "--from", "markdown+pipe_tables-implicit_figures",
        "--toc", "--toc-depth=2", "--columns=10000",
    ]
    run(common + ["--to", "html5", "--standalone", "--embed-resources",
                  "--css", CSS, "--syntax-highlighting=none", "--output", html])
    run(["weasyprint", "--optimize-images", "--base-url", work, html, pdf])
    raw = os.path.join(work, f"{name}.raw.docx")
    run(common + ["--to", "docx", "--output", raw])
    steady_zip(raw, docx)
    for path in (pdf, docx):
        print(f"wrote {os.path.relpath(path, REPO)} ({os.path.getsize(path) // 1024} KB)")


def steady_zip(src, dst):
    """Rewrite a DOCX with fixed entry times and order, so the same input
    gives the same bytes."""
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for name in sorted(zin.namelist()):
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 18, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zout.writestr(info, zin.read(name))


def main():
    need("pandoc")
    need("weasyprint")
    work = tempfile.mkdtemp(prefix="keyring-docs-")
    try:
        build("Keyring-Walkthrough-Guides", "Keyring walkthroughs",
              "Step-by-step guides for every page, for the people who use Keyring",
              combined_guides(), work)
        build("Keyring-Admin-SOPs", "Keyring administrator SOPs",
              "Standard operating procedures for the people who run Keyring",
              admin_text(), work)
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
