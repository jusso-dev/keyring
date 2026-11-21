#!/usr/bin/env bash
# Builds a Keyring enterprise document (PDF and editable Word DOCX) from a folder
# of numbered Markdown files plus metadata.yaml, using the shared Keyring styles in
# docs/design (template.html, style.css, docx.lua, make_reference_docx.py).
#
# Usage: tools/docs/build-doc.sh <source-folder> <output-name>
#   e.g. tools/docs/build-doc.sh docs/security Keyring-Security
#
# Writes docs/<output-name>.pdf and docs/<output-name>.docx.
# Needs pandoc 3, Python 3 and WeasyPrint on PATH.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
src="$(cd "$1" && pwd)"
name="$2"
design="$repo/docs/design"
pdf="$repo/docs/$name.pdf"
docx="$repo/docs/$name.docx"
meta="$src/metadata.yaml"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1795132800}"

command -v pandoc >/dev/null || { echo "pandoc is required." >&2; exit 1; }
command -v weasyprint >/dev/null || { echo "WeasyPrint is required." >&2; exit 1; }
sources=("$src"/[0-9][0-9]-*.md)
value() { sed -n "s/^$1: *\"\{0,1\}\([^\"]*\)\"\{0,1\} *$/\1/p" "$meta" | head -1; }

html="$design/.build-$name.html"
pandoc "${sources[@]}" \
  --from markdown+pipe_tables+raw_html+fenced_divs+bracketed_spans \
  --to html5 --standalone \
  --template "$design/template.html" \
  --metadata-file "$meta" \
  --number-sections --columns=10000 --toc --toc-depth 2 --section-divs=false --syntax-highlighting=none \
  --resource-path "$src:$design" \
  --output "$html"
weasyprint --base-url "$design/" "$html" "$pdf"
rm -f "$html"
echo "Wrote docs/$name.pdf ($(($(wc -c < "$pdf") / 1024)) KB)"

ref_dir="$(mktemp -d)"
reference="$ref_dir/reference.docx"
KEYRING_REFERENCE_OUT="$reference" \
KEYRING_DOC_TITLE="$(value running-title)" \
KEYRING_DOC_VERSION="$(value version)" \
KEYRING_DOC_DATE="$(value date)" \
KEYRING_DOC_STATUS="$(value status)" \
  python3 "$design/make_reference_docx.py" >/dev/null

(cd "$design" && pandoc "${sources[@]}" \
  --from markdown+pipe_tables+fenced_divs+bracketed_spans \
  --to docx+native_numbering \
  --reference-doc "$reference" \
  --metadata-file "$meta" \
  --lua-filter "$design/docx.lua" \
  --number-sections \
  --resource-path "$design:$src" \
  --output "$docx")
rm -rf "$ref_dir"
echo "Wrote docs/$name.docx ($(($(wc -c < "$docx") / 1024)) KB)"
