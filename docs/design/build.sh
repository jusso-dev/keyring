#!/usr/bin/env bash
# Builds docs/Keyring-Design-Document.pdf and docs/Keyring-Design-Document.docx from the Markdown in docs/design.
#   PDF:  pandoc (Markdown to HTML, numbered sections, table of contents), then WeasyPrint (HTML and CSS to PDF)
#   Word: pandoc (Markdown to DOCX) with the styles in reference.docx and the docx.lua filter
#
# Usage: docs/design/build.sh [--diagrams] [--png]
#   --diagrams  regenerate and export the draw.io diagrams first (needs draw.io desktop)
#   --png       also render every page to docs/design/out/page-NN.png for a visual check (needs pdftoppm)
#
# Needs pandoc and WeasyPrint (brew install pandoc weasyprint). The outputs and the diagram exports are
# committed, so CI and readers need none of these tools. SOURCE_DATE_EPOCH fixes the dates written into
# both files, so rebuilding unchanged sources with the same tool versions gives the same bytes.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
docs="$(dirname "$here")"
out="$here/out"
pdf="$docs/Keyring-Design-Document.pdf"
docx="$docs/Keyring-Design-Document.docx"
# 18-11-2026 00:00 UTC, the document's date.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1794960000}"

png=false
for arg in "$@"; do
  case "$arg" in
    --diagrams) "$docs/diagrams/drawio/export.sh" ;;
    --png) png=true ;;
    *) echo "unknown option $arg" >&2; exit 2 ;;
  esac
done

command -v pandoc >/dev/null || { echo "pandoc is required (brew install pandoc)." >&2; exit 1; }
command -v weasyprint >/dev/null || { echo "WeasyPrint is required (brew install weasyprint)." >&2; exit 1; }

mkdir -p "$out"
# Chapter files in order. Each "# Heading" is a numbered chapter.
sources=("$here"/[0-9][0-9]-*.md)

# Relative paths in the chapters (../diagrams/...) resolve from docs/design, so that is the base URL.
pandoc "${sources[@]}" \
  --from markdown+pipe_tables+raw_html+fenced_divs+bracketed_spans \
  --to html5 \
  --standalone \
  --template "$here/template.html" \
  --metadata-file "$here/metadata.yaml" \
  --number-sections --columns=10000 \
  --toc --toc-depth 2 \
  --section-divs=false \
  --syntax-highlighting=none \
  --output "$out/keyring-design.html"

weasyprint --base-url "$here/" "$out/keyring-design.html" "$pdf"
echo "Wrote $pdf"

python3 "$here/make_reference_docx.py" >/dev/null
(cd "$here" && pandoc "${sources[@]}" \
  --from markdown+pipe_tables+fenced_divs+bracketed_spans \
  --to docx+native_numbering \
  --reference-doc "$here/reference.docx" \
  --metadata-file "$here/metadata.yaml" \
  --lua-filter "$here/docx.lua" \
  --number-sections \
  --resource-path "$here" \
  --output "$docx")
echo "Wrote $docx"

if $png; then
  command -v pdftoppm >/dev/null || { echo "pdftoppm (poppler) is required for --png." >&2; exit 1; }
  rm -f "$out"/page-*.png
  pdftoppm -r 60 -png "$pdf" "$out/page"
  echo "Page previews in $out"
fi
