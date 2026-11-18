#!/usr/bin/env bash
# Regenerates keyring-design.drawio from build_drawio.py, then exports every page to SVG and PNG with the
# draw.io desktop command line. Run from anywhere:  docs/diagrams/drawio/export.sh
#
# Needs python3 and draw.io desktop (macOS: /Applications/draw.io.app; Linux: the drawio package, under
# xvfb-run when there is no display), and pngquant to keep the PNGs small. Set DRAWIO=/path/to/drawio to
# choose a binary.
# The exports are committed, so CI and readers of the document need neither.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
src="$here/keyring-design.drawio"
out="$here/export"

drawio_bin="${DRAWIO:-}"
if [[ -z "$drawio_bin" ]]; then
  for c in drawio /Applications/draw.io.app/Contents/MacOS/draw.io /opt/drawio/drawio; do
    if command -v "$c" >/dev/null 2>&1; then drawio_bin="$c"; break; fi
  done
fi
[[ -n "$drawio_bin" ]] || { echo "draw.io desktop not found. Install it or set DRAWIO=/path/to/drawio." >&2; exit 1; }

python3 "$here/build_drawio.py"
mkdir -p "$out"

# Page order and names match build_drawio.py.
names=(01-logical-architecture 02-identity-token-flows 03-network-data-flows 04-notification-flows
       05-deployment 06-security-controls)

for i in "${!names[@]}"; do
  page=$((i + 1))
  name="${names[$i]}"
  "$drawio_bin" --export --format svg --page-index "$page" --embed-svg-images --output "$out/$name.svg" "$src" 2>/dev/null
  "$drawio_bin" --export --format png --page-index "$page" --scale 1.2 --border 16 --output "$out/$name.png" "$src" 2>/dev/null
  echo "exported page $page: $name"
done

# draw.io puts a PNG copy of every HTML label inside each SVG, as a fallback for viewers without
# foreignObject. Browsers don't need it and it makes each SVG over a megabyte, so drop it. The PNG
# exports above are the raster copy.
python3 - "$out" <<'PY'
import pathlib, re, sys
for f in sorted(pathlib.Path(sys.argv[1]).glob("*.svg")):
    s = f.read_text(encoding="utf-8")
    s = re.sub(r'<image [^>]*xlink:href="data:image/png;base64,[^"]*"[^>]*/>(?=</switch>)', "", s)
    f.write_text(s, encoding="utf-8", newline="\n")
PY

# The PNGs are embedded in the PDF and Word editions and committed, so keep them small. pngquant
# (brew install pngquant) reduces them to a palette with no visible change; its output is the same
# on every run. Without it the full-colour PNGs are kept.
if command -v pngquant >/dev/null 2>&1; then
  for name in "${names[@]}"; do
    pngquant --quality=80-95 --speed 1 --strip --force --output "$out/$name.png" "$out/$name.png"
  done
else
  echo "pngquant not found: PNGs left at full size." >&2
fi
