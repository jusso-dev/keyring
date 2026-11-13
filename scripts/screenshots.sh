#!/bin/sh
# Takes the README screenshots. Start the demo first, in another terminal:
#
#   cargo test --test screenshots -- --ignored --nocapture
#
# then pass the cookie line it prints:
#
#   KEYRING_DEMO_COOKIE=keyring_session=... scripts/screenshots.sh
#
# Needs Node and Playwright's Chromium (`npx -y playwright@1.65.0 install
# chromium`). Compresses with pngquant when it is installed.
set -eu
cd "$(dirname "$0")/.."
npx -y -p playwright@1.65.0 -c 'node scripts/screenshots.mjs'
if command -v pngquant >/dev/null 2>&1; then
  pngquant --force --skip-if-larger --strip --quality 70-90 --ext .png docs/images/screenshots/*.png || true
fi
ls -l docs/images/screenshots
