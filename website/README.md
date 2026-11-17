# Keyring documentation site

The Docusaurus site published at <https://jusso-dev.github.io/keyring/>. It renders the Markdown in `../docs` in place: edit the pages there, not here. This folder holds only the site's configuration, sidebar and styles.

This is not part of Keyring. The product has no npm: the Docker image, `Cargo.toml` and the Rust CI never read this folder, and `.dockerignore` keeps it out of the image. `.github/workflows/docs.yml` builds it on pull requests and publishes it from `main`.

## Build and preview

Needs Node 22 or later.

```sh
npm ci --ignore-scripts && npm run build
npm run serve
```

`npm run build` fails on a broken link or anchor. `npm run serve` previews the built site at `http://localhost:3000/keyring/`.

## Where things are

- `docusaurus.config.js`: the site's settings. The docs come from `../docs`, without `docs/design/` (the design document's pandoc source) and `docs/diagrams/`.
- `sidebars.js`: the ten sections and their order. New walkthroughs in `docs/guides/` are added in file order.
- `src/css/custom.css`: colours and type from `design.md`. Light only, system fonts.
- `src/remark/repo-links.js`: points links from `docs/` to files elsewhere in the repository (the README, `SECURITY.md`) at GitHub.
