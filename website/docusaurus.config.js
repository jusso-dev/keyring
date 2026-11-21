// @ts-check
// The Keyring documentation site. It renders the Markdown in ../docs in
// place, so the repository and the site have one source of truth. Nothing
// here is part of the product: the Docker image, Cargo and the Rust CI never
// read this folder.

const REPO = 'https://github.com/jusso-dev/keyring';
const repoLinks = require('./src/remark/repo-links');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Keyring',
  tagline: 'A small web app in front of Azure Key Vault',
  favicon: 'img/logo.svg',
  url: 'https://jusso-dev.github.io',
  baseUrl: '/keyring/',
  organizationName: 'jusso-dev',
  projectName: 'keyring',
  trailingSlash: false,

  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',
  onDuplicateRoutes: 'throw',

  markdown: {
    // .md is read as CommonMark, not MDX, so the docs render as they do on
    // GitHub (angle brackets in commands stay text).
    format: 'detect',
    hooks: {
      onBrokenMarkdownLinks: 'throw',
      onBrokenMarkdownImages: 'throw',
    },
  },

  i18n: {defaultLocale: 'en', locales: ['en']},

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          path: '../docs',
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js'),
          exclude: [
            // Pandoc source for the design document; the site links the
            // built PDF and DOCX instead.
            'design/**',
            'diagrams/**',
            // Docusaurus's own defaults.
            '**/_*.{js,jsx,ts,tsx,md,mdx}',
            '**/_*/**',
            '**/*.test.{js,jsx,ts,tsx}',
            '**/__tests__/**',
          ],
          // Links from docs/ to files elsewhere in the repository go to
          // GitHub, not into the build.
          beforeDefaultRemarkPlugins: [[repoLinks, {blobUrl: `${REPO}/blob/main`}]],
          showLastUpdateTime: false,
          showLastUpdateAuthor: false,
        },
        blog: false,
        pages: false,
        theme: {customCss: require.resolve('./src/css/custom.css')},
      }),
    ],
  ],

  themes: [
    [
      // Local search: the index is built with the site and searched in the
      // browser. No external service, no key, no request off the site.
      require.resolve('@easyops-cn/docusaurus-search-local'),
      /** @type {import('@easyops-cn/docusaurus-search-local').PluginOptions} */
      ({
        hashed: true,
        language: ['en'],
        indexDocs: true,
        indexBlog: false,
        indexPages: false,
        docsRouteBasePath: '/',
        docsDir: '../docs',
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      colorMode: {
        defaultMode: 'light',
        disableSwitch: true,
        respectPrefersColorScheme: false,
      },
      navbar: {
        title: 'Keyring',
        logo: {
          alt: 'Keyring logo',
          src: 'img/logo.svg',
        },
        items: [
          {type: 'docSidebar', sidebarId: 'docs', position: 'left', label: 'Docs'},
          {href: REPO, label: 'GitHub', position: 'right'},
        ],
      },
      footer: {
        links: [
          {
            title: 'Keyring',
            items: [
              {label: 'Source on GitHub', href: REPO},
              {label: 'Issues', href: `${REPO}/issues`},
              {label: 'Changelog', href: `${REPO}/blob/main/CHANGELOG.md`},
            ],
          },
        ],
        copyright: 'Keyring is open source under the licence in its repository.',
      },
      docs: {sidebar: {hideable: true}},
    }),
};

module.exports = config;
