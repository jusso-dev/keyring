// @ts-check
// The site's ten sections, in order. The pages are the Markdown files in
// ../docs, named here by doc ID: the path under docs/ without `.md`, and
// without a number prefix such as `02-` (Docusaurus drops it).

const fs = require('node:fs');
const path = require('node:path');

// Every walkthrough in docs/guides/ after the "About" page, in file order,
// so a new guide shows up without editing this file.
const guides = fs
  .readdirSync(path.join(__dirname, '../docs/guides'))
  .filter((f) => f.endsWith('.md') && !f.startsWith('00-'))
  .sort()
  .map((f) => `guides/${f.replace(/^\d+-/, '').replace(/\.md$/, '')}`);

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docs: [
    {type: 'doc', id: 'introduction', label: 'Introduction'},
    {type: 'doc', id: 'get-started', label: 'Get started'},
    {
      type: 'category',
      label: 'Deploy',
      link: {type: 'doc', id: 'deploy'},
      items: [
        {type: 'link', label: 'Entra app registration', href: '/deploy#2-register-the-app-in-entra-id'},
        {type: 'link', label: 'Settings and parameters', href: '/deploy#parameters'},
        {type: 'link', label: 'Internal Container Apps', href: '/deploy#internal-container-apps'},
        'private-vaults',
        {type: 'link', label: 'Custom domain', href: '/deploy#5-point-your-address-at-it'},
        {type: 'link', label: 'Upgrade', href: '/deploy#updating'},
        {type: 'link', label: 'Removal', href: '/deploy#removing'},
      ],
    },
    {
      type: 'category',
      label: 'Walkthroughs',
      link: {type: 'doc', id: 'guides/about'},
      items: guides,
    },
    {
      type: 'category',
      label: 'Administer',
      link: {type: 'doc', id: 'admin/admin-sops'},
      items: ['rotation', 'app-credentials'],
    },
    {
      type: 'category',
      label: 'Security and audit',
      link: {
        type: 'generated-index',
        slug: '/security',
        title: 'Security and audit',
        description:
          'What Keyring protects and how, what it records, and how to watch it: the threat model, the audit log and sink, Microsoft Sentinel, alerts, step-up and the reason gate.',
      },
      items: [
        {type: 'link', label: 'Threat model', href: '/architecture#threat-model'},
        {type: 'link', label: 'Audit event fields', href: '/deploy#audit-event-fields'},
        {type: 'link', label: 'Audit sink', href: '/deploy#audit-sink'},
        'sentinel',
        {type: 'link', label: 'Access alerts', href: '/alerts#access-alerts'},
        {type: 'link', label: 'Step-up', href: '/deploy#step-up-before-sensitive-actions'},
        {type: 'link', label: 'Reason gate', href: '/deploy#a-reason-before-a-value-is-shown'},
      ],
    },
    {
      type: 'category',
      label: 'Notifications',
      link: {
        type: 'generated-index',
        slug: '/notifications',
        title: 'Notifications',
        description:
          'Email from Keyring through Azure Communication Services, expiry events from Event Grid, and what each notification says.',
      },
      items: [
        {type: 'link', label: 'Email set-up (ACS)', href: '/deploy#email'},
        'alerts',
        {type: 'ref', id: 'guides/notifications', label: 'Each notification type'},
      ],
    },
    {
      type: 'category',
      label: 'Troubleshooting',
      link: {type: 'doc', id: 'troubleshooting'},
      items: ['real-vault-checklist', 'real-vault-automation'],
    },
    {
      type: 'category',
      label: 'Design',
      link: {type: 'doc', id: 'design-overview'},
      items: ['architecture'],
    },
    {type: 'doc', id: 'reference', label: 'Reference'},
  ],
};

module.exports = sidebars;
