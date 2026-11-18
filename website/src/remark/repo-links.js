// @ts-check
// A link in docs/ that points outside docs/ (the README, SECURITY.md, a
// workflow) can't be a page on this site, and Docusaurus would otherwise
// copy the file into the build. When the file exists in the repository, this
// points the link at it on GitHub. A link to a file that doesn't exist is
// left alone, so the build still fails on it.

const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '../../..');
const DOCS_DIR = path.join(REPO_ROOT, 'docs');

/** @param {{blobUrl: string}} options */
function repoLinks({blobUrl}) {
  /** @param {any} node @param {string} dir */
  function walk(node, dir) {
    if ((node.type === 'link' || node.type === 'definition') && typeof node.url === 'string') {
      const url = node.url;
      if (!/^[a-z][a-z0-9+.-]*:/i.test(url) && !url.startsWith('#') && !url.startsWith('/')) {
        const [target, hash] = url.split('#');
        const resolved = path.resolve(dir, decodeURI(target));
        const outsideDocs = !resolved.startsWith(DOCS_DIR + path.sep);
        const inRepo = resolved.startsWith(REPO_ROOT + path.sep);
        if (target && inRepo && outsideDocs && fs.existsSync(resolved)) {
          const rel = path.relative(REPO_ROOT, resolved).split(path.sep).join('/');
          node.url = `${blobUrl}/${rel}${hash ? `#${hash}` : ''}`;
        }
      }
    }
    if (Array.isArray(node.children)) {
      for (const child of node.children) walk(child, dir);
    }
  }
  return (/** @type {any} */ tree, /** @type {any} */ file) => {
    if (file.path) walk(tree, path.dirname(file.path));
  };
}

module.exports = repoLinks;
