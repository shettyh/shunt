#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const docsDir = path.join(rootDir, 'src', 'content', 'docs');
const publicDir = path.join(rootDir, 'public');

const siteUrl = (process.env.SITE_URL || 'https://shettyh.github.io').replace(/\/$/, '');
const basePath = (process.env.BASE_PATH ?? '/shunt').replace(/\/$/, '');
const docsBaseUrl = `${siteUrl}${basePath}`;

function walk(dir) {
  if (!fs.existsSync(dir)) return [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walk(full));
    } else if (entry.isFile() && /\.(md|mdx)$/.test(entry.name)) {
      files.push(full);
    }
  }
  return files.sort();
}

function parseFrontmatter(content) {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!match) return { meta: {}, body: content };
  const rawMeta = match[1];
  const body = match[2];
  const meta = {};
  for (const line of rawMeta.split(/\r?\n/)) {
    const kv = line.match(/^([a-zA-Z0-9_-]+):\s*(.*)$/);
    if (kv) {
      meta[kv[1]] = kv[2].replace(/^['"]|['"]$/g, '').trim();
    }
  }
  return { meta, body };
}

function toSlug(filePath) {
  const rel = path.relative(docsDir, filePath).replace(/\\/g, '/');
  return rel.replace(/\.(md|mdx)$/, '').replace(/(^|\/)index$/, '');
}

const files = walk(docsDir);
fs.mkdirSync(publicDir, { recursive: true });

const indexLines = [
  '# Shunt Documentation',
  '',
  '> Shunt is an ultra-lean, pluggable Rust gateway for HTTP APIs, multi-provider AI, and MCP (Model Context Protocol) traffic.',
  '',
  `- Full documentation text: ${docsBaseUrl}/llms-full.txt`,
  '- Repository: https://github.com/shettyh/shunt',
  '',
  '## Pages',
  '',
];

const fullSections = [
  '# Shunt — Complete Documentation',
  '',
  'Source: https://github.com/shettyh/shunt',
  '',
];

for (const file of files) {
  const raw = fs.readFileSync(file, 'utf8');
  const { meta, body } = parseFrontmatter(raw);
  const slug = toSlug(file);
  if (!slug) continue; // skip landing page MDX JSX

  const title = meta.title || slug;
  const desc = meta.description ? `: ${meta.description}` : '';
  const url = `${docsBaseUrl}/${slug}/`;

  indexLines.push(`- [${title}](${url})${desc}`);

  // Strip MDX component imports if any
  const cleanedBody = body
    .replace(/^import\s+.*?;?\s*$/gm, '')
    .trim();

  fullSections.push(`---\n\n# ${title}\nURL: ${url}\n\n${cleanedBody}\n`);
}

fs.writeFileSync(path.join(publicDir, 'llms.txt'), indexLines.join('\n') + '\n', 'utf8');
fs.writeFileSync(path.join(publicDir, 'llms-full.txt'), fullSections.join('\n') + '\n', 'utf8');
console.log(`Generated public/llms.txt and public/llms-full.txt (${files.length} docs scanned).`);
