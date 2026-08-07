#!/usr/bin/env node
// Render evidence/transcript.md as an SVG "terminal screenshot".
//
// A generated SVG rather than a PNG so the evidence stays diffable, reviewable
// in a pull request, and reproducible from the run that produced it. No browser
// and no headless anything.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';

const SRC = 'evidence/transcript.md';
const OUT = 'evidence/screenshot.svg';

if (!existsSync(SRC)) {
  console.error(`no ${SRC} - run \`npm run demo\` first`);
  process.exit(1);
}

const lines = readFileSync(SRC, 'utf8')
  .split('\n')
  .filter((l) => l.trim() !== '```');

const CH = 6.62; // advance width of 11px monospace
const LH = 16;
const PAD = 18;
const TOP = 34;
const cols = Math.max(...lines.map((l) => l.length), 80);
const width = Math.ceil(cols * CH) + PAD * 2;
const height = TOP + lines.length * LH + PAD;

const esc = (s) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** Colour a line by what it is, mirroring the terminal output. */
function fill(line) {
  if (/^\s*DENY\b/.test(line)) return '#ff6b6b';
  if (/^\s*ALLOW\b/.test(line)) return /NEGATIVE|S18/.test(line) ? '#e8c547' : '#5ec27e';
  if (/^S\d/.test(line)) return '#ffffff';
  if (/^\s*(note|EXPECTATION FAILED):/.test(line)) return '#e8c547';
  if (/^\s*(why|user|model ->|ledger|family=|session=|ignored)/.test(line)) return '#8a94a6';
  if (/^(Metrics|Unmediated baseline|MCP authority boundary)/.test(line)) return '#ffffff';
  if (/mediation invariant HOLDS|All scenario expectations met/.test(line)) return '#5ec27e';
  if (/^\s*EXECUTED\b/.test(line)) return '#ff6b6b';
  return '#c9d1d9';
}

const body = lines
  .map((l, i) => {
    const y = TOP + i * LH;
    return `<text x="${PAD}" y="${y}" fill="${fill(l)}">${esc(l)}</text>`;
  })
  .join('\n');

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="11">
  <rect width="${width}" height="${height}" rx="8" fill="#0d1117"/>
  <circle cx="20" cy="16" r="5" fill="#ff5f57"/>
  <circle cx="38" cy="16" r="5" fill="#febc2e"/>
  <circle cx="56" cy="16" r="5" fill="#28c840"/>
  <text x="76" y="20" fill="#8a94a6" font-size="10">npm run verify — mcp-authority-boundary</text>
${body}
</svg>
`;

writeFileSync(OUT, svg);
console.log(`wrote ${OUT} (${lines.length} lines, ${width}x${height})`);
