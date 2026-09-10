// Generates the single unexpected-type stimulus used by every machine.
//
// The payload is a non-string (array) where a string is expected. v1 resolves
// it as a zero-byte write and its executor String()-coerces it into a 100,000
// byte write. HEAD refuses it at resolution. Same bytes in, both versions.
import { writeFileSync } from 'node:fs';

const out = process.argv[2] ?? 'stimulus.json';
const PAYLOAD = 'x'.repeat(100_000);

const stimulus = {
  producedBy: 'make-stimulus.mjs (MacBook: caller/input source role)',
  targetPath: 'corp/public/notes.md',
  rawCall: {
    tool: 'write_document',
    args: { path: 'corp/public/notes.md', content: [PAYLOAD] },
  },
};

writeFileSync(out, JSON.stringify(stimulus));
console.log(`wrote ${out} (${PAYLOAD.length} payload chars inside an array)`);
