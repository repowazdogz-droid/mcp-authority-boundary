#!/usr/bin/env python3
"""Apply one defect patch to a pristine HEAD worktree. Fails loudly unless the
anchor matches exactly once, so a patch that does not apply cannot silently
produce a 'variant' identical to pristine."""
import sys

MUT = sys.argv[1]
ROOT = sys.argv[2]  # variant worktree root

PATCHES = {
    # D1: the executor consumes the model's raw argument instead of the
    # resolved operation. Dormant while resolution refuses non-strings (that
    # masking is itself a finding); live in D9 combined with D4.
    'D1': ('src/enforce.ts',
           '    const result = executeTool(call.operation, outcome.grant, mediation);',
           "    const rawContent = (raw.args as unknown as Record<string, unknown>)['content'];\n"
           "    const execOp = rawContent === undefined ? call.operation : ({ ...call.operation, content: String(rawContent) } as typeof call.operation);\n"
           "    const result = executeTool(execOp, outcome.grant, mediation);"),
    # D2: the grant-digest comparison is removed. A grant for op A executes op B.
    # (`digest.length < 0` is false at runtime but opaque to tsc, so the
    # branch body keeps its type narrowing and the variant still compiles.)
    'D2': ('src/mediation.ts',
           '  if (grant.operationSha256 !== digest) {',
           '  if (grant.operationSha256 !== digest && digest.length < 0) {'),
    # D3: the tool writes somewhere other than the authorized resource.
    'D3': ('src/tools.ts',
           '      documents.set(op.path, op.content);',
           "      documents.set(op.path + '.shadow', op.content);"),
    # D4: the resolver coerces again (v1's line, verbatim).
    'D4': ('src/resolve.ts',
           "      // Rejected, not coerced. This is the A1 fix.\n"
           "      const content = asString(clean['content']);\n"
           "      if (content === null) {\n"
           "        return fail(\n"
           "          `content must be a string; got ${describeType(clean['content'])}. ` +\n"
           "            `Refusing rather than coercing, because a coerced value would be authorized at one ` +\n"
           "            `size and written at another`,\n"
           "          tool,\n"
           "        );\n"
           "      }",
           "      const content = typeof clean['content'] === 'string' ? clean['content'] : '';"),
    # D5: single-use grants become reusable (same compile-preserving trick).
    'D5': ('src/mediation.ts',
           '  if (spent.has(grant)) {',
           '  if (spent.has(grant) && digest.length < 0) {'),
    # D6: the tool reports success without producing the effect.
    'D6': ('src/tools.ts',
           '      documents.set(op.path, op.content);',
           '      void op.content;'),
}

# D9 is the v1 reconstruction: coercing resolver (D4) + raw-consuming
# executor (D1). Applied as both patches in sequence.
SEQ = {
    'D1': ['D1'], 'D2': ['D2'], 'D3': ['D3'],
    'D4': ['D4'], 'D5': ['D5'], 'D6': ['D6'],
    'D9': ['D4', 'D1'],
}

applied = []
for key in SEQ[MUT]:
    rel, find, replace = PATCHES[key]
    path = f'{ROOT}/{rel}'
    with open(path) as f:
        src = f.read()
    n = src.count(find)
    if n != 1:
        sys.exit(f'FATAL: anchor for {key} in {rel} matched {n} times (need 1)')
    with open(path, 'w') as f:
        f.write(src.replace(find, replace))
    applied.append(f'{key}:{rel}')
print('applied', ' '.join(applied))
