const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const gen = path.join(root, 'src', 'recomp', 'gen');
const source = path.join(root, 'diagnostics', 'fullgen');
const definition = /^void (sub_[0-9A-F]{8})\(void\)$/m;

/*
 * Some functions in the normal generated set were truncated at an internal
 * branch target because the first-pass CFG ended at an overlapping callable
 * boundary.  The complete analysis owns those targets as labels in the
 * original function, which is the only representation that preserves the
 * parent's locals and guest stack frame.  Pull those complete owner blocks in
 * before calculating the genuinely missing callable set.
 */
const expandedOwners = new Set([
  'sub_002500E0',
  'sub_00250810',
  'sub_00252540',
]);
const absorbedContinuations = new Set([
  'sub_00250126',
  'sub_00250132',
  'sub_002508D8',
  'sub_002508DC',
  'sub_00252615',
]);

const sourceBlocks = new Map();
for (const name of fs.readdirSync(source).filter(n => /^recomp_\d{4}\.c$/.test(n)).sort()) {
  const text = fs.readFileSync(path.join(source, name), 'utf8');
  for (const block of text.split(/(?=^\/\*\*\r?$)/m)) {
    const m = definition.exec(block);
    if (m) sourceBlocks.set(m[1], block);
  }
}

const ownersReplaced = new Set();
for (const name of fs.readdirSync(gen).filter(n => /^recomp_\d{4}\.c$/.test(n)).sort()) {
  const file = path.join(gen, name);
  const text = fs.readFileSync(file, 'utf8');
  const blocks = text.split(/(?=^\/\*\*\r?$)/m);
  let changed = false;
  for (let i = 0; i < blocks.length; i++) {
    const m = definition.exec(blocks[i]);
    if (!m || !expandedOwners.has(m[1])) continue;
    const complete = sourceBlocks.get(m[1]);
    if (!complete) throw new Error(`Complete owner body not found for ${m[1]}`);
    blocks[i] = complete;
    ownersReplaced.add(m[1]);
    changed = true;
  }
  if (changed) fs.writeFileSync(file, blocks.join(''));
}
for (const name of expandedOwners) {
  if (!ownersReplaced.has(name)) throw new Error(`Current owner body not found for ${name}`);
}

const actual = new Set();
for (const name of fs.readdirSync(gen)) {
  if (!/^recomp_\d{4}\.c$/.test(name)) continue;
  const text = fs.readFileSync(path.join(gen, name), 'utf8');
  for (const m of text.matchAll(/^void (sub_[0-9A-F]{8})\(void\)$/gm)) actual.add(m[1]);
}

const recovered = [];
const recoveredNames = new Set();
for (const name of fs.readdirSync(source).filter(n => /^recomp_\d{4}\.c$/.test(n)).sort()) {
  const text = fs.readFileSync(path.join(source, name), 'utf8');
  const blocks = text.split(/(?=^\/\*\*\r?$)/m);
  for (const block of blocks) {
    const m = definition.exec(block);
    if (!m || actual.has(m[1]) || recoveredNames.has(m[1])) continue;
    recoveredNames.add(m[1]);
    recovered.push(block.trimEnd());
  }
}

const out = [
  '/** Missing callable entries recovered from the current complete analysis. */',
  '#define RECOMP_GENERATED_CODE',
  '#include "recomp_funcs.h"',
  '#include <math.h>',
  '',
  ...recovered,
  ''
].join('\n');
fs.writeFileSync(path.join(gen, 'recomp_missing_complete.c'), out);

const stubPath = path.join(gen, 'recomp_stubs_unresolved.c');
let stubs = fs.readFileSync(stubPath, 'utf8');
stubs = stubs.split(/\r?\n/).filter(line => {
  const m = /^void (sub_[0-9A-F]{8})\(void\)/.exec(line);
  return !m || (!recoveredNames.has(m[1]) && !absorbedContinuations.has(m[1]));
}).join('\n') + '\n';
fs.writeFileSync(stubPath, stubs);

const headerPath = path.join(gen, 'recomp_funcs.h');
let header = fs.readFileSync(headerPath, 'utf8');
for (const name of absorbedContinuations) {
  header = header.replace(new RegExp(`^void ${name}\\(void\\);\\r?\\n`, 'm'), '');
}
const declarations = [...recoveredNames]
  .filter(name => !header.includes(`void ${name}(void);`))
  .map(name => `void ${name}(void);`)
  .join('\n');
if (declarations) {
  header = header.replace(/\n#endif \/\* RECOMP_FUNCS_H \*\//,
    `\n/* Callable entries recovered from complete overlapping-library analysis. */\n${declarations}\n\n#endif /* RECOMP_FUNCS_H */`);
}
fs.writeFileSync(headerPath, header);

/* Keep indirect calls in lock-step with every concrete generated body. */
const concrete = new Map();
for (const name of fs.readdirSync(gen).filter(n => /^recomp_(?:\d{4}|missing_complete)\.c$/.test(n)).sort()) {
  const text = fs.readFileSync(path.join(gen, name), 'utf8');
  for (const m of text.matchAll(/^void (sub_([0-9A-F]{8}))\(void\)$/gm)) {
    if (concrete.has(m[1])) throw new Error(`Duplicate concrete definition: ${m[1]}`);
    concrete.set(m[1], parseInt(m[2], 16));
  }
}

const dispatchPath = path.join(gen, 'recomp_dispatch.c');
let dispatch = fs.readFileSync(dispatchPath, 'utf8');
const entries = [...concrete]
  .sort((a, b) => a[1] - b[1])
  .map(([name, addr]) => `    { 0x${addr.toString(16).toUpperCase().padStart(8, '0')}u, (recomp_func_t)${name} },`)
  .join('\n');
const tablePattern = /static const recomp_entry_t g_recomp_table\[\] = \{\r?\n[\s\S]*?\r?\n\};/;
if (!tablePattern.test(dispatch)) throw new Error('Dispatch table not found');
dispatch = dispatch.replace(tablePattern,
  `static const recomp_entry_t g_recomp_table[] = {\n${entries}\n};`);
dispatch = dispatch.replace(/Maps \d+ Xbox VAs to translated function pointers\./,
  `Maps ${concrete.size} Xbox VAs to translated function pointers.`);
fs.writeFileSync(dispatchPath, dispatch);

console.log(
  `Recovered ${recovered.length} missing functions; expanded ${ownersReplaced.size} owners; ` +
  `absorbed ${absorbedContinuations.size} continuation stubs; dispatched ${concrete.size} concrete functions.`
);
