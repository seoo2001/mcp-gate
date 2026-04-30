// Grade the JSON produced by cmd/smoke-helper-node/smoke.js into a
// human-readable verdict.
//
// Usage: node scripts/smoke-node-grade.js <probe.json>
const fs = require('node:fs');
const path = process.argv[2];
const out = JSON.parse(fs.readFileSync(path, 'utf8'));

const pad = (s, n) => (s + ' '.repeat(n)).slice(0, n);
console.log(`node version:           ${out.node_version}`);
console.log(`HTTPS_PROXY in child:   ${out.env.HTTPS_PROXY}`);
console.log(`GITHUB_TOKEN prefix:    ${out.env.GITHUB_TOKEN_prefix}`);
console.log();
console.log('Probe results:');
for (const [name, p] of Object.entries(out.probes)) {
  if (p.skipped) console.log(`  ${pad(name, 30)}  SKIP  ${p.skipped.split('\n')[0]}`);
  else if (p.ok) console.log(`  ${pad(name, 30)}  OK    HTTP ${p.status}`);
  else           console.log(`  ${pad(name, 30)}  FAIL  ${p.err}`);
}
console.log();
const worked = Object.entries(out.verdict)
  .filter(([k]) => k.endsWith('_used_proxy') || k.endsWith('_dispatcher_used'))
  .filter(([, v]) => v === true)
  .map(([k]) => k);
console.log(worked.length ? `WORKED: ${worked.join(', ')}` : 'NONE WORKED — Node HTTP stacks bypassed the proxy.');
