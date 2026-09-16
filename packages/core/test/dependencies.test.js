import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runDependencyAudit } from '../src/scanners/dependencies.js';

test('package trust audit catches unpinned sources, missing integrity, tree problems, and signature failures', () => {
  const root = mkdtempSync(join(tmpdir(), 'agentshield-dependency-trust-'));
  try {
    writeFileSync(join(root, 'package.json'), JSON.stringify({
      dependencies: {
        'git-tool': 'github:example/git-tool#main',
        'registry-tool': '1.0.0',
      },
    }));
    writeFileSync(join(root, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'git-tool': 'github:example/git-tool#main', 'registry-tool': '1.0.0' } },
        'node_modules/git-tool': { version: '1.0.0', resolved: 'git+https://github.com/example/git-tool.git' },
        'node_modules/registry-tool': { version: '1.0.0', resolved: 'https://registry.npmjs.org/registry-tool/-/registry-tool-1.0.0.tgz' },
      },
    }));
    const command = (_file, args) => {
      if (args[0] === 'outdated') return {};
      if (args[0] === 'audit' && args[1] === 'signatures') return { invalid: [{ name: 'tampered-tool', version: '1.0.0' }], missing: [{ name: 'unsigned-tool', version: '2.0.0' }] };
      if (args[0] === 'audit') return { vulnerabilities: {} };
      if (args[0] === 'ls') return { problems: ['invalid: registry-tool@1.0.0 /tmp/registry-tool'] };
      return {};
    };

    const findings = runDependencyAudit([root], { command });
    const titles = findings.map((finding) => finding.title);

    assert.ok(titles.some((title) => title.includes('git-tool is installed from a git source')));
    assert.ok(titles.some((title) => title.includes('registry-tool is missing a lockfile integrity hash')));
    assert.ok(titles.some((title) => title.includes('Installed dependency does not satisfy')));
    assert.ok(titles.some((title) => title.includes('signature verification failed for tampered-tool@1.0.0')));
    assert.ok(titles.some((title) => title.includes('signature is missing for unsigned-tool@2.0.0')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
