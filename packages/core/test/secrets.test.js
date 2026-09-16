import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { classifyValue, isPlaceholderValue, runSecretExposureScan } from '../src/scanners/secrets.js';

test('secret discovery skips fixture directories during normal scans', () => {
  const root = mkdtempSync(join(tmpdir(), 'agentshield-secrets-'));
  try {
    mkdirSync(join(root, 'fixtures', 'risky'), { recursive: true });
    mkdirSync(join(root, 'app'), { recursive: true });
    writeFileSync(join(root, 'fixtures', 'risky', '.env'), 'OPENAI_API_KEY=sk-fixturefixturefixturefixture\n');
    writeFileSync(join(root, 'app', '.env'), 'OPENAI_API_KEY=sk-realrealrealrealrealreal\n');

    // Only findings under the temporary root count; the scanner also reads the
    // developer's real shell profiles, and those must not decide this test.
    const findings = runSecretExposureScan([], { workspaceDirs: [root], maxEnvDepth: 3 })
      .filter((finding) => finding.path.startsWith(root));
    assert.equal(findings.length, 1);
    assert.match(findings[0].path, /app\/\.env$/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('plaintext secret in an env file is high severity and redacted', () => {
  const root = mkdtempSync(join(tmpdir(), 'agentshield-leaked-env-'));
  const rawToken = 'sk-AGENTSHIELDRELEASETEST000000000000';
  try {
    writeFileSync(join(root, '.env.release-test'), `OPENAI_API_KEY=${rawToken}\n`);

    const findings = runSecretExposureScan([], { workspaceDirs: [root] });
    const finding = findings.find((item) => item.path.endsWith('.env.release-test'));

    assert.ok(finding);
    assert.equal(finding.severity, 'high');
    assert.equal(finding.confidence, 'high');
    assert.match(finding.description, /sk-A…0000/);
    assert.doesNotMatch(finding.description, new RegExp(rawToken));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('an explicit secret path can be a directory', () => {
  const root = mkdtempSync(join(tmpdir(), 'agentshield-secret-path-'));
  try {
    writeFileSync(join(root, '.env'), 'OPENAI_API_KEY=sk-directorydirectorydirectory00000\n');

    const findings = runSecretExposureScan([root], { workspaceDirs: [] });

    assert.ok(findings.some((item) => item.path === join(root, '.env')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('known credential prefixes are detected under any key, placeholders never are', () => {
  const live = [
    ['ANTHROPIC_API_KEY', `sk-ant-${'a1b2c3d4'.repeat(4)}`, 'Anthropic API key'],
    ['token', `ghp_${'A1b2C3d4E5'.repeat(4)}`, 'GitHub token'],
    ['AWS_ACCESS_KEY_ID', 'AKIAIOSFODNN7EXAMPLE'.replace('EXAMPLE', 'EXAMPLX'), 'AWS access key id'],
    ['some_setting', `xai-${'z9y8x7w6'.repeat(4)}`, 'xAI API key'],
    ['STRIPE', `sk_live_${'Q1w2E3r4'.repeat(4)}`, 'Stripe key'],
    ['DATABASE_URL', 'postgres://app:s3cr3tpass@db.internal:5432/app', 'Database connection string with password'],
    ['slack', `xoxb-${'1234567890'}-${'abcdefghij'.repeat(2)}`, 'Slack token'],
  ];
  for (const [key, value, detector] of live) {
    const hit = classifyValue(key, value);
    assert.ok(hit, `${detector} should be detected`);
    assert.equal(hit.detector, detector);
    assert.ok(!hit.redactedValue.includes(value.slice(6, -6)), 'the middle of the value is never shown');
  }
  const db = classifyValue('DATABASE_URL', 'postgres://app:s3cr3tpass@db.internal:5432/app');
  assert.ok(!db.redactedValue.includes('s3cr3tpass'), 'connection string passwords are redacted');

  for (const value of ['${OPENAI_API_KEY}', '$OPENAI_API_KEY', '<your-openai-key>', 'sk-...', 'xxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'REPLACE_ME_WITH_A_KEY', 'your_api_key_here', '{{ secrets.TOKEN }}']) {
    assert.ok(isPlaceholderValue(value), `${value} is a placeholder`);
    assert.equal(classifyValue('OPENAI_API_KEY', value), null, `${value} is not reported`);
  }
  assert.equal(classifyValue('build_id', 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2'), null, 'a long value under a non-credential key is not a generic token');
  assert.ok(classifyValue('api_token', 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2'), 'the same value under a credential key still is');
});
