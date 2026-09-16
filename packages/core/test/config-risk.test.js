import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runConfigRiskAudit } from '../src/scanners/config-risk.js';

function withConfig(name, contents, assertions) {
  const root = mkdtempSync(join(tmpdir(), 'agentshield-config-'));
  const configPath = join(root, name);
  try {
    writeFileSync(configPath, contents);
    assertions(runConfigRiskAudit([configPath]).filter((finding) => finding.path === configPath), configPath);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test('config audit detects dangerous execution and exposure settings', () => {
  withConfig('release-test.toml', [
    '[network]',
    'host = "0.0.0.0"',
    '',
    '[mcp_servers.remote]',
    'url = "https://mcp.example.invalid"',
    'auth = "none"',
    '',
    '[execution]',
    'yolo = true',
    'browser_automation = true',
  ].join('\n'), (findings) => {
    const titles = new Set(findings.map((finding) => finding.title));

    assert.equal(findings.filter((finding) => finding.severity === 'high').length, 3);
    assert.equal(findings.filter((finding) => finding.severity === 'medium').length, 2);
    assert.ok(titles.has('Service is configured to listen on every network interface'));
    assert.ok(titles.has('A service surface is configured without authentication'));
    assert.ok(titles.has('An agent is configured to skip execution safeguards'));
    assert.ok(titles.has('A remote MCP server is configured'));
    assert.ok(titles.has('Browser automation runs alongside a remote MCP server'));
  });
});

test('a wildcard bind is still detected when a port is attached', () => {
  withConfig('bind.toml', '[network]\nbind = "0.0.0.0:4173"\n', (findings) => {
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'high');
  });
});

test('a loopback endpoint is not reported as a remote trust boundary', () => {
  withConfig('local.toml', '[mcp_servers.local]\nurl = "http://127.0.0.1:8080/mcp"\n', (findings) => {
    assert.deepEqual(findings, []);
  });
});

test('conversation history in a JSON config does not produce config findings', () => {
  // ~/.claude.json stores transcripts next to real settings. Scanning the file
  // as raw text used to flag every prose mention of "mcp", "browser", or "::".
  const contents = JSON.stringify({
    projects: {
      '/Users/example/app': {
        history: [
          { display: 'bind the server to 0.0.0.0 and set auth = "none"' },
          { display: 'run the browser mcp against https://example.invalid' },
        ],
      },
    },
    mcpServers: {
      local: { command: 'npx', args: ['-y', 'some-local-server@1.0.0'] },
    },
  });

  withConfig('claude.json', contents, (findings) => {
    assert.deepEqual(findings, []);
  });
});

test('finding ids stay unique across two configs that share a file extension', () => {
  const root = mkdtempSync(join(tmpdir(), 'agentshield-config-'));
  try {
    const first = join(root, 'one.toml');
    const second = join(root, 'two.toml');
    writeFileSync(first, 'host = "0.0.0.0"\n');
    writeFileSync(second, 'host = "0.0.0.0"\n');

    const ids = runConfigRiskAudit([first, second])
      .filter((finding) => finding.path === first || finding.path === second)
      .map((finding) => finding.id);

    assert.equal(ids.length, 2);
    assert.equal(new Set(ids).size, 2);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
