import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createFinding } from '../schema.js';
import { shortHash } from '../id.js';
import { parseConfigEntries, unquote } from '../parsers.js';
import { inspectAgentSettings } from './agent-settings.js';

const WILDCARD_HOST = /^(?:0\.0\.0\.0|::|\[::\]|\*)(?::\d+)?$/;
const HOST_KEY = /(^|[._-])(host|hostname|bind|bind_address|bindaddress|address|listen|listen_address|interface)$/i;

const AUTH_KEY = /(^|[._-])(auth|authentication|auth_mode|auth_type|require_auth|requireauth)$/i;
const AUTH_OFF_VALUE = /^(none|false|off|no|disabled|0)$/i;
const AUTH_DISABLE_KEY = /(^|[._-])(no_auth|noauth|disable_auth|auth_disabled|skip_auth|allow_anonymous)$/i;
const TRUTHY = /^(true|1|yes|on|enabled)$/i;

// Values that hand an agent unrestricted execution on the host.
const DANGEROUS_VALUES = [
  /^danger-full-access$/i,
  /^bypasspermissions$/i,
  /^never$/i,
  /^--dangerously-skip-permissions$/,
  /^--yolo$/,
];
const EXECUTION_KEY = /(^|[._-])(yolo|sandbox_mode|sandboxmode|permission_mode|permissionmode|approval_policy|approvalpolicy|shell_full_access|shellfullaccess|full_access|dangerously_skip_permissions)$/i;
// permissions.defaultMode in Claude Code settings is handled structurally in
// agent-settings.js, where "auto" and "dontAsk" mean something specific.

const BROWSER_TOOL = /(^|[/@._-])(playwright|puppeteer|browserbase|browser-use|chrome-devtools|browser_automation|browsermcp)([/._-]|$)/i;
const MCP_KEY = /(^|\.)(mcpservers|mcp_servers|mcp)(\.|$)/i;
const ENDPOINT_KEY = /(^|[._-])(url|uri|endpoint|remote_url|server_url|base_url|serverurl|baseurl)$/i;

function isLoopbackUrl(value) {
  try {
    const { hostname } = new URL(value);
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname === '[::1]';
  } catch {
    return false;
  }
}

function isRemoteUrl(value) {
  return /^https?:\/\//i.test(value) && !isLoopbackUrl(value);
}

function inspectConfig(entries, path) {
  const findings = [];
  const key = (suffix) => `config-${suffix}-${shortHash(path)}`;
  const add = (finding) => {
    if (!findings.some((existing) => existing.id === finding.id)) findings.push(createFinding(finding));
  };

  let sawBrowserTool = false;
  let sawRemoteMcp = false;

  for (const [rawKey, rawValue] of entries) {
    const value = unquote(rawValue);
    const leaf = rawKey.split('.').pop() ?? rawKey;

    if (HOST_KEY.test(leaf) && WILDCARD_HOST.test(value)) {
      add({
        id: key('nonlocal-bind'),
        category: 'config-risk', severity: 'high', confidence: 'high',
        title: 'Service is configured to listen on every network interface',
        description: `${rawKey} is set to ${value}, so this service accepts connections from other devices on the network rather than only from this machine.`,
        path,
        recommendation: 'Bind this service to 127.0.0.1 unless remote access is intentional, authenticated, and firewalled.',
        metadata: { setting: rawKey, value },
      });
    }

    const authDisabled = (AUTH_KEY.test(leaf) && AUTH_OFF_VALUE.test(value))
      || (AUTH_DISABLE_KEY.test(leaf) && TRUTHY.test(value));
    if (authDisabled) {
      add({
        id: key('no-auth'),
        category: 'config-risk', severity: 'high', confidence: 'medium',
        title: 'A service surface is configured without authentication',
        description: `${rawKey} is set to ${value}, which disables or omits authentication on this surface.`,
        path,
        recommendation: 'Enable authentication before exposing this service to anything beyond a tightly controlled local-only environment.',
        metadata: { setting: rawKey, value },
      });
    }

    const dangerousExecution = (EXECUTION_KEY.test(leaf) && (TRUTHY.test(value) || DANGEROUS_VALUES.some((pattern) => pattern.test(value))))
      || DANGEROUS_VALUES.some((pattern) => pattern.test(value) && pattern.source.startsWith('^--'));
    if (dangerousExecution) {
      add({
        id: key('dangerous-exec'),
        category: 'config-risk', severity: 'high', confidence: 'high',
        title: 'An agent is configured to skip execution safeguards',
        description: `${rawKey} is set to ${value}, which lets this agent run commands without the normal approval or sandbox boundary.`,
        path,
        recommendation: 'Keep the default permission mode for daily use and reserve full-access modes for disposable, isolated environments.',
        metadata: { setting: rawKey, value },
      });
    }

    if (BROWSER_TOOL.test(value) || BROWSER_TOOL.test(rawKey)) sawBrowserTool = true;

    const isMcpEndpoint = MCP_KEY.test(rawKey);
    if ((isMcpEndpoint || ENDPOINT_KEY.test(leaf)) && isRemoteUrl(value)) {
      sawRemoteMcp = true;
      // One finding per endpoint: two remote servers in one file are two
      // decisions for the reader.
      add({
        id: key(`remote-trust-${shortHash(rawKey, 6)}`),
        category: 'config-risk', severity: 'medium', confidence: 'high',
        title: isMcpEndpoint ? 'A remote MCP server is configured' : 'An agent tool points at a remote endpoint',
        description: `${rawKey} points at ${value}. A remote tool server can read what the agent sends it and can return content the agent will act on, which extends your trust boundary off this machine.`,
        path,
        recommendation: 'Confirm you control or trust this endpoint, review what the agent is allowed to send it, and remove endpoints you no longer use.',
        metadata: { setting: rawKey, endpoint: value },
      });
    }
  }

  if (sawBrowserTool && sawRemoteMcp) {
    add({
      id: key('browser-posture'),
      category: 'config-risk', severity: 'medium', confidence: 'medium',
      title: 'Browser automation runs alongside a remote MCP server',
      description: 'This config enables browser-driving tools in the same agent that talks to a remote MCP server. Content fetched by the browser can influence what the agent does next.',
      path,
      recommendation: 'Keep browser automation scoped to sites you trust, and avoid combining it with remote MCP servers you do not control.',
      metadata: { signals: ['browser-automation', 'remote-mcp'] },
    });
  }

  return findings;
}

// Structural rules read the parsed document; the entry rules above read
// flattened pairs. A finding the structural pass already made (the same
// setting, the same file) is not repeated by the entry pass.
function structuralFindings(path, raw) {
  if (!path.endsWith('.json')) return [];
  try {
    return inspectAgentSettings(JSON.parse(raw), path);
  } catch {
    return [];
  }
}

export function runConfigRiskAudit(extraPaths = [], options = {}) {
  const home = homedir();
  const workspaceDirs = options.workspaceDirs || [process.cwd()];
  const paths = [
    join(home, '.codex', 'config.toml'),
    join(home, '.claude.json'),
    join(home, '.claude', 'settings.json'),
    join(home, '.claude', 'settings.local.json'),
    join(home, '.config', 'cursor', 'mcp.json'),
    join(home, '.cursor', 'mcp.json'),
    join(home, '.config', 'opencode', 'config.json'),
    ...workspaceDirs.flatMap((dir) => [join(dir, '.claude', 'settings.json'), join(dir, '.claude', 'settings.local.json'), join(dir, '.mcp.json')]),
    ...extraPaths,
  ];

  const findings = [];
  for (const path of [...new Set(paths)]) {
    if (!existsSync(path)) continue;
    let raw;
    try {
      raw = readFileSync(path, 'utf8');
    } catch {
      continue;
    }
    const structural = structuralFindings(path, raw);
    const covered = new Set(structural.map((finding) => finding.metadata?.setting).filter(Boolean));
    const flat = inspectConfig(parseConfigEntries(path, raw), path)
      .filter((finding) => !structural.length || !(
        covered.has(finding.metadata?.setting)
        || (finding.id.includes('-dangerous-exec-') && covered.has('permissions.defaultMode'))
        || /^(hooks|env)\./.test(finding.metadata?.setting ?? '')
      ));
    findings.push(...structural, ...flat);
  }
  return findings;
}
